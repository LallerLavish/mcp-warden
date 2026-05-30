// Network egress control via seccomp user-notification.
// Traps connect(), reads the destination out of the child, checks an allowlist,
// and ALLOWS by performing the connect itself (pidfd_getfd) — never CONTINUE,
// so a multithreaded child can't win the TOCTOU race on the sockaddr pointer.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
use std::sync::Arc;
use std::thread;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde_json::json;

use crate::log::{log_event, Log};

// ---- seccomp constants (<linux/seccomp.h>, <linux/audit.h>) ----
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

// classic-BPF opcodes
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

// ---- kernel structs (#[repr(C)]) ----
#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}
#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}
#[repr(C)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

// ioctl request numbers, computed from struct sizes
const fn iowr(ty: u32, nr: u32, size: usize) -> libc::c_ulong {
    ((3u32 << 30) | ((size as u32) << 16) | (ty << 8) | nr) as libc::c_ulong
}
const fn iow(ty: u32, nr: u32, size: usize) -> libc::c_ulong {
    ((1u32 << 30) | ((size as u32) << 16) | (ty << 8) | nr) as libc::c_ulong
}
const NOTIF_RECV: libc::c_ulong = iowr(0x21, 0, std::mem::size_of::<SeccompNotif>());
const NOTIF_SEND: libc::c_ulong = iowr(0x21, 1, std::mem::size_of::<SeccompNotifResp>());
const NOTIF_ID_VALID: libc::c_ulong = iow(0x21, 2, std::mem::size_of::<u64>());

// ============================ child side (pre_exec) ============================

pub fn set_no_new_privs() -> io::Result<()> {
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn connect_filter() -> [libc::sock_filter; 6] {
    let connect_nr = libc::SYS_connect as u32;
    let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jmp = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    [
        stmt(BPF_LD_W_ABS, OFF_ARCH),            // 0: A = arch
        jmp(BPF_JEQ_K, 0, 3, AUDIT_ARCH),        // 1: arch != ours -> ALLOW (idx5)
        stmt(BPF_LD_W_ABS, OFF_NR),              // 2: A = nr
        jmp(BPF_JEQ_K, 0, 1, connect_nr),        // 3: nr != connect -> ALLOW (idx5)
        stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF), // 4: trap connect to supervisor
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),      // 5: allow
    ]
}

/// Install the filter and return the listener fd. Call in pre_exec, after
/// set_no_new_privs (+ landlock). The fd is set CLOEXEC so the exec'd server
/// can't inherit it and answer its own notifications.
pub fn install_connect_notifier() -> io::Result<RawFd> {
    let prog = connect_filter();
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const libc::sock_fprog,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = fd as RawFd;
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    Ok(fd)
}

// ---- SCM_RIGHTS fd passing (raw libc, no nix) ----

pub fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
    unsafe {
        let mut dummy: u8 = 0;
        let mut iov = libc::iovec {
            iov_base: &mut dummy as *mut _ as *mut libc::c_void,
            iov_len: 1,
        };
        let mut cbuf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );

        if libc::sendmsg(sock, &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn recv_fd(sock: RawFd) -> io::Result<RawFd> {
    unsafe {
        let mut dummy: u8 = 0;
        let mut iov = libc::iovec {
            iov_base: &mut dummy as *mut _ as *mut libc::c_void,
            iov_len: 1,
        };
        let mut cbuf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cbuf.len() as _;

        if libc::recvmsg(sock, &mut msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(io::Error::new(io::ErrorKind::Other, "no SCM_RIGHTS cmsg"));
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut RawFd as *mut u8,
            std::mem::size_of::<RawFd>(),
        );
        Ok(fd)
    }
}

// ============================ parent side (supervisor) ============================

fn host_net(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(a) => IpNet::V4(Ipv4Net::new(a, 32).unwrap()),
        IpAddr::V6(a) => IpNet::V6(Ipv6Net::new(a, 128).unwrap()),
    }
}

/// Turn the policy's allow entries (IPs, CIDRs, or hostnames) into IP nets.
/// Hostnames are resolved once at startup (N3 will pin live DNS instead).
pub fn resolve_allowlist(entries: &[String]) -> Vec<IpNet> {
    use std::net::ToSocketAddrs;
    let mut out = Vec::new();
    for e in entries {
        if let Ok(net) = e.parse::<IpNet>() {
            out.push(net);
        } else if let Ok(ip) = e.parse::<IpAddr>() {
            out.push(host_net(ip));
        } else {
            match (e.as_str(), 0u16).to_socket_addrs() {
                Ok(addrs) => out.extend(addrs.map(|a| host_net(a.ip()))),
                Err(err) => eprintln!("[warden] cannot resolve allow host '{e}': {err}"),
            }
        }
    }
    out
}

pub fn run_notify_loop(notif_fd: RawFd, child_pid: i32, allowed: Vec<IpNet>, log: Log) {
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) } as RawFd;
    if pidfd < 0 {
        eprintln!("[warden] pidfd_open failed: {}", io::Error::last_os_error());
        return;
    }
    let allowed = Arc::new(allowed);
    loop {
        let mut req: SeccompNotif = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(notif_fd, NOTIF_RECV, &mut req as *mut _) } != 0 {
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                _ => break, // listener closed: child gone
            }
        }
        let allowed = Arc::clone(&allowed);
        let log = Arc::clone(&log);
        thread::spawn(move || handle_connect(notif_fd, pidfd, child_pid, &allowed, &log, req));
    }
    unsafe { libc::close(pidfd) };
}

fn classify(family: i32, buf: &[u8; 128], len: usize, allowed: &[IpNet]) -> (bool, String) {
    match family {
        libc::AF_INET if len >= 8 => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let ok = ip.is_loopback() || allowed.iter().any(|n| n.contains(&IpAddr::V4(ip)));
            (ok, format!("{ip}:{port}"))
        }
        libc::AF_INET6 if len >= 24 => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[8..24]);
            let ip = Ipv6Addr::from(o);
            let ok = ip.is_loopback() || allowed.iter().any(|n| n.contains(&IpAddr::V6(ip)));
            (ok, format!("[{ip}]:{port}"))
        }
        // AF_UNIX / other non-IP: not egress -> allow (we perform it ourselves).
        _ => (true, format!("af={family}")),
    }
}

fn read_child_mem(pid: i32, addr: u64, out: &mut [u8]) -> bool {
    if out.is_empty() {
        return true;
    }
    let local = libc::iovec {
        iov_base: out.as_mut_ptr() as *mut libc::c_void,
        iov_len: out.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: out.len(),
    };
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    n == out.len() as isize
}

fn notif_id_valid(fd: RawFd, id: u64) -> bool {
    let mut id = id;
    unsafe { libc::ioctl(fd, NOTIF_ID_VALID, &mut id as *mut u64) == 0 }
}

fn respond(fd: RawFd, id: u64, val: i64, error: i32) {
    let mut resp = SeccompNotifResp { id, val, error, flags: 0 };
    unsafe { libc::ioctl(fd, NOTIF_SEND, &mut resp as *mut _) };
}

fn handle_connect(
    notif_fd: RawFd,
    pidfd: RawFd,
    child_pid: i32,
    allowed: &[IpNet],
    log: &Log,
    req: SeccompNotif,
) {
    let sockfd = req.data.args[0] as RawFd;
    let addr_ptr = req.data.args[1];
    let addr_len = (req.data.args[2] as usize).min(128);

    let mut buf = [0u8; 128];
    if !read_child_mem(child_pid, addr_ptr, &mut buf[..addr_len]) {
        respond(notif_fd, req.id, 0, -libc::EPERM); // fail closed
        log_event(log, "net.connect", json!({"dest":"<unreadable>","decision":"deny"}));
        return;
    }

    let family = u16::from_ne_bytes([buf[0], buf[1]]) as i32;
    let (allow, dest) = classify(family, &buf, addr_len, allowed);

    if !allow {
        respond(notif_fd, req.id, 0, -libc::EPERM);
        eprintln!("[warden] DENY  connect -> {dest}");
        log_event(log, "net.connect", json!({"dest":dest,"decision":"deny"}));
        return;
    }

    if !notif_id_valid(notif_fd, req.id) {
        return; // target died; nothing to do
    }

    // Borrow the child's actual socket and connect it ourselves, using OUR
    // validated copy of the address. No CONTINUE -> no TOCTOU window.
    let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, sockfd, 0) } as RawFd;
    if dup < 0 {
        respond(notif_fd, req.id, 0, -libc::EPERM);
        return;
    }
    let r = unsafe {
        libc::connect(
            dup,
            buf.as_ptr() as *const libc::sockaddr,
            addr_len as libc::socklen_t,
        )
    };
    let (val, err) = if r == 0 {
        (0i64, 0i32)
    } else {
        (0i64, -io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))
    };
    unsafe { libc::close(dup) };
    respond(notif_fd, req.id, val, err);
    eprintln!("[warden] ALLOW connect -> {dest}");
    log_event(log, "net.connect", json!({"dest":dest,"decision":"allow"}));
}