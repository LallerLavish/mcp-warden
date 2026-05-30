mod log;
mod policy;
mod proxy;
mod seccomp;

use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use log::Log;
use proxy::pipe_and_log;

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let Some(sep) = args.iter().position(|a| a == "--") else {
        eprintln!("usage: warden [--policy <path>] -- <command> [args...]");
        std::process::exit(2);
    };
    let warden_args = &args[1..sep];
    let child_argv = &args[sep + 1..];
    if child_argv.is_empty() {
        eprintln!("warden: missing command after `--`");
        std::process::exit(2);
    }

    let mut policy_path: Option<String> = None;
    let mut i = 0;
    while i < warden_args.len() {
        match warden_args[i].as_str() {
            "--policy" => {
                policy_path = warden_args.get(i + 1).cloned();
                if policy_path.is_none() {
                    eprintln!("warden: --policy needs a path");
                    std::process::exit(2);
                }
                i += 2;
            }
            other => {
                eprintln!("warden: unknown arg `{}`", other);
                std::process::exit(2);
            }
        }
    }

    let pol = policy_path.as_deref().map(policy::load).unwrap_or_default();

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("warden.log")?;
    let log: Log = Arc::new(Mutex::new(std::io::BufWriter::new(log_file)));

    // apply landlock only if there are FS rules (an empty ruleset = deny-all = can't exec)
    let want_landlock = !pol.read.is_empty() || !pol.write.is_empty();
    let want_net = !pol.network.allow.is_empty();

    // socketpair carries the seccomp listener fd from child -> parent
    let net_socks = if want_net { Some(UnixStream::pair()?) } else { None };
    let child_fd: Option<i32> = net_socks.as_ref().map(|(_, c)| c.as_raw_fd());

    let mut cmd = Command::new(&child_argv[0]);
    cmd.args(&child_argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    if want_landlock || want_net {
        let pol_clone = pol.clone();
        unsafe {
            cmd.pre_exec(move || {
                seccomp::set_no_new_privs()?;
                if want_landlock {
                    policy::apply_landlock(&pol_clone)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                }
                if want_net {
                    let nfd = seccomp::install_connect_notifier()?;
                    seccomp::send_fd(child_fd.unwrap(), nfd)?;
                }
                Ok(())
            });
        }
    }

    let mut child = cmd.spawn()?;
    let child_pid = child.id() as i32;

    // bring up the egress supervisor BEFORE relaying, so early connects are policed
    if want_net {
        let (parent_sock, child_sock) = net_socks.unwrap();
        drop(child_sock); // parent keeps only its end
        let notif_fd = seccomp::recv_fd(parent_sock.as_raw_fd())?;
        drop(parent_sock);
        let allowed = seccomp::resolve_allowlist(&pol.network.allow);
        for n in &allowed {
            eprintln!("[warden] egress allow: {n}");
        }
        let net_log = Arc::clone(&log);
        thread::spawn(move || seccomp::run_notify_loop(notif_fd, child_pid, allowed, net_log));
    }

    let child_stdin = child.stdin.take().expect("Failed to open child stdin");
    let child_stdout = child.stdout.take().expect("Failed to open child stdout");

    let log_in = Arc::clone(&log);
    let log_out = Arc::clone(&log);

    let decisions_path = policy_path
        .as_ref()
        .map(|p| std::path::PathBuf::from(format!("{p}.decisions.json")));
    let decisions: proxy::Decisions = proxy::DecisionStore::load(decisions_path);
    let tools_default = pol.tools.default.clone();
    let tools_rules = pol.tools.rules.clone();

    let t_in = thread::spawn(move || {proxy::pipe_gate_and_log(io::stdin(), child_stdin, log_in, tools_default, tools_rules, decisions)});
    let t_out = thread::spawn(move || pipe_and_log(child_stdout, io::stdout(), "server->client", log_out));
    
    let status = child.wait()?;
    if let Err(e) = t_in.join().expect("stdin thread panicked") {
        eprintln!("warden: stdin relay error: {}", e);
    }
    if let Err(e) = t_out.join().expect("stdout thread panicked") {
        eprintln!("warden: stdout relay error: {}", e);
    }
    std::process::exit(status.code().unwrap_or(0));
}