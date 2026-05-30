mod log;
mod policy;
mod proxy;

use std::fs::OpenOptions;
use std::io;
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

    let pol = policy_path
        .as_deref()
        .map(policy::load)
        .unwrap_or_default();

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("warden.log")?;
    let log: Log = Arc::new(Mutex::new(std::io::BufWriter::new(log_file)));

    let mut cmd = Command::new(&child_argv[0]);
    cmd.args(&child_argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    if policy_path.is_some() {
        let pol_clone = pol.clone();
        unsafe {
            cmd.pre_exec(move || {
                policy::apply_landlock(&pol_clone)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
            });
        }
    }

    let mut child = cmd.spawn()?;
    let child_stdin = child.stdin.take().expect("Failed to open child stdin");
    let child_stdout = child.stdout.take().expect("Failed to open child stdout");

    let log_in = Arc::clone(&log);
    let log_out = Arc::clone(&log);

    let t_in = thread::spawn(move || {
        pipe_and_log(io::stdin(), child_stdin, "client->server", log_in)
    });
    let t_out = thread::spawn(move || {
        pipe_and_log(child_stdout, io::stdout(), "server->client", log_out)
    });

    let status = child.wait()?;
    if let Err(e) = t_in.join().expect("stdin thread panicked") {
        eprintln!("warden: stdin relay error: {}", e);
    }
    if let Err(e) = t_out.join().expect("stdout thread panicked") {
        eprintln!("warden: stdout relay error: {}", e);
    }
    std::process::exit(status.code().unwrap_or(0));
}
