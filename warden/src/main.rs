use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use chrono::Utc;
use landlock::{
    Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
use serde::Deserialize;
use serde_json::{json, Value};

type Log = Arc<Mutex<BufWriter<std::fs::File>>>;

#[derive(Debug, Clone, Default, Deserialize)]
struct Policy {
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    write: Vec<String>,
}

fn apply_landlock(policy: &Policy) -> Result<(), Box<dyn std::error::Error>> {
    let abi = ABI::V1;
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))?
        .create()?;
    for p in &policy.read {
        ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new(p)?, AccessFs::from_read(abi)))?;
    }
    for p in &policy.write {
        ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new(p)?, AccessFs::from_all(abi)))?;
    }
    ruleset.restrict_self()?;
    Ok(())
}

fn log_line(log: &Log, direction: &str, line: &str) {
    let trimmed = line.trim_end();
    let msg: Value = serde_json::from_str(trimmed)
        .unwrap_or_else(|_| Value::String(trimmed.to_string()));
    let entry = json!({
        "ts": Utc::now().to_rfc3339(),
        "dir": direction,
        "msg": msg,
    });
    if let Ok(mut f) = log.lock() {
        let _ = writeln!(f, "{}", entry);
        let _ = f.flush();
    }
}

fn pipe_and_log<R: Read, W: Write>(
    src: R,
    mut dst: W,
    direction_tag: &'static str,
    log: Log,
) -> io::Result<()> {
    let mut reader = BufReader::new(src);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        log_line(&log, direction_tag, &line);
        if let Err(e) = dst.write_all(line.as_bytes()) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e);
        }
        dst.flush()?;
    }
    Ok(())
}

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

    // Parse warden's own flags
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

    // Load policy. No --policy = no sandbox (transparent proxy, M2 behavior).
    let policy: Policy = if let Some(p) = &policy_path {
        let s = std::fs::read_to_string(p).unwrap_or_else(|e| {
            eprintln!("warden: cannot read policy {}: {}", p, e);
            std::process::exit(2);
        });
        toml::from_str(&s).unwrap_or_else(|e| {
            eprintln!("warden: invalid policy TOML: {}", e);
            std::process::exit(2);
        })
    } else {
        Policy::default()
    };

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("warden.log")?;
    let log: Log = Arc::new(Mutex::new(BufWriter::new(log_file)));

    let mut cmd = Command::new(&child_argv[0]);
    cmd.args(&child_argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    // pre_exec runs in the forked child, just before exec(). Landlock
    // restrictions inherit across exec, so the wrapped server is sandboxed.
    if policy_path.is_some() {
        let policy_clone = policy.clone();
        unsafe {
            cmd.pre_exec(move || {
                apply_landlock(&policy_clone)
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