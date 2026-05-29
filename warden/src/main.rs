use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::thread;

// Added an identifier so we know WHO is sending the message for the audit log
fn pipe_and_log<R: Read, W: Write>(src: R, mut dst: W, direction_tag: &'static str) -> io::Result<()> {
    let mut reader = BufReader::new(src);
    let mut line = String::new();
    
    loop {
        line.clear();
        // Read until newline (MCP spec uses newline-delimited JSON)
        if reader.read_line(&mut line)? == 0 {
            break; // EOF reached
        }

        // ==========================================
        // M2 TODO: AUDIT LOG INTERCEPTION POINT
        // Parse `line` as JSON here.
        // E.g., log_to_jsonl(direction_tag, &line);
        // ==========================================

        // Forward the payload to the actual destination
        if let Err(e) = dst.write_all(line.as_bytes()) {
            // If the pipe is broken (e.g., child died), stop trying to write
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
        eprintln!("usage: warden -- <command> [args...]");
        std::process::exit(2);
    };
    
    let child_argv = &args[sep + 1..];
    if child_argv.is_empty() {
        eprintln!("warden: missing command after `--`");
        std::process::exit(2);
    }

    let mut child = Command::new(&child_argv[0])
        .args(&child_argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let child_stdin = child.stdin.take().expect("Failed to open child stdin");
    let child_stdout = child.stdout.take().expect("Failed to open child stdout");

    // Spawn threads, passing the direction tag for M2 logging
    let t_in = thread::spawn(move || pipe_and_log(io::stdin(), child_stdin, "client->server"));
    let t_out = thread::spawn(move || pipe_and_log(child_stdout, io::stdout(), "server->client"));

    // Wait for the child to exit
    let status = child.wait()?;

    // Properly check if our threads panicked or encountered IO errors
    if let Err(e) = t_in.join().expect("stdin thread panicked") {
        eprintln!("warden: stdin relay error: {}", e);
    }
    if let Err(e) = t_out.join().expect("stdout thread panicked") {
        eprintln!("warden: stdout relay error: {}", e);
    }

    std::process::exit(status.code().unwrap_or(0));
}