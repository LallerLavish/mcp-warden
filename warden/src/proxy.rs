use std::io::{self, BufRead, BufReader, Read, Write};

use crate::log::{log_line, Log};

pub fn pipe_and_log<R: Read, W: Write>(
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
