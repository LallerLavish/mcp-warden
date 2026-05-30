use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde_json::{json, Value};

pub type Log = Arc<Mutex<BufWriter<std::fs::File>>>;

pub fn log_line(log: &Log, direction: &str, line: &str) {
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
