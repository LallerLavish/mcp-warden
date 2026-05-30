use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};

const RED: &str = "\x1b[31m";
const GRN: &str = "\x1b[32m";
const CYN: &str = "\x1b[36m";
const DIM: &str = "\x1b[2m";
const BLD: &str = "\x1b[1m";
const RST: &str = "\x1b[0m";

fn hhmmss(ts: &str) -> &str {
    ts.get(11..19).unwrap_or(ts) // 2026-05-30T10:08:20.39... -> 10:08:20
}

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| "warden.log".into());
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cannot open {path}: {e}");
            std::process::exit(1);
        }
    };

    println!("{BLD}warden audit trail{RST}  {DIM}({path}){RST}\n");

    for line in BufReader::new(file).lines() {
        let Ok(line) = line else { continue };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };

        let ts = v["ts"].as_str().map(hhmmss).unwrap_or("--:--:--");
        let to_server = v["dir"].as_str().unwrap_or("").starts_with("client");
        let arrow = if to_server { "→ server" } else { "← server" };
        let msg = &v["msg"];

        // request / notification
        if let Some(method) = msg["method"].as_str() {
            match msg["params"]["name"].as_str() {
                Some(tool) => println!(
                    "{DIM}{ts}{RST} {CYN}{BLD}{arrow}{RST}  {method}  {BLD}{tool}{RST}"
                ),
                None => println!("{DIM}{ts}{RST} {CYN}{BLD}{arrow}{RST}  {method}"),
            }
            continue;
        }

        // response: surface each text line, flag denials
        let mut printed = false;
        if let Some(arr) = msg["result"]["content"].as_array() {
            for c in arr {
                if let Some(text) = c["text"].as_str() {
                    for tl in text.lines() {
                        let tl = tl.trim();
                        if tl.is_empty() {
                            continue;
                        }
                        if tl.contains("BLOCKED") || tl.contains("Permission denied") {
                            println!("{DIM}{ts}{RST} {arrow}  {RED}{BLD}⛔ DENIED{RST} {RED}{tl}{RST}");
                        } else {
                            println!("{DIM}{ts}{RST} {arrow}  {GRN}✓{RST} {tl}");
                        }
                        printed = true;
                    }
                }
            }
        }
        if msg.get("error").is_some() {
            println!("{DIM}{ts}{RST} {arrow}  {RED}error{RST} {}", msg["error"]);
            printed = true;
        }
        if !printed {
            println!("{DIM}{ts}{RST} {arrow}  {DIM}(response){RST}");
        }
    }
}