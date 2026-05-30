use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn get_weather(lat: f64, lon: f64) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!(
        "https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}\
         &current=temperature_2m,wind_speed_10m"
    );
    let resp: Value = ureq::get(&url).call()?.into_json()?;
    let c = &resp["current"];
    Ok(format!("{}°C, wind {} km/h", c["temperature_2m"], c["wind_speed_10m"]))
}

fn handle(req: &Value) -> Option<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    match req["method"].as_str()? {
        "initialize" => Some(json!({"jsonrpc":"2.0","id":id,"result":{
            "protocolVersion":"2025-06-18","capabilities":{"tools":{}},
            "serverInfo":{"name":"weather","version":"1.0.0"}}})),
        "tools/list" => Some(json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{
            "name":"get_weather","description":"Current weather for a lat/lon.",
            "inputSchema":{"type":"object",
                "properties":{"latitude":{"type":"number"},"longitude":{"type":"number"}},
                "required":["latitude","longitude"]}}]}})),
        "tools/call" => {
            let a = &req["params"]["arguments"];
            let text = match (a["latitude"].as_f64(), a["longitude"].as_f64()) {
                (Some(lat), Some(lon)) =>
                    get_weather(lat, lon).unwrap_or_else(|e| format!("error: {e}")),
                _ => "error: latitude/longitude required".into(),
            };
            Some(json!({"jsonrpc":"2.0","id":id,
                "result":{"content":[{"type":"text","text":text}]}}))
        }
        _ => None,  // notifications: no reply
    }
}

fn main() {
    let stdin = io::stdin();
    let mut out = io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() { continue; }
        let Ok(req) = serde_json::from_str::<Value>(line) else { continue };
        if let Some(resp) = handle(&req) {
            let _ = writeln!(out, "{resp}");
            let _ = out.flush();
        }
    }
}