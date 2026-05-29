// mcp-warden landlock proof-of-concept.
// Goal: prove the OS actually blocks file access we didn't allow.
// Run with `cargo run`. Requires Linux 5.13+ with landlock enabled.

use landlock::{
    Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
use std::fs;

/// Restrict the *current* process to read-only access beneath `allowed`.
/// Everything else on the filesystem becomes inaccessible.
fn enforce_readonly(allowed: &str) -> Result<(), Box<dyn std::error::Error>> {
    let abi = ABI::V1; // V1 = widest kernel support; BestEffort upgrades where available
    Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .add_rule(PathBeneath::new(PathFd::new(allowed)?, AccessFs::from_read(abi)))?
        .restrict_self()?;
    Ok(())
}

fn try_read(label: &str, path: &str) {
    match fs::read_to_string(path) {
        Ok(_) => println!("  [{label}] READABLE  {path}"),
        Err(e) => println!("  [{label}] BLOCKED   {path}  ({})", e.kind()),
    }
}

fn main() {
    let allowed = "/tmp/warden-allowed";
    let inside = format!("{allowed}/ok.txt");
    let outside = "/etc/os-release"; // stands in for ~/.ssh in the real M4 demo

    fs::create_dir_all(allowed).expect("setup: mkdir");
    fs::write(&inside, "hello from inside the jail\n").expect("setup: write");

    println!("== before landlock (both should be READABLE) ==");
    try_read("pre", &inside);
    try_read("pre", outside);

    println!("\napplying landlock: read-only, limited to {allowed}\n");
    enforce_readonly(allowed).expect("landlock enforcement failed");

    println!("== after landlock (inside READABLE, outside BLOCKED) ==");
    try_read("post", &inside);
    try_read("post", outside);
}