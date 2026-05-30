use landlock::{
    Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Tools {
    /// action for a tool with no explicit rule: "allow" | "ask" | "block"
    #[serde(default = "default_tool_action")]
    pub default: String,
    /// per-tool overrides
    #[serde(default)]
    pub rules: HashMap<String, String>,
}

impl Default for Tools {
    fn default() -> Self {
        Tools { default: "allow".into(), rules: HashMap::new() }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub network: Network,
    #[serde(default)]               
    pub tools: Tools, 
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Network {
    /// Allowed egress destinations: IPs, CIDRs, or hostnames.
    #[serde(default)]
    pub allow: Vec<String>,
}

pub fn apply_landlock(policy: &Policy) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn load(path: &str) -> Policy {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("warden: cannot read policy {}: {}", path, e);
        std::process::exit(2);
    });
    toml::from_str(&s).unwrap_or_else(|e| {
        eprintln!("warden: invalid policy TOML: {}", e);
        std::process::exit(2);
    })
}

fn default_tool_action() -> String { "allow".into() }