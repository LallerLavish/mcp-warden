use landlock::{
    Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
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
