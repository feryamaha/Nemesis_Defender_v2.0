//! denylist-defender.json loader
//!
//! Loads and caches the deny-list configuration from disk.
//! Used by the regex_layer scanner to detect hostile commands
//! in file content — works on any OS (macOS, Linux, Windows).

use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Debug, Deserialize, Clone)]
pub struct DenyListConfig {
    pub version: String,
    pub categories: HashMap<String, Category>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Category {
    pub description: String,
    pub severity: String,
    pub suggestion: Option<String>,
    pub patterns: Vec<String>,
}

static DENYLIST_CACHE: OnceLock<Option<DenyListConfig>> = OnceLock::new();

/// Resolve the path to denylist-defender.json
/// Tries multiple paths to handle different execution contexts.
fn resolve_config_path() -> Option<PathBuf> {
    let config_rel = ["config", "denylist-defender.json"]
        .iter()
        .collect::<PathBuf>();

    // Try 1: relative to the binary location (works regardless of CWD)
    // Binary at: .nemesis/target/release/nemesis-pretool-check-unix
    // Config at: .nemesis/nemesis-defender/config/denylist-defender.json
    if let Ok(exe) = std::env::current_exe() {
        let exe_dir = exe.parent()?;
        // From target/release/ → ../../nemesis-defender/config/
        let from_exe = exe_dir
            .join("..")
            .join("..")
            .join("nemesis-defender")
            .join(&config_rel);
        if from_exe.exists() {
            return Some(from_exe);
        }
        // Symlink or flat layout: binary dir itself
        let from_exe_flat = exe_dir.join(&config_rel);
        if from_exe_flat.exists() {
            return Some(from_exe_flat);
        }
    }

    let cwd = std::env::current_dir().ok()?;

    // Try 2: ./config/ (when CWD is nemesis-defender crate root)
    let from_cwd = cwd.join(&config_rel);
    if from_cwd.exists() {
        return Some(from_cwd);
    }

    // Try 3: ../config/ (from test/bin subdirectories)
    let from_parent = cwd.join("..").join(&config_rel);
    if from_parent.exists() {
        return Some(from_parent);
    }

    // Try 4: Project root context (CWD is Nemesis_Rust_v2.0/)
    let from_project = cwd
        .join(".nemesis")
        .join("nemesis-defender")
        .join(&config_rel);
    if from_project.exists() {
        return Some(from_project);
    }

    None
}

/// Load deny-list configuration (cached after first call)
pub fn load() -> Option<&'static DenyListConfig> {
    DENYLIST_CACHE
        .get_or_init(|| {
            let path = resolve_config_path()?;
            let content = std::fs::read_to_string(&path).ok()?;
            serde_json::from_str::<DenyListConfig>(&content).ok()
        })
        .as_ref()
}

/// Get all patterns flattened for a given severity
/// Returns: Vec<(category_name, pattern, description, suggestion)>
pub fn patterns_by_severity(severity: &str) -> Vec<(String, String, String, Option<String>)> {
    let mut result = Vec::new();

    if let Some(cfg) = load() {
        for (cat_name, cat) in &cfg.categories {
            if cat.severity == severity {
                for pattern in &cat.patterns {
                    result.push((
                        cat_name.clone(),
                        pattern.clone(),
                        cat.description.clone(),
                        cat.suggestion.clone(),
                    ));
                }
            }
        }
    }

    result
}
