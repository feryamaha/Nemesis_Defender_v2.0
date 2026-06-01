//! Shell hook installer — Rust module that writes minimal hook to ~/.zshrc / ~/.bashrc
//!
//! The snippet written registers a hook inside the shell process and calls
//! nemesis-defender --ensure-daemon in the background.
//!
//! All detection logic is in Rust (daemon). Shell snippet = hook registration only.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Package manager commands that trigger daemon auto-start.
const TRIGGER_PATTERN: &str =
    "bun add|bun install|npm install|npm i |npm ci|yarn add|yarn install|pnpm add|pnpm install|pip install|pip3 install|cargo add|cargo build|cargo install";

/// Marker embedded in the snippet so we detect if already installed.
const HOOK_MARKER: &str = "# nemesis-defender-hook";

pub fn install() {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[nemesis-defender] ERROR: cannot find own binary: {}", e);
            std::process::exit(1);
        }
    };

    let exe_str = exe.display().to_string();

    let home = match home_dir() {
        Some(h) => h,
        None => {
            eprintln!("[nemesis-defender] ERROR: cannot determine home directory");
            std::process::exit(1);
        }
    };

    let zshrc = home.join(".zshrc");
    let bashrc = home.join(".bashrc");

    let zsh_snippet = format!(
        r#"
{marker}
_nemesis_nd_preexec() {{
  case "$1" in
    {triggers}) "{exe}" --ensure-daemon 2>/dev/null & ;;
  esac
}}
autoload -Uz add-zsh-hook && add-zsh-hook preexec _nemesis_nd_preexec
{marker}-end
"#,
        marker = HOOK_MARKER,
        triggers = TRIGGER_PATTERN,
        exe = exe_str
    );

    let bash_snippet = format!(
        r#"
{marker}
_nemesis_nd_debug() {{
  case "$BASH_COMMAND" in
    {triggers}) "{exe}" --ensure-daemon 2>/dev/null & ;;
  esac
}}
trap '_nemesis_nd_debug' DEBUG
{marker}-end
"#,
        marker = HOOK_MARKER,
        triggers = TRIGGER_PATTERN,
        exe = exe_str
    );

    let mut installed: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    for (rc_path, snippet) in [(&zshrc, &zsh_snippet), (&bashrc, &bash_snippet)] {
        match append_if_not_present(rc_path, snippet) {
            AppendResult::Appended => installed.push(rc_path.display().to_string()),
            AppendResult::AlreadyPresent => skipped.push(rc_path.display().to_string()),
            AppendResult::Error(e) => {
                eprintln!(
                    "[nemesis-defender] WARNING: cannot write to {}: {}",
                    rc_path.display(),
                    e
                );
            }
        }
    }

    if !installed.is_empty() {
        eprintln!("[nemesis-defender] Shell hook installed in:");
        for p in &installed {
            eprintln!("  ✓ {}", p);
        }
        eprintln!("[nemesis-defender] Restart your terminal or run:");
        eprintln!("  source ~/.zshrc   (zsh)");
        eprintln!("  source ~/.bashrc  (bash)");
    }

    if !skipped.is_empty() {
        eprintln!("[nemesis-defender] Already installed (skipped):");
        for p in &skipped {
            eprintln!("  - {}", p);
        }
    }
}

enum AppendResult {
    Appended,
    AlreadyPresent,
    Error(String),
}

fn append_if_not_present(path: &Path, snippet: &str) -> AppendResult {
    let existing = std::fs::read_to_string(path).unwrap_or_default();

    if existing.contains(HOOK_MARKER) {
        return AppendResult::AlreadyPresent;
    }

    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => return AppendResult::Error(e.to_string()),
    };

    match file.write_all(snippet.as_bytes()) {
        Ok(_) => AppendResult::Appended,
        Err(e) => AppendResult::Error(e.to_string()),
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("USERPROFILE").ok().map(PathBuf::from))
}
