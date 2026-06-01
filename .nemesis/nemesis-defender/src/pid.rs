//! PID file management for nemesis-defender daemon
//!
//! PID file location: .nemesis/runtime/defender.pid
//! (same directory as permission-gate.state.json)

use std::path::PathBuf;

fn pid_path() -> PathBuf {
    // Derive absolute path from binary location — immune to CWD changes.
    // Binary: .nemesis/target/release/nemesis-defender
    // PID:    .nemesis/runtime/defender.pid
    if let Ok(exe) = std::env::current_exe() {
        // Walk up: release/ → target/ → .nemesis/ → runtime/
        if let Some(release_dir) = exe.parent() {
            if let Some(target_dir) = release_dir.parent() {
                if let Some(nemesis_dir) = target_dir.parent() {
                    let runtime = nemesis_dir.join("runtime").join("defender.pid");
                    if let Some(parent) = runtime.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    return runtime;
                }
            }
        }
    }

    // Fallback: CWD-based (only if binary path resolution fails)
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let from_root = cwd.join(".nemesis").join("runtime").join("defender.pid");
    if from_root.parent().map(|p| p.exists()).unwrap_or(false) {
        return from_root;
    }
    let from_nemesis = cwd.join("runtime").join("defender.pid");
    if from_nemesis.parent().map(|p| p.exists()).unwrap_or(false) {
        return from_nemesis;
    }
    let _ = std::fs::create_dir_all(cwd.join(".nemesis").join("runtime"));
    cwd.join(".nemesis").join("runtime").join("defender.pid")
}

/// Path to the exclusive spawn-lock file (prevents duplicate daemon spawning)
pub fn lock_path() -> std::path::PathBuf {
    pid_path().with_extension("lock")
}

pub fn write_pid_file() {
    let pid = std::process::id();
    let path = pid_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, pid.to_string());
}

pub fn remove_pid_file() {
    let _ = std::fs::remove_file(pid_path());
}

pub fn read_pid() -> Option<u32> {
    std::fs::read_to_string(pid_path())
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

pub fn is_daemon_running() -> bool {
    let Some(pid) = read_pid() else { return false };

    // Check if process with this PID is actually alive
    #[cfg(unix)]
    {
        // kill -0 sends no signal but returns 0 if process exists
        let alive = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !alive {
            // Stale PID file — clean up so next caller spawns a fresh daemon
            let _ = std::fs::remove_file(pid_path());
        }

        alive
    }

    #[cfg(not(unix))]
    {
        // Windows: check via tasklist
        let out = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid)])
            .output();
        let alive = out
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false);
        if !alive {
            let _ = std::fs::remove_file(pid_path());
        }
        alive
    }
}
