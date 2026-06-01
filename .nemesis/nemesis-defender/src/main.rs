//! nemesis-defender daemon
//!
//! nemesis-defender — Iron Dome supply chain malware scanner
//!
//! Modes:
//!   --daemon              Start filesystem watcher (blocks)
//!   --ensure-daemon       Start daemon if not running (non-blocking, returns immediately)
//!   --stop                Stop running daemon via PID file
//!   --scan <path>         Scan single file (exit 2 = MALICIOUS)
//!   --install-shell-hook  Write minimal shell hook to ~/.zshrc and ~/.bashrc (run once)

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dry_run = args.contains(&"--dry-run".to_string())
        || std::env::var("NEMESIS_DEFENDER_DRY_RUN").is_ok();

    match args.get(1).map(|s| s.as_str()) {
        Some("--daemon") => {
            pid::write_pid_file();
            if dry_run {
                std::env::set_var("NEMESIS_DEFENDER_DRY_RUN", "1");
                eprintln!(
                    "[nemesis-defender] Iron Dome active (DRY-RUN mode) — PID {}",
                    std::process::id()
                );
            } else {
                eprintln!(
                    "[nemesis-defender] Iron Dome active — PID {}",
                    std::process::id()
                );
            }
            watcher::daemon::run();
            pid::remove_pid_file();
        }

        Some("--ensure-daemon") => {
            // Fast-path: daemon already running
            if pid::is_daemon_running() {
                std::process::exit(0);
            }

            // Acquire exclusive spawn-lock to prevent race (concurrent --ensure-daemon calls).
            // create_new(true) is atomic: only one process succeeds, others exit safely.
            let lock_path = pid::lock_path();
            let lock_acquired = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
                .is_ok();

            if !lock_acquired {
                // Lock exists — check if it is stale (process crashed before cleanup)
                let stale = std::fs::metadata(&lock_path)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.elapsed().ok())
                    .map(|age| age.as_secs() > 5)
                    .unwrap_or(false);

                if stale {
                    // Lock is older than 5s — previous spawner crashed; clean up and retry
                    let _ = std::fs::remove_file(&lock_path);
                    let retry = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&lock_path)
                        .is_ok();
                    if !retry {
                        // Another process grabbed it in the meantime; exit safely
                        std::process::exit(0);
                    }
                    // Lock acquired after stale cleanup — continue to spawn
                } else {
                    // Lock is recent — another process is actively spawning; exit safely
                    std::process::exit(0);
                }
            }

            // Re-check after acquiring lock (another process may have started daemon)
            if pid::is_daemon_running() {
                std::process::exit(0);
            }

            let exe = match std::env::current_exe() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[nemesis-defender] ERROR: cannot find own binary: {}", e);
                    std::process::exit(1);
                }
            };

            // Use binary's directory to find project root (immune to CWD changes)
            let project_root = exe
                .parent()
                .and_then(|release| release.parent())
                .and_then(|target| target.parent())
                .map(|nemesis| nemesis.parent().unwrap_or(nemesis).to_path_buf())
                .unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
                });

            match std::process::Command::new(&exe)
                .arg("--daemon")
                .current_dir(&project_root)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                Ok(child) => {
                    std::thread::sleep(std::time::Duration::from_millis(150));
                    let _ = std::fs::remove_file(&lock_path);
                    eprintln!("[nemesis-defender] Daemon started (PID {})", child.id());
                    std::process::exit(0);
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&lock_path);
                    eprintln!("[nemesis-defender] ERROR spawning daemon: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Some("--stop") => {
            if let Some(p) = pid::read_pid() {
                #[cfg(unix)]
                let _ = std::process::Command::new("kill")
                    .args(["-TERM", &p.to_string()])
                    .status();
                pid::remove_pid_file();
                eprintln!("[nemesis-defender] Daemon stopped (was PID {})", p);
            } else {
                eprintln!("[nemesis-defender] No daemon running.");
            }
        }

        Some("--scan") => {
            let path = match args.get(2) {
                Some(p) => std::path::PathBuf::from(p),
                None => {
                    eprintln!("[nemesis-defender] Usage: --scan <path>");
                    std::process::exit(1);
                }
            };
            let content = match std::fs::read(&path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[nemesis-defender] Cannot read {}: {}", path.display(), e);
                    std::process::exit(1);
                }
            };
            let result = nemesis_defender::scan_content(&path, &content);
            let _ = reporter::log_result(&result);
            if result.is_blocked() {
                eprintln!(
                    "[nemesis-defender] BLOCKED: {} — {} violation(s)",
                    path.display(),
                    result.violations.len()
                );
                for v in &result.violations {
                    eprintln!("  ├─ [{}] {}", v.visitor, v.message);
                    if let Some(ref suggestion) = v.suggestion {
                        eprintln!("  │   → FIX: {}", suggestion);
                    }
                }
                std::process::exit(2);
            } else if result.severity == nemesis_defender::Severity::Suspicious {
                eprintln!(
                    "[nemesis-defender] SUSPICIOUS: {} — {} signal(s) — logged",
                    path.display(),
                    result.violations.len()
                );
            }
            // CLEAN — silent exit 0
        }

        Some("--install-shell-hook") => {
            shell_hook::install();
        }

        _ => {
            eprintln!("[nemesis-defender] Nemesis Iron Dome");
            eprintln!("Usage:");
            eprintln!("  nemesis-defender --daemon [--dry-run]  Start filesystem watcher (--dry-run: log without deleting)");
            eprintln!("  nemesis-defender --ensure-daemon       Start if not running");
            eprintln!("  nemesis-defender --stop                Stop running daemon");
            eprintln!("  nemesis-defender --scan <path>         Scan single file");
            eprintln!(
                "  nemesis-defender --install-shell-hook  Install terminal hook (once per machine)"
            );
            eprintln!();
            eprintln!("Environment variables:");
            eprintln!("  NEMESIS_DEFENDER_DRY_RUN=1             Same as --dry-run flag");
            std::process::exit(1);
        }
    }
}

use nemesis_defender::{reporter, watcher};
mod pid;
mod shell_hook;
