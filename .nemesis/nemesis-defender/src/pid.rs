//! PID file management for nemesis-defender daemon
//!
//! PID file location: .nemesis/runtime/defender.pid
//! (same directory as permission-gate.state.json)

use std::path::PathBuf;

fn pid_path() -> PathBuf {
    // Resolve `.nemesis/runtime/defender.pid` subindo do path do binário até o ancestral
    // chamado `.nemesis` — robusto para AMBOS os layouts (não assume profundidade fixa):
    //   dev:    .nemesis/target/release/nemesis-defender  → ancestral .nemesis → .nemesis/runtime/
    //   distro: .nemesis/bin/nemesis-defender             → ancestral .nemesis → .nemesis/runtime/
    // (Mesma estratégia de violations_log::ledger_path; evita o overshoot que criava
    //  `<raiz do projeto>/runtime/` solto no layout distribuído.)
    if let Ok(exe) = std::env::current_exe() {
        for anc in exe.ancestors() {
            if anc.file_name().map(|n| n == ".nemesis").unwrap_or(false) {
                let runtime = anc.join("runtime").join("defender.pid");
                if let Some(parent) = runtime.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                return runtime;
            }
        }
    }

    // Fallback (resolução pelo binário falhou): SEMPRE ancora em `.nemesis/` relativo ao CWD —
    // nunca solto na raiz do projeto.
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
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

/// O processo `pid` está vivo E é o nemesis-defender? (liveness + identidade, anti PID-reuse).
///
/// A identidade é checada porque o SO pode REUSAR um PID após a morte do daemon: sem confirmar
/// o nome do processo, um PID reciclado por outro programa seria tratado como "daemon vivo".
/// A liveness/identidade é resolvida por plataforma — crucial porque `/proc` NÃO existe no macOS
/// (era a causa-raiz dos 100+ daemons: o check via `/proc` falhava sempre, o PID era tido como
/// morto e cada `--ensure-daemon` do shell-hook subia um novo).
fn pid_alive_and_ours(pid: u32) -> bool {
    // Linux: `/proc/<pid>/comm` é confiável e não exige spawnar processo.
    #[cfg(target_os = "linux")]
    {
        let proc_comm = std::path::PathBuf::from(format!("/proc/{}/comm", pid));
        proc_comm.exists()
            && std::fs::read_to_string(&proc_comm)
                .map(|s| s.trim().starts_with("nemesis-defende"))
                .unwrap_or(false)
    }

    // macOS / BSD: NÃO há `/proc`. `ps -p <pid> -o comm=` imprime o caminho/nome do executável
    // se (e só se) o processo existe — liveness — e o basename confirma a identidade.
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout).lines().any(|line| {
                    std::path::Path::new(line.trim())
                        .file_name()
                        .map(|n| n.to_string_lossy().starts_with("nemesis-defende"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    // Windows: tasklist filtrado pelo PID.
    #[cfg(not(unix))]
    {
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid)])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }
}

pub fn is_daemon_running() -> bool {
    let Some(pid) = read_pid() else { return false };

    let alive = pid_alive_and_ours(pid);

    if !alive {
        // PID file obsoleto — limpa para o próximo caller subir um daemon fresco.
        let _ = std::fs::remove_file(pid_path());
    }

    alive
}
