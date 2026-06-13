use crate::checks::{binary_action_path, nemesis_dir};
use crate::report::{CheckResult, CheckStatus};

pub fn run() -> CheckResult {
    let mut res = CheckResult::new("G6 - Daemon nemesis-defender");
    let pid_file = nemesis_dir().join("runtime").join("defender.pid");
    // Ação resolvida para o layout ativo (distro `.nemesis/bin/` ou fonte `target/release/`).
    // O caminho fixo `target/release` quebrava no Mac: o comando colado dava "no such file".
    let action = format!("Acao: {} --ensure-daemon", binary_action_path("nemesis-defender"));

    let pid = std::fs::read_to_string(&pid_file)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());

    let pid = match pid {
        Some(p) => p,
        None => {
            res.push("PID file ausente - daemon nao esta rodando.");
            res.push(action);
            return res.status(CheckStatus::Fail);
        }
    };

    #[cfg(target_os = "linux")]
    {
        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid)).unwrap_or_default();
        if !comm.trim().starts_with("nemesis-defende") {
            res.push(format!(
                "PID {} no PID file, mas processo nao esta vivo (stale).",
                pid
            ));
            res.push(action);
            return res.status(CheckStatus::Fail);
        }
        res.push(format!("OK    daemon vivo (PID {}).", pid));

        let mut inotify = 0;
        if let Ok(entries) = std::fs::read_dir(format!("/proc/{}/fd", pid)) {
            for e in entries.flatten() {
                if let Ok(target) = std::fs::read_link(e.path()) {
                    if target.to_string_lossy().contains("inotify") {
                        inotify += 1;
                    }
                }
            }
        }
        if inotify > 0 {
            res.push(format!(
                "OK    {} descritor(es) inotify aberto(s) - watcher ativo.",
                inotify
            ));
            return res.status(CheckStatus::Ok);
        }
        res.push("ATENCAO nenhum fd inotify - watcher pode estar inativo (fs.inotify.max_user_watches?).");
        return res.status(CheckStatus::Warn);
    }

    #[cfg(not(target_os = "linux"))]
    {
        // macOS/BSD: sem `/proc`. Confirma liveness + identidade via `ps -p <pid> -o comm=`
        // (mesmo método de pid.rs). Sem isso, o doctor dava "OK" só por existir o PID file,
        // mesmo com o daemon morto — laudo falso. (inotify/fd só é inspecionável no Linux.)
        let alive = std::process::Command::new("ps")
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
            .unwrap_or(false);

        if alive {
            res.push(format!(
                "OK    daemon vivo (PID {}). Inspecao de fd/watcher so no Linux.",
                pid
            ));
            return res.status(CheckStatus::Ok);
        }
        res.push(format!(
            "PID {} no PID file, mas processo nao esta vivo (stale).",
            pid
        ));
        res.push(action);
        return res.status(CheckStatus::Fail);
    }
}
