// src/uninstall.rs
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn uninstall(target_dir: &Path) -> anyhow::Result<()> {
    println!("[nemesis] Uninstalling Nemesis...");

    let nemesis_dir = target_dir.join(".nemesis");

    // Parar daemon
    println!("[nemesis] Stopping defender daemon...");
    let pid_file = nemesis_dir.join("runtime/defender.pid");
    if pid_file.exists() {
        let pid_content = fs::read_to_string(&pid_file)?;
        if let Ok(pid) = pid_content.trim().parse::<u32>() {
            let _ = Command::new("kill").arg(pid.to_string()).output();
        }
    }

    // Remover binarios
    println!("[nemesis] Removing binaries...");
    let bin_dir = nemesis_dir.join("bin");
    if bin_dir.exists() {
        fs::remove_dir_all(&bin_dir)?;
    }

    // Remover hooks
    println!("[nemesis] Removing hooks...");
    remove_hooks(target_dir)?;

    // Remover logs e runtime
    println!("[nemesis] Cleaning up...");
    let logs_dir = nemesis_dir.join("logs");
    if logs_dir.exists() {
        fs::remove_dir_all(&logs_dir)?;
    }

    let runtime_dir = nemesis_dir.join("runtime");
    if runtime_dir.exists() {
        fs::remove_dir_all(&runtime_dir)?;
    }

    println!("[nemesis] Uninstalled.");
    Ok(())
}

fn remove_hooks(target_dir: &Path) -> anyhow::Result<()> {
    let hooks = vec![
        (".claude/settings.json", "Claude Code"),
        (".devin/hooks.json", "Devin"),
        (".cursor/hooks.json", "Cursor"),
        (".codex/hooks.json", "Codex"),
        (".openclaude/settings.json", "OpenClaude"),
    ];

    for (path, name) in hooks {
        let full_path = target_dir.join(path);
        if full_path.exists() {
            fs::remove_file(&full_path)?;
            println!("[nemesis] Removed: {}", name);
        }
    }

    Ok(())
}
