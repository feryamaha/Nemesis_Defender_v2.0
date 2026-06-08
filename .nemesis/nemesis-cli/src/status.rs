// src/status.rs
use std::fs;
use std::path::Path;

pub fn status(target_dir: &Path) -> anyhow::Result<()> {
    let nemesis_dir = target_dir.join(".nemesis");

    let installed = nemesis_dir.exists();
    println!("[nemesis] Installed: {}", if installed { "yes" } else { "no" });

    if !installed {
        return Ok(());
    }

    let bin_dir = nemesis_dir.join("bin");
    let bin_count = fs::read_dir(&bin_dir)?.count();
    println!("[nemesis] Binaries: {} files in {}", bin_count, bin_dir.display());

    let hooks_count = count_hooks(target_dir);
    println!("[nemesis] Hooks: {} IDEs configurados", hooks_count);

    if let Ok(content) = fs::read_to_string(nemesis_dir.join("config/deny-list.json")) {
        let pattern_count = content.matches(r#""id":"#).count();
        println!("[nemesis] Deny-list: {} patterns", pattern_count);
    }

    let pid_file = nemesis_dir.join("runtime/defender.pid");
    if pid_file.exists() {
        println!("[nemesis] Defender: running");
    } else {
        println!("[nemesis] Defender: not running");
    }

    println!("[nemesis] eBPF: {}", if cfg!(target_os = "linux") { "available" } else { "not available" });

    Ok(())
}

fn count_hooks(target_dir: &Path) -> usize {
    let ides = vec![".claude", ".devin", ".cursor", ".codex", ".openclaude"];
    ides.iter()
        .filter(|ide| target_dir.join(ide).exists())
        .count()
}
