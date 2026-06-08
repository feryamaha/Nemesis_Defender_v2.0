// =============================================================================
// nemesis-cgroup-watcher — Monitora processos do Devin e move
// automaticamente para o cgroup nemesis-agent.
// Roda como serviço systemd (root) para ter permissão de escrita no cgroup.
// =============================================================================

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("[nemesis-ebpf-kernel] eBPF kernel enforcement is available only on Linux.");
    eprintln!("[nemesis-ebpf-kernel] Non-Linux host detected — running stub placeholder (no-op).");
}

#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
const CGROUP_PROCS: &str = "/sys/fs/cgroup/nemesis-agent/cgroup.procs";
#[cfg(target_os = "linux")]
const POLL_INTERVAL: Duration = Duration::from_secs(2);

// Múltiplos padrões de agentes LLM para monitoramento
// Cada pattern é verificado com pgrep -f (match no cmdline completo)
// Usar paths específicos para evitar false positives
#[cfg(target_os = "linux")]
const AGENT_PATTERNS: &[&str] = &[
    // Devin
    "/usr/share/devin/devin",
    "devin",
    // Claude Code (todas as variantes de instalacao)
    ".claude/local/claude",
    ".local/share/claude/versions/",
    "claude-code",
    "claude",
    // OpenClaude / OpenCode
    "openclaude",
    "opencode",
    // Codex (OpenAI)
    "codex",
    // Cursor (ambas: instalacao padrao e AppImage)
    ".cursor/",
    "cursor",
    // Aider (AI pair programming)
    "aider",
    // Continue.dev
    "continue",
    // GitHub Copilot CLI
    "github-copilot",
    "copilot",
    // Amazon CodeWhisperer / Q Developer
    "codewhisperer",
    "amazon-q",
    // Cline (VSCode extension)
    "cline",
    // Devin
    "devin",
    // Replit Agent
    "replit",
    // Tabby
    "tabby",
];

#[cfg(target_os = "linux")]
fn is_in_cgroup(pid: u32) -> bool {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    fs::read_to_string(cgroup_path)
        .map(|content| content.contains("nemesis-agent"))
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn move_to_cgroup(pid: u32) -> bool {
    fs::write(CGROUP_PROCS, pid.to_string()).is_ok()
}

#[cfg(target_os = "linux")]
fn read_cgroup_pids() -> HashSet<u32> {
    fs::read_to_string(CGROUP_PROCS)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .collect()
}

#[cfg(target_os = "linux")]
fn find_agent_pids() -> Vec<u32> {
    let mut all_pids = Vec::new();

    for pattern in AGENT_PATTERNS {
        let output = Command::new("pgrep")
            .args(["-f", pattern])
            .output();

        if let Ok(out) = output {
            let pids: Vec<u32> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|line| line.trim().parse::<u32>().ok())
                .collect();
            all_pids.extend(pids);
        }
    }

    all_pids.sort_unstable();
    all_pids.dedup();
    all_pids
}

/// Coleta todos os descendentes de um PID (filhos, netos, etc.)
/// Usa /proc/<pid>/task/<pid>/children (mais rapido que pgrep -P)
#[cfg(target_os = "linux")]
fn collect_descendants(pid: u32, collected: &mut HashSet<u32>) {
    let children_path = format!("/proc/{}/task/{}/children", pid, pid);
    if let Ok(content) = fs::read_to_string(&children_path) {
        for token in content.split_whitespace() {
            if let Ok(child) = token.parse::<u32>() {
                if collected.insert(child) {
                    // Recursivo: coletar filhos dos filhos
                    collect_descendants(child, collected);
                }
            }
        }
    }
}

/// Move um PID e TODOS os seus descendentes para o cgroup
#[cfg(target_os = "linux")]
fn move_agent_and_descendants(pid: u32, known: &mut HashSet<u32>, moved: &mut HashSet<u32>) {
    if moved.contains(&pid) {
        return;
    }

    if is_in_cgroup(pid) {
        moved.insert(pid);
        // Mesmo ja estando no cgroup, pode ter filhos novos
        collect_descendants(pid, known);
        return;
    }

    if move_to_cgroup(pid) {
        eprintln!("[nemesis-watcher] PID {} movido para nemesis-agent", pid);
        moved.insert(pid);
    } else {
        return;
    }

    // Coletar e mover todos os descendentes
    let mut descendants = HashSet::new();
    collect_descendants(pid, &mut descendants);
    for &child in &descendants {
        if !moved.contains(&child) && move_to_cgroup(child) {
            eprintln!("[nemesis-watcher] PID {} (descendant) movido para nemesis-agent", child);
            moved.insert(child);
        }
    }
}

/// Varre /proc procurando processos cujo PPID ja esta no cgroup
/// Isto captura shells/bash que o agente CLI spawnou ANTES de ser movido
#[cfg(target_os = "linux")]
fn scan_orphans_by_ppid(cgroup_pids: &HashSet<u32>, moved: &mut HashSet<u32>) {
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid_str = entry.file_name().to_string_lossy().to_string();
            let Ok(pid) = pid_str.parse::<u32>() else { continue; };
            if moved.contains(&pid) || cgroup_pids.contains(&pid) {
                continue;
            }

            // Ler /proc/<pid>/stat para obter PPID (4o campo)
            let stat_path = format!("/proc/{}/stat", pid);
            let Ok(stat) = fs::read_to_string(&stat_path) else { continue; };
            let fields: Vec<&str> = stat.split_whitespace().collect();
            if fields.len() < 4 { continue; }
            let Ok(ppid) = fields[3].parse::<u32>() else { continue; };

            if cgroup_pids.contains(&ppid) || moved.contains(&ppid) {
                // Pai esta no cgroup — filho deve ir tambem
                if move_to_cgroup(pid) {
                    eprintln!("[nemesis-watcher] PID {} (orphan, PPID={}) movido para nemesis-agent", pid, ppid);
                    moved.insert(pid);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_for_cgroup() {
    let path = Path::new(CGROUP_PROCS);
    if path.exists() {
        return;
    }
    eprintln!("[nemesis-watcher] cgroup nemesis-agent nao existe. Aguardando...");
    while !path.exists() {
        thread::sleep(Duration::from_secs(5));
    }
    eprintln!("[nemesis-watcher] cgroup detectado. Iniciando monitoramento.");
}

#[cfg(target_os = "linux")]
fn main() {
    eprintln!("[nemesis-watcher] Iniciando monitoramento de processos de agentes LLM...");

    wait_for_cgroup();

    let mut known_pids: HashSet<u32> = HashSet::new();
    let mut moved_pids: HashSet<u32> = HashSet::new();

    loop {
        // 1. Encontrar PIDs que matcheiam AGENT_PATTERNS
        let agent_pids = find_agent_pids();

        // 2. Limpar PIDs que nao existem mais
        known_pids.retain(|pid| Path::new(&format!("/proc/{}", pid)).exists());
        moved_pids.retain(|pid| Path::new(&format!("/proc/{}", pid)).exists());

        // 3. Mover agentes + descendentes para o cgroup
        for &pid in &agent_pids {
            move_agent_and_descendants(pid, &mut known_pids, &mut moved_pids);
        }

        // 4. Scan por PPID: capturar processos cujo pai esta no cgroup
        // mas o proprio filho ainda nao foi movido
        let cgroup_pids = read_cgroup_pids();
        scan_orphans_by_ppid(&cgroup_pids, &mut moved_pids);

        thread::sleep(POLL_INTERVAL);
    }
}
