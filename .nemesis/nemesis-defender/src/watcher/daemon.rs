//! Filesystem daemon — Iron Dome continuous monitoring
//!
//! Uses the `notify` crate for cross-platform filesystem watching:
//! - Linux:   inotify
//! - macOS:   FSEvents / kqueue
//! - Windows: ReadDirectoryChangesW
//!
//! Watches all IDE config dirs + project paths for new/modified files.
//! On MALICIOUS detection: removes file + logs + alerts stderr.
//! On SUSPICIOUS detection: logs + alerts stderr (file kept, user decides).

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::SystemTime;

use crate::watcher::{
    SUSPICIOUS_EXTENSIONS, SUSPICIOUS_FILE_NAMES, SYSTEM_WATCH_PATHS, WATCH_PATHS,
};
use crate::{reporter, scan_content, DefenderResult, DefenderViolation, Language, Severity};

// Session awareness for multi-turn attack detection
static mut SESSION_BUFFER: Option<SessionBuffer> = None;

fn get_session_buffer_mut() -> &'static mut SessionBuffer {
    unsafe {
        SESSION_BUFFER
            .as_mut()
            .expect("Session buffer not initialized")
    }
}

fn get_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

// Session awareness for multi-turn attack detection
const MAX_SESSION_EVENTS: usize = 50;
const ESCALATION_WINDOW_SECS: u64 = 300; // 5 minutes
const ALERT_COOLDOWN_SECS: u64 = 60; // mesmo tipo nao re-dispara por 60s
const BRUTE_FORCE_THRESHOLD: usize = 5; // apenas risk_level==2 conta

#[derive(Clone, Debug)]
struct SessionEvent {
    timestamp: SystemTime,
    tool_type: String,
    target: String,
    risk_level: u8,
    blocked: bool,
}

struct SessionBuffer {
    events: VecDeque<SessionEvent>,
    last_alert: HashMap<String, SystemTime>, // cooldown por tipo
}

impl SessionBuffer {
    fn new() -> Self {
        SessionBuffer {
            events: VecDeque::with_capacity(MAX_SESSION_EVENTS),
            last_alert: HashMap::new(),
        }
    }

    fn push(&mut self, event: SessionEvent) {
        if self.events.len() >= MAX_SESSION_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    fn detect_escalation(&mut self) -> Option<String> {
        let now = SystemTime::now();
        let window: Vec<&SessionEvent> = self
            .events
            .iter()
            .filter(|e| {
                now.duration_since(e.timestamp)
                    .map(|d| d.as_secs() < ESCALATION_WINDOW_SECS)
                    .unwrap_or(false)
            })
            .collect();

        // Pattern 1: Read sensivel → Bash com rede
        let read_sensitive = window
            .iter()
            .any(|e| e.tool_type == "Read" && is_sensitive_target(&e.target));
        let network_after = window
            .iter()
            .any(|e| e.tool_type == "Bash" && has_network_command(&e.target));

        if read_sensitive && network_after && self.can_alert("ESCALATION", &now) {
            self.last_alert.insert("ESCALATION".into(), now);
            return Some(
                "ESCALATION: leitura de arquivo sensivel seguida de comando de rede".into(),
            );
        }

        // Pattern 2: Brute force — apenas risk_level==2 (malicious) conta
        let blocked_count = window
            .iter()
            .filter(|e| e.blocked && e.risk_level == 2)
            .count();
        if blocked_count >= BRUTE_FORCE_THRESHOLD && self.can_alert("BRUTE_FORCE", &now) {
            self.last_alert.insert("BRUTE_FORCE".into(), now);
            return Some(format!(
                "BRUTE FORCE: {} tentativas maliciosas bloqueadas em {} segundos",
                blocked_count, ESCALATION_WINDOW_SECS
            ));
        }

        // Pattern 3: Recon — acesso progressivo a diretorios
        let unique_dirs: std::collections::HashSet<String> = window
            .iter()
            .filter(|e| e.tool_type == "Read" || e.tool_type == "ListDir")
            .map(|e| extract_parent_dir(&e.target))
            .filter(|d| !d.is_empty())
            .collect();
        if unique_dirs.len() >= 8 && self.can_alert("RECON", &now) {
            self.last_alert.insert("RECON".into(), now);
            return Some(format!(
                "RECON: acesso a {} diretorios distintos em {} segundos",
                unique_dirs.len(),
                ESCALATION_WINDOW_SECS
            ));
        }

        None
    }

    fn can_alert(&self, kind: &str, now: &SystemTime) -> bool {
        match self.last_alert.get(kind) {
            None => true,
            Some(last) => now
                .duration_since(*last)
                .map(|d| d.as_secs() >= ALERT_COOLDOWN_SECS)
                .unwrap_or(true),
        }
    }
}

// Helper functions for session analysis
fn is_sensitive_target(target: &str) -> bool {
    let sensitive_patterns = [
        ".env",
        ".env.",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        ".aws/",
        ".azure/",
        ".gcp/",
        "service-account",
        "secrets",
        "credentials",
        "passwd",
        "shadow",
        ".npmrc",
        ".yarnrc",
        ".pypirc",
        ".cargo/",
        ".netrc",
        ".pgpass",
    ];
    sensitive_patterns
        .iter()
        .any(|&pattern| target.contains(pattern))
}

fn has_network_command(target: &str) -> bool {
    let network_patterns = [
        "curl", "wget", "http", "ftp", "ssh", "scp", "rsync", "nc ", "netcat", "telnet", "ftp ",
        "tftp",
    ];
    network_patterns
        .iter()
        .any(|&pattern| target.contains(pattern))
}

fn extract_parent_dir(path: &str) -> String {
    use std::path::Path;
    Path::new(path)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("")
        .to_string()
}

fn maybe_rotate_session_log(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > 1_048_576 {
            let _ = std::fs::write(path, "");
        }
    }
}

fn poll_session_events(session_path: &Path, last_pos: &mut u64) -> Vec<SessionEvent> {
    let mut events = Vec::new();

    let file = match std::fs::File::open(session_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);

    if file_len < *last_pos {
        *last_pos = 0;
    }

    let mut reader = std::io::BufReader::new(file);
    if reader.seek(SeekFrom::Start(*last_pos)).is_err() {
        return events;
    }

    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let ts_millis = parsed["ts"].as_u64().unwrap_or(0);
                let ts = SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ts_millis);
                events.push(SessionEvent {
                    timestamp: ts,
                    tool_type: parsed["tool"].as_str().unwrap_or("Unknown").to_string(),
                    target: parsed["target"].as_str().unwrap_or("").to_string(),
                    risk_level: parsed["risk"].as_u64().unwrap_or(0) as u8,
                    blocked: parsed["blocked"].as_bool().unwrap_or(false),
                });
            }
        }
        line.clear();
    }

    *last_pos = reader.stream_position().unwrap_or(file_len);
    events
}

fn is_project_path(path: &Path, cwd: &Path) -> bool {
    path.starts_with(cwd)
}

/// Verdadeiro se `cwd` NÃO é uma raiz de projeto segura para o daemon deletar dentro.
/// Recusa: raiz do filesystem ("/"), o próprio HOME do usuário, diretórios rasos demais,
/// e qualquer dir que não contenha `.nemesis/`. Isso impede o escopo GLOBAL (varrer/deletar
/// o disco inteiro) que causou data-loss no macOS quando a raiz era mal resolvida.
fn is_unsafe_root(cwd: &Path) -> bool {
    // Raiz do filesystem (sem parent) — ex.: "/"
    if cwd.parent().is_none() {
        return true;
    }
    // HOME do usuário não é raiz de projeto (Nemesis é per-projeto, não global)
    if let Some(home) = get_home() {
        if cwd == home {
            return true;
        }
    }
    // Diretórios rasos demais (ex.: "/Users", "/home", "/tmp") — provável engano de resolução
    if cwd.components().count() < 3 {
        return true;
    }
    // Raiz legítima de projeto Nemesis SEMPRE contém `.nemesis/`. Sem isso, não é projeto.
    if !cwd.join(".nemesis").is_dir() {
        return true;
    }
    false
}

fn should_scan_tmp_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Extensoes suspeitas
    if SUSPICIOUS_EXTENSIONS.iter().any(|ext| name.ends_with(ext)) {
        return true;
    }

    // Nomes suspeitos
    let name_lower = name.to_lowercase();
    if SUSPICIOUS_FILE_NAMES.iter().any(|s| name_lower.contains(s)) {
        return true;
    }

    // Sem extensao (pode ser binario)
    if !name.contains('.') && name.len() > 2 {
        return true;
    }

    false
}

pub fn run() {
    // Initialize session buffer for multi-turn attack detection
    unsafe {
        SESSION_BUFFER = Some(SessionBuffer::new());
    }

    eprintln!(
        "[nemesis-defender] Daemon starting — watching {} path groups",
        WATCH_PATHS.len()
    );

    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();

    let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("[nemesis-defender] FATAL: cannot create watcher: {}", e);
            std::process::exit(1);
        }
    };

    // Register all watch paths that exist in the current working directory
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    // ── SAFETY GUARD (anti escopo global / data-loss) ──
    // O daemon DELETA arquivos Malicious dentro de `cwd` (is_project_path = starts_with cwd).
    // Se `cwd` resolver para HOME, raiz do filesystem, ou um diretório raso demais, o escopo
    // de deleção vira GLOBAL — o daemon varreria/deletaria o disco inteiro e interferiria em
    // outros projetos (data-loss observado no macOS, onde a raiz era mal resolvida).
    // Nemesis é PER-PROJETO: a raiz legítima contém `.nemesis/`. Fail-safe: recusar iniciar.
    if is_unsafe_root(&cwd) {
        eprintln!(
            "[nemesis-defender] ABORT: raiz de projeto insegura para o daemon: '{}'. \
             O escopo de deleção seria global (HOME/raiz/sem .nemesis). \
             Inicie o daemon a partir da raiz de um projeto Nemesis (que contém .nemesis/).",
            cwd.display()
        );
        return;
    }

    let mut watched_count = 0;

    // Grupo A: paths do projeto (relativos ao CWD)
    for &watch_path in WATCH_PATHS {
        let full_path = cwd.join(watch_path);
        if full_path.exists() {
            match watcher.watch(&full_path, RecursiveMode::Recursive) {
                Ok(_) => {
                    eprintln!("[nemesis-defender] Watching: {}", full_path.display());
                    watched_count += 1;
                }
                Err(e) => {
                    eprintln!(
                        "[nemesis-defender] Warning: cannot watch {}: {}",
                        full_path.display(),
                        e
                    );
                }
            }
        }
    }

    // Grupo B: paths de sistema (absolutos, expandidos com $HOME)
    if let Some(home) = get_home() {
        for &watch_path in SYSTEM_WATCH_PATHS {
            let full_path = home.join(watch_path);
            if full_path.exists() {
                match watcher.watch(&full_path, RecursiveMode::Recursive) {
                    Ok(_) => {
                        eprintln!(
                            "[nemesis-defender] Watching (system): {}",
                            full_path.display()
                        );
                        watched_count += 1;
                    }
                    Err(e) => {
                        eprintln!(
                            "[nemesis-defender] Warning: cannot watch {}: {}",
                            full_path.display(),
                            e
                        );
                    }
                }
            }
        }

        // Shell config files individuais
        let shell_configs = [".bashrc", ".zshrc", ".profile", ".bash_profile"];
        for f in &shell_configs {
            let full_path = home.join(f);
            if full_path.exists() {
                match watcher.watch(&full_path, RecursiveMode::NonRecursive) {
                    Ok(_) => {
                        eprintln!(
                            "[nemesis-defender] Watching (shell config): {}",
                            full_path.display()
                        );
                        watched_count += 1;
                    }
                    Err(_) => {} // arquivo unico pode falhar — ignorar
                }
            }
        }
    }

    // /tmp/ — staging area (com filtro)
    let tmp = PathBuf::from("/tmp");
    if tmp.exists() {
        match watcher.watch(&tmp, RecursiveMode::NonRecursive) {
            Ok(_) => {
                eprintln!("[nemesis-defender] Watching (tmp): /tmp/ (filtered)");
                watched_count += 1;
            }
            Err(e) => {
                eprintln!("[nemesis-defender] Warning: cannot watch /tmp/: {}", e);
            }
        }
    }

    if watched_count == 0 {
        eprintln!("[nemesis-defender] Warning: inotify watches unavailable — running in session-poll-only mode");
        eprintln!("[nemesis-defender] Multi-turn detection via pretool events remains active.");
        eprintln!("[nemesis-defender] To restore filesystem monitoring: sudo sysctl -w fs.inotify.max_user_watches=524288");
    }

    eprintln!(
        "[nemesis-defender] Iron Dome active — watching {} inotify paths",
        watched_count
    );

    // Estado de runtime (não log): o pretool escreve aqui cada tool-call; o daemon lê para
    // a correlação comportamental (multi-turn / escalação). Fica em .nemesis/runtime/.
    let session_events_path = cwd.join(".nemesis/runtime/session-events.jsonl");
    let mut session_file_pos: u64 = 0;
    let poll_interval = std::time::Duration::from_millis(5000); // 5s — evita write-storm e reduz uso de CPU

    // Event loop — inotify events + pretool session events polled every 500ms
    loop {
        match rx.recv_timeout(poll_interval) {
            Ok(Ok(event)) => handle_event(event, &cwd),
            Ok(Err(e)) => eprintln!("[nemesis-defender] Watch error: {}", e),
            Err(_) => {} // timeout — fall through to session poll
        }

        maybe_rotate_session_log(&session_events_path);
        let pretool_events = poll_session_events(&session_events_path, &mut session_file_pos);
        for ev in pretool_events {
            let buffer = get_session_buffer_mut();
            buffer.push(ev);
            if let Some(msg) = buffer.detect_escalation() {
                // &mut self — inclui cooldown
                eprintln!(
                    "[nemesis-defender] 🚨 MULTI-TURN ESCALATION DETECTED: {}",
                    msg
                );
                let _ = reporter::log_escalation(&msg);
            }
        }
    }
}

fn handle_event(event: Event, cwd: &Path) {
    // Reage a criação, modificação de DADOS e RENAME-para-dentro (MovedTo).
    // O `Modify(Name)` é essencial: editores (vim/VS Code) salvam por escrita-em-temp +
    // rename atômico, e `git checkout`/`npm` extraem por rename — todos geram MOVED_TO,
    // NÃO Create/Modify(Data). Sem isto, arquivo malicioso plantado por essas vias escapava
    // do Iron Dome. Ignora apenas deleção e metadata (chmod/touch).
    use notify::event::ModifyKind;
    let is_write_event = matches!(
        event.kind,
        EventKind::Create(_)
            | EventKind::Modify(ModifyKind::Data(_))
            | EventKind::Modify(ModifyKind::Name(_))
            | EventKind::Modify(ModifyKind::Any)
    );

    if !is_write_event {
        return;
    }

    for path in event.paths {
        // Skip directories
        if path.is_dir() {
            continue;
        }

        // Skip .nemesis/logs/ (our own log files — avoid feedback loop)
        if path.components().any(|c| c.as_os_str() == ".nemesis")
            && path.components().any(|c| c.as_os_str() == "logs")
        {
            continue;
        }

        // Skip binary files by extension
        if should_skip_extension(&path) {
            continue;
        }

        // Skip paths isentos (pentests, documentação de teste)
        if crate::is_path_excluded(&path) {
            continue;
        }

        // /tmp/ filter: only scan suspicious files
        if path.starts_with("/tmp") && !should_scan_tmp_file(&path) {
            continue;
        }

        // NUNCA re-escanear a própria quarentena: o malware retido lá dispararia um loop
        // infinito de detecção. Os itens em .nemesis/quarantine/ são inertes e aguardam
        // decisão humana (restore/purge).
        if path.to_string_lossy().contains("/.nemesis/quarantine/") {
            continue;
        }

        // inotify only sees CREATE/MODIFY — always Write
        // Read/Bash events come via poll_session_events() from pretool
        let tool_type = "Write".to_string();

        // Scan the file and delete if Malicious
        let result = scan_file_return_result(&path, cwd);
        scan_file(&path, cwd);

        // Determine risk level
        let risk_level = match result.severity {
            Severity::Clean => 0,
            Severity::Suspicious => 1,
            Severity::Malicious => 2,
        };

        // Check if this would be blocked (for tracking blocked attempts)
        let blocked = matches!(result.severity, Severity::Malicious)
            && is_project_path(&path, cwd)
            && !path.to_string_lossy().contains("/.nemesis/")
            && !path.to_string_lossy().ends_with("/.nemesis");

        // Add event to session buffer
        let event = SessionEvent {
            timestamp: SystemTime::now(),
            tool_type,
            target: path.display().to_string(),
            risk_level,
            blocked,
        };

        let mut buffer = get_session_buffer_mut();
        buffer.push(event);

        // Check for escalation after each event
        if let Some(escalation_msg) = buffer.detect_escalation() {
            eprintln!(
                "[nemesis-defender] 🚨 MULTI-TURN ESCALATION DETECTED: {}",
                escalation_msg
            );
            // Log the escalation
            let _ = reporter::log_escalation(&escalation_msg);
        }
    }
}

// Modified scan_file to return the result instead of just processing it
fn scan_file_return_result(path: &Path, cwd: &Path) -> DefenderResult {
    // Skip .nemesis/logs/ (our own log files — avoid feedback loop)
    if path.components().any(|c| c.as_os_str() == ".nemesis")
        && path.components().any(|c| c.as_os_str() == "logs")
    {
        return DefenderResult {
            violations: Vec::new(),
            severity: Severity::Clean,
            scan_depth: 0,
            path: path.to_path_buf(),
            language: Language::Unknown,
        };
    }

    // Skip binary files by extension
    if should_skip_extension(&path) {
        return DefenderResult {
            violations: Vec::new(),
            severity: Severity::Clean,
            scan_depth: 0,
            path: path.to_path_buf(),
            language: Language::Unknown,
        };
    }

    // Skip paths isentos (pentests, documentação de teste)
    if crate::is_path_excluded(&path) {
        return DefenderResult {
            violations: Vec::new(),
            severity: Severity::Clean,
            scan_depth: 0,
            path: path.to_path_buf(),
            language: Language::Unknown,
        };
    }

    // /tmp/ filter: only scan suspicious files
    if path.starts_with("/tmp") && !should_scan_tmp_file(&path) {
        return DefenderResult {
            violations: Vec::new(),
            severity: Severity::Clean,
            scan_depth: 0,
            path: path.to_path_buf(),
            language: Language::Unknown,
        };
    }

    let content = match std::fs::read(path) {
        Ok(c) => c,
        Err(_) => {
            return DefenderResult {
                violations: Vec::new(),
                severity: Severity::Clean,
                scan_depth: 0,
                path: path.to_path_buf(),
                language: Language::Unknown,
            }
        } // File may have been deleted already — ignore
    };

    // Skip large files (> 1MB) — not typical for source/skill files
    if content.len() > 1_048_576 {
        return DefenderResult {
            violations: Vec::new(),
            severity: Severity::Clean,
            scan_depth: 0,
            path: path.to_path_buf(),
            language: Language::Unknown,
        };
    }

    scan_content(path, &content)
}

fn scan_file(path: &Path, cwd: &Path) {
    let content = match std::fs::read(path) {
        Ok(c) => c,
        Err(_) => return, // File may have been deleted already — ignore
    };

    // Skip large files (> 1MB) — not typical for source/skill files
    if content.len() > 1_048_576 {
        return;
    }

    let result = scan_content(path, &content);

    match result.severity {
        Severity::Clean => {
            // Silencioso
        }
        Severity::Suspicious => {
            let _ = reporter::log_result(&result);
            eprintln!(
                "[nemesis-defender] ⚠ SUSPICIOUS: {} — {} violation(s) — see .nemesis/logs/defender.log",
                path.display(),
                result.violations.len()
            );
            for v in &result.violations {
                eprintln!("  ├─ [{}] {}", v.visitor, v.message);
            }
        }
        Severity::Malicious => {
            let _ = reporter::log_result(&result);
            // Ledger unificado de bloqueios (vocabulário padrão das 6 mensagens).
            crate::violations_log::append(
                "nemesis-defender",
                &format!(
                    "NEMESIS SEC - CONTEUDO MALICIOSO DETECTADO · {}",
                    path.display()
                ),
            );
            let dry_run = std::env::var("NEMESIS_DEFENDER_DRY_RUN").is_ok();

            if is_project_path(path, cwd) {
                // PROTECAO: NAO deletar nenhum arquivo dentro de .nemesis/
                if path.to_string_lossy().contains("/.nemesis/")
                    || path.to_string_lossy().ends_with("/.nemesis")
                {
                    let prefix = if dry_run { "[DRY-RUN] " } else { "" };
                    eprintln!(
                        "[nemesis-defender] {}██ BLOCKED (Nemesis infrastructure protected): {} — {} violation(s)",
                        prefix,
                        path.display(),
                        result.violations.len()
                    );
                    eprintln!("  ⚠️  Este arquivo é parte da infraestrutura do Nemesis e não pode ser deletado automaticamente.");
                    eprintln!("  ⚠️  Revise o código e corrija manualmente se necessário.");
                } else {
                    // DENTRO do projeto (NAO Nemesis): deletar (ou log se dry-run)
                    let (removed, prefix) = if dry_run {
                        // DRY-RUN: log but don't delete
                        eprintln!(
                            "[nemesis-defender] [DRY-RUN] ██ WOULD BE BLOCKED + REMOVED: {} — {} violation(s)",
                            path.display(),
                            result.violations.len()
                        );
                        (false, "[DRY-RUN] ")
                    } else {
                        // Normal mode: QUARENTENA — move para .nemesis/quarantine/ em vez de
                        // deletar. Retém o conteúdo para revisão humana (restore/purge).
                        match crate::quarantine::quarantine_file(path, &result) {
                            Ok(id) => {
                                eprintln!(
                                    "[nemesis-defender] ██ BLOCKED + QUARANTINED: {} — {} violation(s) → .nemesis/quarantine/{}",
                                    path.display(),
                                    result.violations.len(),
                                    id
                                );
                                eprintln!("  ⚠️  PARE. Arquivo malicioso retido para revisão humana.");
                                eprintln!("  ⚠️  Revise:  nemesis-defender --quarantine show {}", id);
                                eprintln!("  ⚠️  Decida:  --quarantine restore <id> (falso-positivo) | purge <id> (expurgar)");
                                (true, "")
                            }
                            Err(e) => {
                                eprintln!(
                                    "[nemesis-defender] ██ MALICIOUS: {} — falha ao quarentenar ({}). Acao manual necessaria.",
                                    path.display(),
                                    e
                                );
                                (false, "")
                            }
                        }
                    };
                }
            } else {
                // FORA do projeto: ALERTAR mas NAO deletar
                let prefix = if dry_run { "[DRY-RUN] " } else { "" };
                eprintln!(
                    "[nemesis-defender] {}██ MALICIOUS DETECTED (system path — NOT DELETED): {} — {} violation(s)",
                    prefix,
                    path.display(),
                    result.violations.len()
                );
                eprintln!("  ⚠️  Path de sistema — remova manualmente se necessario.");
            }

            eprintln!("[nemesis-defender] Full report: .nemesis/logs/defender.log");
            for v in &result.violations {
                eprintln!(
                    "  ├─ [{}] Line {}:{} — {}",
                    v.visitor, v.line, v.col, v.message
                );
                if let Some(decoded) = &v.decoded {
                    let preview = &decoded[..decoded.len().min(100)];
                    eprintln!("  │   Decoded: {}...", preview);
                }
            }
        }
    }
}

fn should_skip_extension(path: &Path) -> bool {
    let skip_exts = &[
        "png", "jpg", "jpeg", "gif", "webp", "ico", "svg", "woff", "woff2", "ttf", "eot", "zip",
        "tar", "gz", "br", "lock", // bun.lockb, package-lock.json
        "map",  // source maps
        // Documentos/markup NÃO são código executável — o Iron Dome (daemon) visa malware
        // que executa. Docs (README, landing page, manuais) legitimamente CONTÊM strings de
        // ataque como exemplo/documentação; escaneá-los geraria falso-positivo (quarentenar
        // o próprio index.html/README). O scan de conteúdo no write-time (pretool) continua.
        "md", "markdown", "html", "htm", "txt", "rst", "csv",
        // Logs/telemetria do próprio Nemesis NÃO são código — e contêm nomes de comando e
        // strings de evidência das detecções, que casariam padrões e gerariam auto-scan FP
        // (o daemon quarentenando o próprio defender.log/violations.log). Pular sempre.
        "log", "jsonl",
    ];

    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| skip_exts.contains(&ext))
        .unwrap_or(false)
}
