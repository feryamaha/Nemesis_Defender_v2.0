//! nemesis-defender — Iron Dome supply chain malware scanner
//!
//! Scans file content for malicious intent:
//! - Vetor 1: postinstall/preinstall script abuse
//! - Vetor 2: decode-then-exec (base64/hex/charCode)
//! - Vetor 3: Unicode steganography (BiDi/PUA/homoglyphs — CVE-2021-42574)
//! - Vetor 4: indirect prompt injection (AI skill poisoning)
//! - Vetor 5: multi-stage/time-gated execution
//! - Vetor 6: dynamic command construction
//! - Vetor 7: credential harvesting + exfiltration
//! - Vetor 8: self-cleaning malware

pub mod language;
pub mod reporter;
pub mod scanner;
pub mod visitors;
pub mod watcher;

use language::detect_language;
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────
// PUBLIC TYPES
// ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Language {
    JavaScript,
    TypeScript,
    Bash,
    Python,
    Toml,
    Json,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DefenderViolation {
    /// Identifier of the visitor that raised this violation
    pub visitor: String,
    /// Line number (1-indexed)
    pub line: u32,
    /// Column number (1-indexed)
    pub col: u32,
    /// Raw evidence snippet from source
    pub evidence: String,
    /// Decoded payload if this violation involved decode-then-exec
    pub decoded: Option<String>,
    /// Human-readable explanation
    pub message: String,
    /// Actionable fix suggestion shown to the developer
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DefenderResult {
    pub severity: Severity,
    pub violations: Vec<DefenderViolation>,
    /// How many recursive decode layers were traversed (max 3)
    pub scan_depth: u8,
    pub path: PathBuf,
    pub language: Language,
}

impl DefenderResult {
    pub fn clean(path: PathBuf, language: Language) -> Self {
        Self {
            severity: Severity::Clean,
            violations: Vec::new(),
            scan_depth: 0,
            path,
            language,
        }
    }

    pub fn is_blocked(&self) -> bool {
        self.severity == Severity::Malicious
    }
}

// ─────────────────────────────────────────────
// PATH EXCLUSIONS
// ─────────────────────────────────────────────

/// Paths/substrings that are exempt from scanning.
/// Arquivos nestas pastas contêm payloads de documentação de teste (pentests).
/// Defender não deve escanear, alertar ou remover estes arquivos.
const EXCLUDED_PATH_SUBSTRINGS: &[&str] = &[
    "pentest-nemesis-control",
    "PENTEST-NEMESIS",
    "defender-exclude.txt",
];

/// Returns true if the path should be skipped by the defender.
pub fn is_path_excluded(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    for substr in EXCLUDED_PATH_SUBSTRINGS {
        if path_str.contains(substr) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────
// MAIN ENTRY POINT
// ─────────────────────────────────────────────

/// Scan file content for malicious intent.
///
/// Called from:
/// - pretool hook (write_to_file interception) — synchronous
/// - daemon watcher (filesystem events) — asynchronous
///
/// Returns DefenderResult with severity + all violations found.
pub fn scan_content(path: &Path, content: &[u8]) -> DefenderResult {
    // ── Isentar pastas de pentest/documentação (early return — não escanea) ──
    if is_path_excluded(path) {
        return DefenderResult {
            severity: Severity::Clean,
            violations: Vec::new(),
            scan_depth: 0,
            path: path.to_path_buf(),
            language: Language::Unknown,
        };
    }

    let language = detect_language(path);
    let mut all_violations: Vec<DefenderViolation> = Vec::new();

    // ── Layer 1: Byte-level scan (no parser — fastest, catches BiDi/PUA) ──
    let byte_violations = scanner::byte_scanner::scan_bidi(content);
    all_violations.extend(byte_violations);

    let pua_violations = scanner::byte_scanner::scan_pua(content);
    all_violations.extend(pua_violations);

    let homoglyph_violations = scanner::byte_scanner::scan_homoglyphs(content);
    all_violations.extend(homoglyph_violations);

    let zero_width_violations = scanner::byte_scanner::scan_zero_width(content);
    all_violations.extend(zero_width_violations);

    // ── Layer 2: Entropy scan (detects obfuscated strings) ──
    let entropy_violations = scanner::entropy::scan_high_entropy(content);
    all_violations.extend(entropy_violations);

    // ── Layer 3: Regex fast-path (pre-AST — credential patterns, known C2 signatures) ──
    let regex_violations = scanner::regex_layer::scan(content, &language);
    all_violations.extend(regex_violations);

    // ── Layer 4: Manifest scan (package.json postinstall, Cargo.toml build.rs abuse) ──
    let manifest_violations = scanner::manifest_scanner::scan(path, content);
    all_violations.extend(manifest_violations);

    // ── Layer 4.5: IDE config poisoning (all file types — markdown/config inspection) ──
    let ide_violations = visitors::ide_config_poisoning::scan_ide_config(path, content);
    all_violations.extend(ide_violations);

    // ── Layer 4.6: Exfil chain (source + sink coexistence → MALICIOUS) ──
    let exfil_chain_violations = visitors::exfil_chain::scan_content(path, content);
    all_violations.extend(exfil_chain_violations);

    // ── Layer 5: AST scan (tree-sitter — semantic analysis per language) ──
    // Only for supported languages; Unknown files get bytes+regex only
    match language {
        Language::JavaScript | Language::TypeScript | Language::Bash | Language::Python => {
            let ast_violations = scanner::ast_scanner::scan(path, content, &language);
            all_violations.extend(ast_violations);
        }
        _ => {}
    }

    // ── Layer 6: Recursive payload decoder ──
    // Extracts string literals, decodes base64/hex/charCode, rescans decoded content
    // Catches payloads hidden inside encoded strings (primary ClawHub vector)
    let (decoded_violations, scan_depth) = scanner::decoder::scan_recursive(content, 0);
    all_violations.extend(decoded_violations);

    // ── Determine final severity ──
    let severity = compute_severity(&all_violations);

    DefenderResult {
        severity,
        violations: all_violations,
        scan_depth,
        path: path.to_path_buf(),
        language,
    }
}

/// Scan a command string (not a file) for malicious intent.
///
/// Reuses the defender's existing scanners:
/// - regex_layer: malware/pentest patterns
/// - entropy: obfuscation detection
/// - decoder: base64/hex/charCode recursive decode
///
/// Does NOT use AST scanner or manifest scanner (not applicable to commands).
/// This is called from the pretool hook AFTER regex verification,
/// as a second line of defense.
pub fn scan_command(command: &str) -> DefenderResult {
    let content = command.as_bytes();
    let path = PathBuf::from("<command>");
    let mut all_violations: Vec<DefenderViolation> = Vec::new();

    // 1. Byte-level scanners (BiDi, PUA, homoglyphs, zero-width)
    //    Detecta instrucoes ocultas e Unicode steganography em comandos
    all_violations.extend(scanner::byte_scanner::scan_bidi(content));
    all_violations.extend(scanner::byte_scanner::scan_pua(content));
    all_violations.extend(scanner::byte_scanner::scan_homoglyphs(content));
    all_violations.extend(scanner::byte_scanner::scan_zero_width(content));

    // 2. Regex layer (reuse — works on any content)
    let regex_violations = scanner::regex_layer::scan(content, &Language::Unknown);
    all_violations.extend(regex_violations);

    // 3. Entropy scan (detect obfuscated strings in command)
    let entropy_violations = scanner::entropy::scan_high_entropy(content);
    all_violations.extend(entropy_violations);

    // 4. Recursive decoder (base64/hex/charCode — depth 3)
    let (decoded_violations, scan_depth) = scanner::decoder::scan_recursive(content, 0);
    all_violations.extend(decoded_violations);

    let severity = compute_severity(&all_violations);

    DefenderResult {
        severity,
        violations: all_violations,
        scan_depth,
        path,
        language: Language::Unknown,
    }
}

fn compute_severity(violations: &[DefenderViolation]) -> Severity {
    // Any single MALICIOUS-tagged visitor → Malicious
    let malicious_visitors = &[
        "decode_exec",
        "url_in_exec",
        "credential_harvest",
        "prompt_injection",
        "manifest_postinstall_exec",
        "manifest_build_exec",
        "self_clean",
        "unicode_bidi",
        "unicode_pua",
        "unicode_zero_width",
        "denylist_malicious",
        "persistence_patterns",
        "python_import_injection",
        "ide_config_poisoning",
        "taint_tracker",
        "exfil_chain",
        "manifest_registry_redirect",
    ];

    let suspicious_visitors = &[
        "dynamic_cmd",
        "time_gated",
        "unicode_homoglyph",
        "high_entropy",
        "denylist_suspicious",
        "manifest_supply_chain",
    ];

    for v in violations {
        if malicious_visitors.contains(&v.visitor.as_str()) {
            return Severity::Malicious;
        }
    }

    // 2+ suspicious signals → escalate to Malicious
    let suspicious_count = violations
        .iter()
        .filter(|v| suspicious_visitors.contains(&v.visitor.as_str()))
        .count();

    if suspicious_count >= 2 {
        return Severity::Malicious;
    }

    if suspicious_count >= 1 {
        return Severity::Suspicious;
    }

    Severity::Clean
}
