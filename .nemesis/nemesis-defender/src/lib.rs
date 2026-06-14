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
pub mod quarantine;
pub mod reporter;
pub mod scanner;
pub mod stats;
pub mod violations_log;
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

/// Paths/substrings que são isentos de scan. O defender não deve escanear,
/// alertar ou remover estes arquivos.
///
/// Marcadores de pasta de pentest/documentação de teste (payloads catalogados).
/// Casados como substring em qualquer ponto do path.
const EXCLUDED_DIR_MARKERS: &[&str] = &[
    "pentest-nemesis-control",
    "PENTEST-NEMESIS",
    "defender-exclude.txt",
    "denylist-defender.json",  // legado: hoje EMBUTIDO no binário; mantido por segurança
    // Pasta de denylists do pretool — regras EDITÁVEIS pelo usuário (ele pode/deve relaxar
    // os regex), logo NÃO são embutidas. Contêm padrões de detecção (\brm -rf\b, \bcurl\b…)
    // que o daemon não deve auto-escanear. Os arquivos reais são deny-list*.json (com hífen)
    // e denylist-folder-files.json; por isso isentamos a PASTA inteira (qualquer forma de
    // path: absoluto, relativo da raiz ou de .nemesis/ — todos contêm "denylist/").
    "denylist/",
    // Pasta dos artefatos de INSTALAÇÃO no repo-fonte (nemesis-install.sh + info-install.txt).
    // O instalador contém legitimamente comandos `curl` (download da release) e o leia-me os
    // documenta — disparariam data_transfer_exfiltration. Mesma classe de pentest-nemesis-control
    // (artefatos controlados, não conteúdo de usuário/agente). Na máquina do usuário esses
    // arquivos caem na raiz do cwd (não em .nemesis/install/), onde já são isentos por outras
    // regras (nemesis-install.sh por nome no daemon; info-install.txt em CANONICAL_ROOT_DOCS).
    ".nemesis/install/",
];

/// Documentação canônica do projeto, mantida exclusivamente por humanos.
/// Estes nomes só são isentados quando o arquivo está na RAIZ do projeto —
/// NUNCA em subpastas (ex.: `docs/CONTRIBUTING.md`, `src/docs/SECURITY.md`),
/// pois um atacante poderia esconder payloads reutilizando estes nomes.
const CANONICAL_ROOT_DOCS: &[&str] = &[
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "index.html",
    // Leia-me de instalação baixado junto com nemesis-install.sh: necessariamente contém os
    // comandos `curl` de download (mesma classe do README, que também os tem). É doc HUMANO, NÃO
    // é lido como instrução por agente (≠ AGENTS.md/CLAUDE.md, que por isso seguem escaneados).
    "info-install.txt",
];

/// Estado INTERNO do `.git/` (mensagens de commit, reflogs, refs, objects, index, HEAD…) contém
/// TEXTO ARBITRÁRIO legítimo — inclusive mensagens de commit/branch com termos que o scanner trata
/// como gatilho (ex.: a palavra "jailbreak" num nome de branch). Mover esses arquivos para a
/// quarentena CORROMPE o repositório (foi o que aconteceu: COMMIT_EDITMSG + reflogs movidos no
/// meio de um `git commit`). Por isso são isentos.
///
/// EXCEÇÃO DELIBERADA: `.git/hooks/` CONTINUA sendo escaneado — git hooks EXECUTAM código e são
/// um vetor real de supply-chain; não podem virar ponto cego.
fn is_git_internal_data(path: &Path) -> bool {
    let mut comps = path.components();
    while let Some(c) = comps.next() {
        if c.as_os_str() == ".git" {
            // Encontrou o diretório do repositório. O componente seguinte decide:
            return match comps.next() {
                // `.git/hooks/...` → NÃO isentar (mantém o scan dos hooks executáveis).
                Some(next) if next.as_os_str() == "hooks" => false,
                // Qualquer outro conteúdo de `.git/` (ou o próprio diretório) → isentar.
                _ => true,
            };
        }
    }
    false
}

/// Verifica se o diretório-pai de `path` é a raiz do projeto
/// (contém marcador `.git` ou `.nemesis`).
fn parent_is_project_root(path: &Path) -> bool {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        // Path relativo sem componente de diretório (ex.: "README.md") → raiz (cwd).
        _ => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };
    parent.join(".git").exists() || parent.join(".nemesis").exists()
}

/// Returns true if the path should be skipped by the defender.
pub fn is_path_excluded(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // 0. Estado interno do `.git/` (exceto `.git/hooks/`) — isento. Escanear/quarentenar
    //    commit msg, reflogs e refs corromperia o repositório (vide is_git_internal_data).
    if is_git_internal_data(path) {
        return true;
    }

    // 1. Pastas de pentest/documentação de teste — isentas em qualquer nível.
    for substr in EXCLUDED_DIR_MARKERS {
        if path_str.contains(substr) {
            return true;
        }
    }

    // 2. Documentação canônica — isenta APENAS na raiz do projeto.
    if let Some(basename) = path.file_name().and_then(|n| n.to_str()) {
        if CANONICAL_ROOT_DOCS.contains(&basename) && parent_is_project_root(path) {
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
///
/// ── ARQUITETURA DE DENYLISTS / CONSISTÊNCIA ENTRE CAMADAS (P1-2 / P1-5) ──
/// A SEGURANÇA DE CONTEÚDO tem FONTE ÚNICA: `config/denylist-defender.json`, aplicada
/// aqui (regex_layer) e portanto compartilhada por AMBOS o pretool (write-time) e o
/// daemon (filesystem). Logo, o veredito de SEGURANÇA é idêntico nas duas camadas para
/// bytes idênticos — verificado empiricamente (decode_exec, exfil, ssh-read, reverse
/// shell, bidi override: pretool == daemon).
///
/// As denylists em `.nemesis/denylist/*.json` servem VETORES DISTINTOS, NÃO são
/// duplicatas e NÃO entram aqui:
///   - camada "commands": interceptação de comando bash AO VIVO (Tool Bash) — só pretool;
///     o daemon observa arquivos, não comandos.
///   - regras de QUALIDADE (BFF, JSX, tipagem): portão de qualidade do pretool no
///     write-time. NUNCA devem chegar ao daemon: violação de qualidade ⇒ bloquear a
///     escrita (reversível), JAMAIS deletar arquivo (irreversível). Por isso o daemon é
///     SECURITY-ONLY e a única divergência legítima pretool/daemon é a camada de qualidade.
/// INVARIANTE: novos padrões de SEGURANÇA DE CONTEÚDO vão em denylist-defender.json (fonte
/// única). Não duplicar em .nemesis/denylist nem mover regra de qualidade para cá.
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

// ─────────────────────────────────────────────
// MODELO DE SEVERIDADE — CORROBORAÇÃO POR CONFIANÇA (P0-1)
// ─────────────────────────────────────────────
//
// Regra de negócio: o Iron Dome só deleta quando a hostilidade é CONFIRMADA.
// "Confirmada" = (a) um sinal determinístico/curado de alta confiança, OU
// (b) corroboração de 2+ métodos de detecção INDEPENDENTES concordando.
//
// Isso elimina a classe de falso-positivo que deletava arquivos legítimos: um único
// matcher heurístico de substring (ex.: prompt_injection casando "danger" via "DAN")
// nunca mais apaga um arquivo sozinho — vira no máximo Suspicious (logado, mantido).
// Ataques reais quase sempre disparam múltiplos sinais distintos ou um confirmatório.

/// Tier A — CONFIRMATÓRIO: 1 hit já confirma malícia. São sinais determinísticos,
/// multi-condição (corroboração embutida) ou de denylist curada pelo mantenedor.
const CONFIRMATORY_VISITORS: &[&str] = &[
    "denylist_malicious",          // denylist curada = comando hostil confirmado (1a camada)
    "decode_exec",                 // decoder achou comando real em payload decodificado / pattern AST específico de decode→exec
    "reverse_shell",               // socket de rede cru + execução de comando coexistindo (multi-linguagem: Ruby/PHP/Go/Perl/Java) — corroboração embutida
    "exfil_chain",                 // exige fonte de credencial + sink de rede coexistindo (corroboração embutida)
    "taint_tracker",               // exige fluxo de dado fonte→sink (corroboração embutida)
    "url_in_exec",                 // fetch+eval / require(http) / curl|bash — padrões multi-token específicos
    "credential_harvest",          // leitura de path sensível (.ssh/id_rsa, .npmrc) ou env-cred + sink (allowlist aplicada)
    "unicode_bidi",                // controle BiDi de reordenação (Trojan Source) — sem uso legítimo em código
    "manifest_postinstall_exec",   // script de ciclo de vida com execução — específico
    "manifest_build_exec",         // build script com execução — específico
    "manifest_registry_redirect",  // redirect de registry — supply chain confirmado
    "ide_config_poisoning",        // injeção em arquivo de config de IDE — alvo específico
    "nemesis_bypass",              // tentativa de neutralizar o próprio Nemesis — confirmatório por definição
];

/// Tier B — CORROBORANTE: matchers heurísticos (substring/padrão) sujeitos a FP.
/// 1 tipo distinto → Suspicious (loga, mantém). 2+ tipos DISTINTOS → Malicious (deleta).
/// Contar TIPOS distintos (não hits) impede que múltiplos matches da MESMA causa
/// (ex.: várias substrings "danger" num só arquivo) escalem indevidamente.
const CORROBORATING_VISITORS: &[&str] = &[
    "prompt_injection",
    "self_clean",
    "persistence_patterns",
    "python_import_injection",
    "unicode_pua",
    "unicode_zero_width",
    "unicode_homoglyph",
    "dynamic_cmd",
    "time_gated",
    "high_entropy",
    "denylist_suspicious",
    "manifest_supply_chain",
];

fn compute_severity(violations: &[DefenderViolation]) -> Severity {
    // (a) Qualquer sinal confirmatório → Malicious.
    if violations
        .iter()
        .any(|v| CONFIRMATORY_VISITORS.contains(&v.visitor.as_str()))
    {
        return Severity::Malicious;
    }

    // (b) Corroboração: contar TIPOS de visitor corroborante DISTINTOS.
    let mut distinct: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for v in violations {
        let name = v.visitor.as_str();
        if CORROBORATING_VISITORS.contains(&name) {
            distinct.insert(name);
        }
    }

    match distinct.len() {
        0 => Severity::Clean,
        1 => Severity::Suspicious,        // sinal heurístico isolado → mantém, só loga
        _ => Severity::Malicious,         // 2+ métodos independentes concordam → confirmado
    }
}

#[cfg(test)]
mod git_exclusion_tests {
    use super::*;

    #[test]
    fn git_internal_state_is_excluded() {
        // Os exatos arquivos que o daemon quarentenou (FP "jailbreak" no commit).
        for p in [
            "/home/u/proj/.git/COMMIT_EDITMSG",
            "/home/u/proj/.git/MERGE_MSG",
            "/home/u/proj/.git/HEAD",
            "/home/u/proj/.git/logs/HEAD",
            "/home/u/proj/.git/logs/refs/heads/main",
            "/home/u/proj/.git/refs/heads/main",
            "/home/u/proj/.git/index",
            "proj/./.git/COMMIT_EDITMSG", // com componente CurDir, como o daemon emite
        ] {
            assert!(is_path_excluded(Path::new(p)), "deveria isentar: {p}");
        }
    }

    #[test]
    fn git_hooks_are_still_scanned() {
        // .git/hooks/ EXECUTA código — não pode virar ponto cego.
        for p in [
            "/home/u/proj/.git/hooks/pre-commit",
            "/home/u/proj/.git/hooks/post-checkout",
        ] {
            assert!(!is_git_internal_data(Path::new(p)), "NÃO isentar hook: {p}");
        }
    }

    #[test]
    fn non_git_paths_unaffected() {
        // `.gitignore`/`.github/` não são o diretório `.git/` do repo.
        assert!(!is_git_internal_data(Path::new("/home/u/proj/.gitignore")));
        assert!(!is_git_internal_data(Path::new("/home/u/proj/.github/workflows/ci.yml")));
        assert!(!is_git_internal_data(Path::new("/home/u/proj/src/main.rs")));
    }
}
