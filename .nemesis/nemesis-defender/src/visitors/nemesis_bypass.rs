//! nemesis_bypass visitor — Vetor 10: Nemesis evasion / self-protection bypass
//!
//! Detects scripts that attempt to disable or bypass the Nemesis enforcement:
//! - Path obfuscation via variable concatenation targeting protected configs
//! - Direct write to .claude/settings.json, .windsurf/hooks.json, .codex/hooks.json
//! - Hex/base64 encoded paths pointing to Nemesis infrastructure
//! - Python os.symlink / os.system targeting Nemesis configs
//! - Node.js fs operations targeting Nemesis binaries or configs

// Alteração teste versionamento!

use crate::DefenderViolation;
use tree_sitter::Node;

const SUGGESTION_NEMESIS_BYPASS: &str =
    "Script tenta desativar ou contornar o Nemesis. Remova imediatamente. \
     Configurações do Nemesis são gerenciadas exclusivamente pelo usuário.";

// ── Paths protegidos do Nemesis ──
const NEMESIS_PROTECTED_TARGETS: &[&str] = &[
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".windsurf/hooks.json",
    ".windsurf/rules/",
    ".codex/hooks.json",
    ".codex/config.toml",
    ".openclaude/settings.json",
    ".github/hooks/nemesis-pretool-hook.json",
    ".nemesis/target/release/nemesis-pretool",
    ".nemesis/workflow-enforcement/config/denylist",
    ".nemesis/workflow-enforcement/config/deny-list",
    ".nemesis/nemesis-defender/config/denylist-defender.json",
    "nemesis-pretool-check-unix",
    "nemesis-posttool-check-unix",
];

// ── Fragmentos de comandos que indicam tentativa de bypass ──
const BYPASS_INDICATORS: &[&str] = &[
    "\"hooks\":{}",
    "\"hooks\": {}",
    "'hooks':{}",
    "{\"hooks\":{}}",
    "{'hooks':{}}",
    "desativar",
    "disable",
    "bypass",
];

// ═══════════════════════════════════════════════════════════════
// BASH VISITOR
// ═══════════════════════════════════════════════════════════════

pub fn visit_bash_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();
    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    // ── 1. Atribuição de variável contendo fragmento de path Nemesis ──
    if node.kind() == "variable_assignment" || node.kind() == "assignment" {
        for target in NEMESIS_PROTECTED_TARGETS {
            if node_text.contains(target) || node_text.contains(&target.replace('/', "\\/")) {
                violations.push(DefenderViolation {
                    visitor: "nemesis_bypass".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: node_text.to_string(),
                    decoded: None,
                    message: format!(
                        "Variável contém path protegido do Nemesis: '{}'. \
                         Possível tentativa de ofuscar acesso a infraestrutura do Nemesis.",
                        target
                    ),
                    suggestion: Some(SUGGESTION_NEMESIS_BYPASS.to_string()),
                });
                return violations;
            }
        }
    }

    // ── 2. Concatenação de variáveis com redirect/tee para escrita ──
    let has_var_concat = (node_text.contains("${") && node_text.matches("${").count() >= 2)
        || (node_text.contains('$') && node_text.matches('$').count() >= 3);
    let has_redirect = node_text.contains('>')
        || node_text.contains(">>")
        || node_text.contains("tee ")
        || node_text.contains("|tee");
    let has_write_cmd = node_text.contains("echo ")
        || node_text.contains("printf ")
        || node_text.contains("cat ")
        || node_text.contains("print ");

    if has_var_concat && has_redirect && has_write_cmd {
        // Verifica se contém payload de desativação
        for indicator in BYPASS_INDICATORS {
            if node_text.contains(indicator) {
                violations.push(DefenderViolation {
                    visitor: "nemesis_bypass".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: node_text.to_string(),
                    decoded: None,
                    message: format!(
                        "Concatenação de variáveis com redirect/tee e payload de desativação ('{}'). \
                         Tentativa de bypass do Nemesis via path ofuscado.",
                        indicator
                    ),
                    suggestion: Some(SUGGESTION_NEMESIS_BYPASS.to_string()),
                });
                return violations;
            }
        }
    }

    // ── 3. Path ofuscado (hex/base64) com destino a arquivo ──
    let has_hex = node_text.contains("\\x") || node_text.contains("\\u");
    let has_b64 =
        node_text.contains("base64") && (node_text.contains("-d") || node_text.contains("decode"));
    let has_output_target =
        node_text.contains('>') || node_text.contains("tee") || node_text.contains("dd of=");

    if (has_hex || has_b64) && has_output_target {
        // Verificar se o output target ou o conteúdo decodificado referencia paths Nemesis
        for target in NEMESIS_PROTECTED_TARGETS {
            let target_short = target.split('/').last().unwrap_or(target);
            if node_text.contains(target_short) {
                violations.push(DefenderViolation {
                    visitor: "nemesis_bypass".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: node_text.to_string(),
                    decoded: None,
                    message: format!(
                        "Path ofuscado (hex/base64) detectado com destino a '{}'. \
                         Payload codificado para evadir detecção de paths do Nemesis.",
                        target_short
                    ),
                    suggestion: Some(SUGGESTION_NEMESIS_BYPASS.to_string()),
                });
                return violations;
            }
        }
    }

    // ── 4. Tentativa de remover binário do Nemesis ──
    if (node_text.contains("rm ") || node_text.contains("unlink ") || node_text.contains("shred "))
        && (node_text.contains("nemesis-pretool") || node_text.contains("nemesis-posttool"))
    {
        violations.push(DefenderViolation {
            visitor: "nemesis_bypass".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Tentativa de remover binário do Nemesis. Ataque direto à infraestrutura de enforcement.".to_string(),
            suggestion: Some(SUGGESTION_NEMESIS_BYPASS.to_string()),
        });
    }

    violations
}

// ═══════════════════════════════════════════════════════════════
// PYTHON VISITOR
// ═══════════════════════════════════════════════════════════════

pub fn visit_python_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();
    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    // ── 1. open(..., 'w') com path construído apontando para config Nemesis ──
    if (node_text.contains("open(")
        || node_text.contains("write_text")
        || node_text.contains("Path("))
        && (node_text.contains("'w'") || node_text.contains("\"w\"") || node_text.contains("write"))
    {
        for target in NEMESIS_PROTECTED_TARGETS {
            let target_short = target.split('/').last().unwrap_or(target);
            if node_text.contains(target) || node_text.contains(target_short) {
                // Verifica se é concatenação de path ou variável
                let has_concat = node_text.contains('+')
                    || node_text.contains("f\"")
                    || node_text.contains("f'")
                    || node_text.contains(".join")
                    || node_text.contains("os.path")
                    || node_text.contains("Path(");

                if has_concat {
                    violations.push(DefenderViolation {
                        visitor: "nemesis_bypass".to_string(),
                        line: (node.start_position().row + 1) as u32,
                        col: (node.start_position().column + 1) as u32,
                        evidence: node_text.to_string(),
                        decoded: None,
                        message: format!(
                            "Python: escrita em path do Nemesis '{}' com concatenação de variáveis. \
                             Tentativa de bypass via Python file operations.",
                            target
                        ),
                        suggestion: Some(SUGGESTION_NEMESIS_BYPASS.to_string()),
                    });
                    return violations;
                }
            }
        }
    }

    // ── 2. os.symlink / shutil.copy2 apontando para config Nemesis via /src/ ──
    if (node_text.contains("os.symlink") || node_text.contains("os.symlink"))
        || (node_text.contains("shutil.copy") || node_text.contains("shutil.move"))
    {
        for target in NEMESIS_PROTECTED_TARGETS {
            if node_text.contains(target) {
                violations.push(DefenderViolation {
                    visitor: "nemesis_bypass".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: node_text.to_string(),
                    decoded: None,
                    message: format!(
                        "Python symlink/copy de '{}' — redirecionamento de acesso a infraestrutura Nemesis.",
                        target
                    ),
                    suggestion: Some(SUGGESTION_NEMESIS_BYPASS.to_string()),
                });
                return violations;
            }
        }
    }

    // ── 3. subprocess / os.system com comando de bypass ──
    if (node_text.contains("subprocess")
        || node_text.contains("os.system")
        || node_text.contains("os.popen"))
        && node_text.contains("settings.json")
        || node_text.contains("hooks.json")
    {
        violations.push(DefenderViolation {
            visitor: "nemesis_bypass".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Python subprocess/system executando operação em config Nemesis.".to_string(),
            suggestion: Some(SUGGESTION_NEMESIS_BYPASS.to_string()),
        });
    }

    violations
}

// ═══════════════════════════════════════════════════════════════
// JAVASCRIPT / TYPESCRIPT VISITOR
// ═══════════════════════════════════════════════════════════════

pub fn visit_js_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();
    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    // ── 1. fs.writeFileSync / fs.writeFile com path construído contendo config Nemesis ──
    if (node_text.contains("writeFileSync")
        || node_text.contains("writeFile")
        || node_text.contains("rmSync")
        || node_text.contains("unlinkSync")
        || node_text.contains("appendFileSync")
        || node_text.contains("appendFile"))
    {
        for target in NEMESIS_PROTECTED_TARGETS {
            let target_short = target.split('/').last().unwrap_or(target);
            if node_text.contains(target) || node_text.contains(target_short) {
                let has_concat = node_text.contains('+')
                    || node_text.contains("${")
                    || node_text.contains("path.join")
                    || node_text.contains("path.resolve");

                if has_concat
                    || node_text.contains("process.env")
                    || node_text.contains("__dirname")
                {
                    violations.push(DefenderViolation {
                        visitor: "nemesis_bypass".to_string(),
                        line: (node.start_position().row + 1) as u32,
                        col: (node.start_position().column + 1) as u32,
                        evidence: node_text.to_string(),
                        decoded: None,
                        message: format!(
                            "JavaScript/TypeScript: operação fs em '{}' com path dinâmico. \
                             Tentativa de bypass do Nemesis via Node.js file operations.",
                            target
                        ),
                        suggestion: Some(SUGGESTION_NEMESIS_BYPASS.to_string()),
                    });
                    return violations;
                }
            }
        }
    }

    // ── 2. Template literal com path Nemesis ofuscado ──
    if node.kind() == "template_string" || node.kind() == "template_literal" {
        if node_text.contains("${") {
            for target in NEMESIS_PROTECTED_TARGETS {
                let target_short = target.split('/').last().unwrap_or(target);
                if node_text.contains(target_short) {
                    violations.push(DefenderViolation {
                        visitor: "nemesis_bypass".to_string(),
                        line: (node.start_position().row + 1) as u32,
                        col: (node.start_position().column + 1) as u32,
                        evidence: node_text.to_string(),
                        decoded: None,
                        message: format!(
                            "Template literal com path Nemesis '{}' interpolado. \
                             Ofuscação de acesso a infraestrutura protegida.",
                            target_short
                        ),
                        suggestion: Some(SUGGESTION_NEMESIS_BYPASS.to_string()),
                    });
                    return violations;
                }
            }
        }
    }

    violations
}
