//! self_clean visitor — Vetor 8: self-cleaning malware
//!
//! Detects self-deletion and forensic evasion:
//! - fs.unlink(__filename)
//! - rm with __filename or $0
//! - Rewriting package.json

use crate::DefenderViolation;
use tree_sitter::Node;

const SUGGESTION_SELF_CLEAN: &str =
    "Remove self-deletion. Execution artifacts must be managed by CI/CD, not by the script itself.";

pub fn visit_js_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node.kind() == "call_expression" {
        if (node_text.contains("unlink") || node_text.contains("unlinkSync"))
            && node_text.contains("__filename")
        {
            violations.push(DefenderViolation {
                visitor: "self_clean".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "Self-deletion: fs.unlink(__filename). Malware deletes itself after execution to evade forensics.".to_string(),
                suggestion: Some(SUGGESTION_SELF_CLEAN.to_string()),
            });
        }
    }

    if node_text.contains("writeFile") && node_text.contains("package.json") {
        violations.push(DefenderViolation {
            visitor: "self_clean".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Dynamic write to package.json. Self-cleaning malware may overwrite manifest with clean version.".to_string(),
            suggestion: Some("Remove dynamic writes to package.json. Manifests must be versioned and immutable during execution.".to_string()),
        });
    }

    if node_text.contains("rm -rf") && (node_text.contains(" ~") || node_text.contains("$HOME")) {
        violations.push(DefenderViolation {
            visitor: "self_clean".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Home directory destruction: rm -rf ~. Dead man's switch pattern — malware destroys user home after execution.".to_string(),
            suggestion: Some(SUGGESTION_SELF_CLEAN.to_string()),
        });
    }

    if node_text.contains("rm -rf")
        && (node_text.contains(".bashrc") || node_text.contains(".zshrc"))
    {
        violations.push(DefenderViolation {
            visitor: "self_clean".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Shell config deletion: rm .bashrc/.zshrc. Malware destroys shell configuration to hide forensic evidence.".to_string(),
            suggestion: Some(SUGGESTION_SELF_CLEAN.to_string()),
        });
    }

    if node_text.contains("rm -rf")
        && (node_text.contains("Date")
            || node_text.contains("token")
            || node_text.contains("expir"))
    {
        violations.push(DefenderViolation {
            visitor: "self_clean".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Dead man's switch pattern: conditional rm -rf triggered by date/token expiration. Malware self-destructs with conditional logic.".to_string(),
            suggestion: Some(SUGGESTION_SELF_CLEAN.to_string()),
        });
    }

    violations
}

pub fn visit_bash_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node_text.contains("rm") && node_text.contains("$0") {
        violations.push(DefenderViolation {
            visitor: "self_clean".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Shell self-deletion: rm with $0. Script deletes itself after execution."
                .to_string(),
            suggestion: Some(SUGGESTION_SELF_CLEAN.to_string()),
        });
    }

    if node_text.contains("rm -rf") && (node_text.contains(" ~") || node_text.contains("$HOME")) {
        violations.push(DefenderViolation {
            visitor: "self_clean".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message:
                "Home directory destruction: rm -rf ~ in shell script. Dead man's switch pattern."
                    .to_string(),
            suggestion: Some(SUGGESTION_SELF_CLEAN.to_string()),
        });
    }

    if node_text.contains("rm -rf")
        && (node_text.contains(".bashrc") || node_text.contains(".zshrc"))
    {
        violations.push(DefenderViolation {
            visitor: "self_clean".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Shell config deletion: rm .bashrc/.zshrc in shell script.".to_string(),
            suggestion: Some(SUGGESTION_SELF_CLEAN.to_string()),
        });
    }

    violations
}

pub fn visit_python_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node.kind() == "call_expression" {
        if (node_text.contains("remove") || node_text.contains("unlink"))
            && node_text.contains("__file__")
        {
            violations.push(DefenderViolation {
                visitor: "self_clean".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "Python self-deletion: os.remove(__file__). Malware deletes itself."
                    .to_string(),
                suggestion: Some(SUGGESTION_SELF_CLEAN.to_string()),
            });
        }
    }

    violations
}
