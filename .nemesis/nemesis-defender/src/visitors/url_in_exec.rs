//! url_in_exec visitor — Vetor 5a: fetch remote + eval
//!
//! Detects patterns where remote content is fetched and executed:
//! - fetch/axios + eval
//! - require() of HTTP URL
//! - Dynamic import from URL

use crate::DefenderViolation;
use tree_sitter::Node;

const SUGGESTION_URL_EXEC: &str =
    "Never execute remote code. Use local packages verified by checksum or signature.";

pub fn visit_js_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node.kind() == "call_expression" {
        if (node_text.contains("fetch") || node_text.contains("axios"))
            && node_text.contains("eval")
        {
            violations.push(DefenderViolation {
                visitor: "url_in_exec".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "Remote fetch (fetch/axios) followed by eval. \
                         Download-and-execute pattern: code fetched from remote URL executed directly.".to_string(),
                suggestion: Some(SUGGESTION_URL_EXEC.to_string()),
            });
        }

        if node_text.contains("require")
            && (node_text.contains("http://") || node_text.contains("https://"))
        {
            violations.push(DefenderViolation {
                visitor: "url_in_exec".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "require() called with HTTP URL. \
                         Remote code execution: module loaded from untrusted URL."
                    .to_string(),
                suggestion: Some(SUGGESTION_URL_EXEC.to_string()),
            });
        }

        if node_text.contains("import(")
            && (node_text.contains("http://") || node_text.contains("https://"))
        {
            violations.push(DefenderViolation {
                visitor: "url_in_exec".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "Dynamic import() with HTTP URL. \
                         Remote code execution: module dynamically loaded from untrusted URL."
                    .to_string(),
                suggestion: Some(SUGGESTION_URL_EXEC.to_string()),
            });
        }
    }

    violations
}

pub fn visit_bash_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if (node_text.contains("curl") || node_text.contains("wget")) && node_text.contains("|") {
        if node_text.contains("bash") || node_text.contains("sh") || node_text.contains("eval") {
            violations.push(DefenderViolation {
                visitor: "url_in_exec".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "curl/wget piped to shell execution. \
                         Classic download-and-execute malware pattern."
                    .to_string(),
                suggestion: Some(SUGGESTION_URL_EXEC.to_string()),
            });
        }
    }

    violations
}

pub fn visit_python_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if (node_text.contains("urllib") || node_text.contains("requests"))
        && (node_text.contains("exec") || node_text.contains("eval"))
    {
        violations.push(DefenderViolation {
            visitor: "url_in_exec".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "HTTP request followed by exec/eval. \
                     Python download-and-execute pattern."
                .to_string(),
            suggestion: Some(SUGGESTION_URL_EXEC.to_string()),
        });
    }

    if node_text.contains("exec")
        && (node_text.contains("http://") || node_text.contains("https://"))
    {
        violations.push(DefenderViolation {
            visitor: "url_in_exec".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "exec() called with HTTP URL argument. \
                     Remote code execution via URL parameter."
                .to_string(),
            suggestion: Some(SUGGESTION_URL_EXEC.to_string()),
        });
    }

    violations
}
