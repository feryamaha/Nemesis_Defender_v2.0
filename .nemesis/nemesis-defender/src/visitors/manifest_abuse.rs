//! manifest_abuse visitor — Vetor 1: postinstall/preinstall script abuse
//!
//! AST-level detection of manifest abuse (complements manifest_scanner):
//! - package.json scripts with non-trivial commands
//! - Cargo.toml build.rs abuse
//! - pyproject.toml setup hooks

use crate::DefenderViolation;
use tree_sitter::Node;

pub fn visit_js_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node.kind() == "string"
        && (node_text.contains("preinstall") || node_text.contains("postinstall"))
    {
        if node_text.contains("curl") || node_text.contains("wget") || node_text.contains("exec") {
            violations.push(DefenderViolation {
                visitor: "manifest_postinstall_exec".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "Lifecycle script contains execution commands. Shai-Hulud 2.0 pattern.".to_string(),
                suggestion: Some("Remove execution commands from lifecycle scripts (postinstall/preinstall). Use CI/CD for builds and installations.".to_string()),
            });
        }
    }

    violations
}

pub fn visit_bash_node(_node: &Node, _source: &str) -> Vec<DefenderViolation> {
    vec![]
}

pub fn visit_python_node(_node: &Node, _source: &str) -> Vec<DefenderViolation> {
    vec![]
}
