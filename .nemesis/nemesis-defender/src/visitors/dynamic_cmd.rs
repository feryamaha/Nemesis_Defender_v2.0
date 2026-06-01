//! dynamic_cmd visitor — Vetor 6: dynamic command construction
//!
//! Detects patterns where commands are constructed at runtime:
//! - String concatenation to build deny-list commands
//! - Template literals with external input
//! - Array join patterns

use crate::DefenderViolation;
use tree_sitter::Node;

const SUSPICIOUS_COMMANDS: &[&str] = &[
    "curl", "wget", "fetch", "http", "https", "exec", "eval", "spawn", "fork", "rm", "unlink",
    "rmdir", "chmod", "chown", "bash", "sh", "zsh",
];

const SUGGESTION_DYNAMIC: &str =
    "Use static argument lists. Never construct commands by string concatenation or interpolation.";

/// Check if command appears in text with word boundaries (not as substring)
/// e.g., "rm" should match "rm -rf" but NOT "trim()" or "form()"
fn contains_command_word(text: &str, cmd: &str) -> bool {
    // Check for the command surrounded by non-alphanumeric characters or at string boundaries
    let re_pattern = format!(r"(^|[^\w]){}\b", regex::escape(cmd));
    regex::Regex::new(&re_pattern)
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}

pub fn visit_js_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node.kind() == "binary_expression" && node_text.contains("+") {
        let parts: Vec<&str> = node_text.split('+').collect();
        let reconstructed: String = parts
            .iter()
            .map(|p| p.trim().trim_matches('"').trim_matches('\''))
            .collect();

        for cmd in SUSPICIOUS_COMMANDS {
            if contains_command_word(&reconstructed, cmd) {
                violations.push(DefenderViolation {
                    visitor: "dynamic_cmd".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: node_text.to_string(),
                    decoded: None,
                    message: format!(
                        "String concatenation builds command containing '{}'. \
                         Dynamic command construction to evade static analysis.",
                        cmd
                    ),
                    suggestion: Some(SUGGESTION_DYNAMIC.to_string()),
                });
                break;
            }
        }
    }

    if node.kind() == "template_string" {
        if node_text.contains("http") && (node_text.contains("exec") || node_text.contains("eval"))
        {
            violations.push(DefenderViolation {
                visitor: "dynamic_cmd".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "Template literal contains HTTP URL and execution function. \
                         Command constructed from potentially external input."
                    .to_string(),
                suggestion: Some(SUGGESTION_DYNAMIC.to_string()),
            });
        }
    }

    if node.kind() == "call_expression" && node_text.contains(".join") {
        for cmd in SUSPICIOUS_COMMANDS {
            if contains_command_word(node_text, cmd) {
                violations.push(DefenderViolation {
                    visitor: "dynamic_cmd".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: node_text.to_string(),
                    decoded: None,
                    message: format!(
                        "Array.join pattern detected reconstructing command with '{}'. \
                         Obfuscation: command split across array elements.",
                        cmd
                    ),
                    suggestion: Some(SUGGESTION_DYNAMIC.to_string()),
                });
                break;
            }
        }
    }

    violations
}

pub fn visit_bash_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node_text.contains("$") && (node_text.contains("curl") || node_text.contains("wget")) {
        violations.push(DefenderViolation {
            visitor: "dynamic_cmd".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Shell variable used in command construction with network tool. \
                     Dynamic command built from external input."
                .to_string(),
            suggestion: Some(
                "Use static, verified URLs. Never interpolate variables into network commands."
                    .to_string(),
            ),
        });
    }

    violations
}

pub fn visit_python_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node.kind() == "string" && (node_text.contains("{") && node_text.contains("}")) {
        for cmd in SUSPICIOUS_COMMANDS {
            if node_text.contains(cmd) {
                violations.push(DefenderViolation {
                    visitor: "dynamic_cmd".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: node_text.to_string(),
                    decoded: None,
                    message: format!(
                        "String formatting (f-string/format) builds command with '{}'. \
                         Dynamic command from variable interpolation.",
                        cmd
                    ),
                    suggestion: Some(SUGGESTION_DYNAMIC.to_string()),
                });
                break;
            }
        }
    }

    if node_text.contains("subprocess") && node_text.contains("shell=True") {
        violations.push(DefenderViolation {
            visitor: "dynamic_cmd".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "subprocess with shell=True allows dynamic command injection. \
                     High risk when combined with external input."
                .to_string(),
            suggestion: Some(
                "Use subprocess.run(cmd_list, shell=False) with an argument list.".to_string(),
            ),
        });
    }

    violations
}
