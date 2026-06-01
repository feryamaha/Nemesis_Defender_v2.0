//! time_gated visitor — Vetor 5b: setTimeout/date-gated payloads
//!
//! Detects time-delayed execution:
//! - setTimeout/setInterval with eval/exec
//! - Date comparisons with malicious branch
//! - Version-gated execution

use crate::DefenderViolation;
use tree_sitter::Node;

const SUGGESTION_TIME_GATED: &str =
    "Remove async execution via setTimeout/setInterval for destructive code. Use explicit, auditable schedulers.";

pub fn visit_js_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node.kind() == "call_expression" {
        if node_text.contains("setTimeout") || node_text.contains("setInterval") {
            if node_text.contains("eval")
                || node_text.contains("exec")
                || node_text.contains("fetch")
            {
                violations.push(DefenderViolation {
                    visitor: "time_gated".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: node_text.to_string(),
                    decoded: None,
                    message: "setTimeout/setInterval with execution function. Time-delayed payload delivery.".to_string(),
                    suggestion: Some(SUGGESTION_TIME_GATED.to_string()),
                });
            }
        }
    }

    if node.kind() == "if_statement" && node_text.contains("Date") {
        if node_text.contains("exec") || node_text.contains("eval") {
            violations.push(DefenderViolation {
                visitor: "time_gated".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message:
                    "Date-gated execution with exec/eval. Payload activates after specific date."
                        .to_string(),
                suggestion: Some(SUGGESTION_TIME_GATED.to_string()),
            });
        }
    }

    violations
}

pub fn visit_bash_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node_text.contains("sleep") && (node_text.contains("exec") || node_text.contains("bash")) {
        violations.push(DefenderViolation {
            visitor: "time_gated".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Shell sleep followed by execution. Time-delayed payload.".to_string(),
            suggestion: Some(SUGGESTION_TIME_GATED.to_string()),
        });
    }

    violations
}

pub fn visit_python_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node_text.contains("time.sleep")
        && (node_text.contains("exec") || node_text.contains("eval"))
    {
        violations.push(DefenderViolation {
            visitor: "time_gated".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Python time.sleep followed by execution. Time-delayed payload.".to_string(),
            suggestion: Some(SUGGESTION_TIME_GATED.to_string()),
        });
    }

    if node.kind() == "if_statement" && node_text.contains("datetime") {
        if node_text.contains("exec") || node_text.contains("eval") {
            violations.push(DefenderViolation {
                visitor: "time_gated".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "Python datetime-gated execution. Date-activated payload.".to_string(),
                suggestion: Some(SUGGESTION_TIME_GATED.to_string()),
            });
        }
    }

    violations
}
