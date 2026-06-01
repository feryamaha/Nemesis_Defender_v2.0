//! decode_exec visitor — Vetor 2: decode → exec
//!
//! Detects patterns where decoded content is immediately executed:
//! - Base64 decode → eval/exec/Function
//! - Hex decode → exec
//! - charCode reconstruction → exec
//! - String manipulation (split/reverse) → exec

use crate::DefenderViolation;
use tree_sitter::Node;

const SUGGESTION_DECODE_EXEC: &str =
    "Remove dynamic decoding and execution. Use static data verified by checksum or signature.";

pub fn visit_js_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    if node.kind() == "call_expression" {
        let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

        if node_text.contains("eval") && node_text.contains("atob") {
            violations.push(DefenderViolation {
                visitor: "decode_exec".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "Base64 decode (atob) passed directly to eval. \
                         Classic obfuscation: hidden command decoded at runtime."
                    .to_string(),
                suggestion: Some(SUGGESTION_DECODE_EXEC.to_string()),
            });
        }

        if node_text.contains("eval")
            && node_text.contains("Buffer.from")
            && node_text.contains("base64")
        {
            violations.push(DefenderViolation {
                visitor: "decode_exec".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "Buffer.from with base64 encoding passed to eval. \
                         Node.js obfuscation pattern for hiding commands."
                    .to_string(),
                suggestion: Some(SUGGESTION_DECODE_EXEC.to_string()),
            });
        }

        if (node_text.contains("exec")
            || node_text.contains("execSync")
            || node_text.contains("spawnSync"))
            && node_text.contains("Buffer.from")
            && node_text.contains("base64")
        {
            violations.push(DefenderViolation {
                visitor: "decode_exec".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "Base64-decoded buffer passed to exec/spawn. \
                         Shell command hidden in Base64 payload."
                    .to_string(),
                suggestion: Some(SUGGESTION_DECODE_EXEC.to_string()),
            });
        }

        if node_text.contains("String.fromCharCode") {
            violations.push(DefenderViolation {
                visitor: "decode_exec".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "String.fromCharCode detected. Reconstructs strings from byte arrays at runtime. \
                         Used to hide commands that are assembled character-by-character.".to_string(),
                suggestion: Some("Use verified string literals. Never reconstruct code from char codes.".to_string()),
            });
        }
    }

    violations
}

pub fn visit_bash_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node_text.contains("base64") && (node_text.contains("|") || node_text.contains("eval")) {
        violations.push(DefenderViolation {
            visitor: "decode_exec".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Base64 decode piped to shell execution. \
                     Classic one-liner malware: base64 payload decoded and executed."
                .to_string(),
            suggestion: Some(SUGGESTION_DECODE_EXEC.to_string()),
        });
    }

    violations
}

pub fn visit_python_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node_text.contains("base64") && (node_text.contains("exec") || node_text.contains("eval")) {
        violations.push(DefenderViolation {
            visitor: "decode_exec".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Base64 decode passed to exec/eval. \
                     Python obfuscation pattern for hiding malicious code."
                .to_string(),
            suggestion: Some(SUGGESTION_DECODE_EXEC.to_string()),
        });
    }

    if node_text.contains("subprocess") && node_text.contains("base64") {
        violations.push(DefenderViolation {
            visitor: "decode_exec".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Base64 decode used with subprocess.run. \
                     Shell command hidden in Base64 payload executed via subprocess.".to_string(),
            suggestion: Some("Use subprocess.run(cmd_list, shell=False) with an argument list. Remove inline decoding.".to_string()),
        });
    }

    violations
}
