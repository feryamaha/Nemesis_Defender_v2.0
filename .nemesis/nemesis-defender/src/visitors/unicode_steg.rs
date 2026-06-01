//! unicode_steg visitor — Vetor 3: Unicode steganography in AST
//!
//! Complements byte_scanner by checking Unicode in AST string nodes:
//! - BiDi control characters in string literals
//! - PUA characters in identifiers
//! - Homoglyphs in function/variable names

use crate::DefenderViolation;
use tree_sitter::Node;

const SUGGESTION_UNICODE: &str =
    "Remove Unicode control characters (BiDi/PUA/homoglyphs). Use only ASCII in identifiers and critical strings.";

pub fn visit_js_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node.kind() == "string" || node.kind() == "template_string" {
        for ch in node_text.chars() {
            let cp = ch as u32;

            if (0x061C..=0x061C).contains(&cp)
                || (0x200E..=0x200F).contains(&cp)
                || (0x202A..=0x202E).contains(&cp)
                || (0x2066..=0x2069).contains(&cp)
                || (0x2028..=0x2029).contains(&cp)
                || (0xFE00..=0xFE0F).contains(&cp)
            {
                violations.push(DefenderViolation {
                    visitor: "unicode_bidi".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: format!("U+{:04X} in string literal", cp),
                    decoded: None,
                    message: "Unicode BiDi control character in AST string node. \
                             CVE-2021-42574 — Trojan Source attack."
                        .to_string(),
                    suggestion: Some(SUGGESTION_UNICODE.to_string()),
                });
            }

            if (0xE000..=0xF8FF).contains(&cp) {
                violations.push(DefenderViolation {
                    visitor: "unicode_pua".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: format!("U+{:04X} (PUA) in string literal", cp),
                    decoded: None,
                    message: "Unicode Private Use Area character in AST. \
                             os-info-checker-es6 attack pattern."
                        .to_string(),
                    suggestion: Some(SUGGESTION_UNICODE.to_string()),
                });
            }
        }
    }

    if node.kind() == "identifier" {
        for ch in node_text.chars() {
            let cp = ch as u32;
            if (0x0400..=0x04FF).contains(&cp) || (0x0370..=0x03FF).contains(&cp) {
                violations.push(DefenderViolation {
                    visitor: "unicode_homoglyph".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: format!("U+{:04X} in identifier", cp),
                    decoded: None,
                    message: "Homoglyph character in identifier. \
                             CVE-2021-42694 — can create duplicate function names."
                        .to_string(),
                    suggestion: Some(SUGGESTION_UNICODE.to_string()),
                });
            }
        }
    }

    violations
}

pub fn visit_bash_node(_node: &Node, _source: &str) -> Vec<DefenderViolation> {
    vec![]
}

pub fn visit_python_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node.kind() == "string" {
        for ch in node_text.chars() {
            let cp = ch as u32;

            if (0x061C..=0x061C).contains(&cp)
                || (0x200E..=0x200F).contains(&cp)
                || (0x202A..=0x202E).contains(&cp)
                || (0x2066..=0x2069).contains(&cp)
            {
                violations.push(DefenderViolation {
                    visitor: "unicode_bidi".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: format!("U+{:04X} in Python string", cp),
                    decoded: None,
                    message: "Unicode BiDi character in Python string. Trojan Source pattern."
                        .to_string(),
                    suggestion: Some(SUGGESTION_UNICODE.to_string()),
                });
            }
        }
    }

    violations
}
