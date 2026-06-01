//! prompt_injection visitor — Vetor 4: indirect prompt injection
//!
//! Detects AI instruction injection in strings/comments:
//! - "ignore previous instructions"
//! - AI format tokens (<|im_start|>, [INST], <<SYS>>)
//! - Imperative instructions to override safety rules
//! - Encoding obfuscation (leetspeak, hex escapes)
//! - Context manipulation (fake system messages, Anthropic impersonation)

use crate::DefenderViolation;
use tree_sitter::Node;

const INJECTION_PATTERNS: &[&str] = &[
    // ── BASE (17) ──
    "ignore previous instructions",
    "disregard all",
    "disregard previous",
    "forget your rules",
    "forget your instructions",
    "override safety",
    "bypass restrictions",
    "<|im_start|>",
    "<|im_end|>",
    "<|system|>",
    "[INST]",
    "[/INST]",
    "<<SYS>>",
    "<</SYS>>",
    "### System:",
    "### User:",
    "### Assistant:",
    // ── INSTRUCTION OVERRIDE (13) ──
    "ignore all previous",
    "ignore your training",
    "forget all instructions",
    "forget all previous",
    "forget your training",
    "new system prompt",
    "override your instructions",
    "override instructions",
    "override all",
    "reset your guidelines",
    "disregard the above",
    "=== END SYSTEM PROMPT ===",
    "--- END OF INSTRUCTIONS ---",
    // ── ROLE-PLAYING / JAILBREAK (18) ──
    "DAN",
    "Do Anything Now",
    "evil twin",
    "evil mode",
    "pretend you are",
    "act as if you are",
    "you are now",
    "you are now unrestricted",
    "bypass your restrictions",
    "bypass safety",
    "developer mode",
    "you are free",
    "no restrictions",
    "unfiltered mode",
    "jailbreak",
    "override your safety",
    "ignore your safety",
    "disable your safety",
    // ── ENCODING OBFUSCATION (8) ──
    "1gn0r3",
    "pr3v10us",
    "1nstruct10ns",
    "0v3rr1d3",
    "r3str1ct10ns",
    "d1s4bl3",
    "byp4ss",
    "j41lbr34k",
    // ── CONTEXT MANIPULATION (10) ──
    "{\"role\": \"system\"}",
    "role\": \"system\"",
    "Previous conversation was",
    "In our last session",
    "Anthropic admin here",
    "System message from Anthropic",
    "this is a system message",
    "Fake Anthropic",
    "[SYSTEM]",
    "=== END SYSTEM PROMPT ===",
    // ── INSTRUCTION SMUGGLING (8) ──
    "<!--",
    "--->",
    "<![CDATA[",
    "]]>",
    "ignore everything above",
    "ignore above",
    "focus only on what follows",
    "your response must begin with",
];

const SUGGESTION_INJECTION: &str =
    "Remove override instructions. Content with AI control directives must be sanitized before being embedded in prompts or config files.";

fn contains_decoded_hex(node_text: &str, pattern: &str) -> bool {
    if !node_text.contains("\\x") {
        return false;
    }
    let mut decoded = String::new();
    let bytes = node_text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 3 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'x' {
            if let (Some(a), Some(b)) = (hex_val(bytes[i + 2]), hex_val(bytes[i + 3])) {
                decoded.push((a << 4 | b) as char);
                i += 4;
                continue;
            }
        }
        decoded.push(bytes[i] as char);
        i += 1;
    }
    decoded.to_lowercase().contains(pattern)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn check_hex_encoded_injection(node_text: &str) -> bool {
    let hex_targets = &[
        "ignore",
        "override",
        "bypass",
        "system",
        "instructions",
        "previous",
        "forget",
        "disregard",
        "DAN",
        "jailbreak",
    ];
    for target in hex_targets {
        if contains_decoded_hex(node_text, target) {
            return true;
        }
    }
    false
}

pub fn visit_js_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node
        .utf8_text(source.as_bytes())
        .unwrap_or("")
        .to_lowercase();

    if node.kind() == "string" || node.kind() == "comment" {
        for pattern in INJECTION_PATTERNS {
            if node_text.contains(&pattern.to_lowercase()) {
                violations.push(DefenderViolation {
                    visitor: "prompt_injection".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: pattern.to_string(),
                    decoded: None,
                    message: "Indirect prompt injection detected. Instruction to override AI agent safety rules.".to_string(),
                    suggestion: Some(SUGGESTION_INJECTION.to_string()),
                });
                break;
            }
        }

        if violations.is_empty() && check_hex_encoded_injection(&node_text) {
            violations.push(DefenderViolation {
                visitor: "prompt_injection".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: "hex_encoded_injection".to_string(),
                decoded: None,
                message: "Hex-encoded indirect prompt injection detected. Attacks use hex escapes to bypass text-based filters.".to_string(),
                suggestion: Some(SUGGESTION_INJECTION.to_string()),
            });
        }
    }

    violations
}

pub fn visit_bash_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node
        .utf8_text(source.as_bytes())
        .unwrap_or("")
        .to_lowercase();

    if node.kind() == "comment" {
        for pattern in INJECTION_PATTERNS {
            if node_text.contains(&pattern.to_lowercase()) {
                violations.push(DefenderViolation {
                    visitor: "prompt_injection".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: pattern.to_string(),
                    decoded: None,
                    message: "Prompt injection in shell comment. Hidden AI instruction."
                        .to_string(),
                    suggestion: Some(SUGGESTION_INJECTION.to_string()),
                });
                break;
            }
        }
    }

    violations
}

pub fn visit_python_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node
        .utf8_text(source.as_bytes())
        .unwrap_or("")
        .to_lowercase();

    if node.kind() == "string" || node.kind() == "comment" {
        for pattern in INJECTION_PATTERNS {
            if node_text.contains(&pattern.to_lowercase()) {
                violations.push(DefenderViolation {
                    visitor: "prompt_injection".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: pattern.to_string(),
                    decoded: None,
                    message:
                        "Prompt injection in Python string/comment. AI instruction hidden in code."
                            .to_string(),
                    suggestion: Some(SUGGESTION_INJECTION.to_string()),
                });
                break;
            }
        }
    }

    violations
}
