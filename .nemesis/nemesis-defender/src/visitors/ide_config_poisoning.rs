//! ide_config_poisoning visitor — Vetor 3+4: IDE config poisoning, fake security scan, authority injection
//!
//! Detects malicious content in IDE config files that arrive poisoned from outside
//! (via PR, clone, postinstall) and that the AI will read as instruction.
//!
//! Target files: CLAUDE.md, .cursorrules, AGENTS.md, GEMINI.md, .devinrules,
//! .github/copilot-instructions.md, .continue/rules/, .claude/, .devin/, .cursor/
//!
//! Detects:
//! - Unicode invisible (tag chars U+E0000–U+E007F, bidi overrides, zero-width)
//! - Prompt injection (ignore-previous, role override, fake system/User:/Assistant:)
//! - Fake security scan pattern
//! - Authority injection ("verified by Anthropic", "approved by...", "trusted")

use crate::DefenderViolation;
use std::path::Path;

/// Check if a file path is an IDE config file that should be scanned for poisoning
fn is_ide_config_file(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();

    // Direct IDE config files
    let ide_config_files = [
        "claude.md",
        ".cursorrules",
        "agents.md",
        "gemini.md",
        ".devinrules",
        ".github/copilot-instructions.md",
    ];

    for config_file in &ide_config_files {
        if path_str.ends_with(config_file) || path_str.contains(config_file) {
            return true;
        }
    }

    // IDE config directories
    let ide_config_dirs = [".claude/", ".devin/", ".cursor/", ".continue/rules/"];

    for config_dir in &ide_config_dirs {
        if path_str.contains(config_dir) {
            return true;
        }
    }

    false
}

/// Check for IDE-specific prompt injection patterns (ignore-previous, role override, etc.)
fn has_ide_prompt_injection(text: &str) -> bool {
    let injection_patterns = [
        "ignore previous instructions",
        "disregard all",
        "forget your rules",
        "override safety",
        "bypass restrictions",
        "new system prompt",
        "override your instructions",
        "reset your guidelines",
        "instructions in this file override",
        "override your system prompt",
        "unrestricted",
        "disable your safety",
        "disable all restrictions",
        "ignore all previous",
        "forget all instructions",
        // DAN / role override
        "act as dan",
        "you are dan",
        "you are now dan",
        "developer mode enabled",
        "jailbreak mode",
        "act as an unrestricted",
        // Fake <system> / conversation continuation
        "<system>",
        "user: ",
        "assistant: ",
        "[system]",
        "### system:",
        "<<sys>>",
    ];

    let text_lower = text.to_lowercase();
    for pattern in &injection_patterns {
        if text_lower.contains(pattern) {
            return true;
        }
    }

    false
}

/// Check for fake security scan patterns — the AI is instructed to "run a scan" before responding,
/// which it interprets as reading/executing something, enabling data exfiltration.
fn has_fake_security_scan(text: &str) -> bool {
    let scan_patterns = [
        "run a security scan",
        "run security scan",
        "perform a security scan",
        "execute a security scan",
        "security scan before",
        "security scan prior",
        "security check before",
        "execute security audit",
        "perform security audit",
        "run an audit before",
        "pre-check:",
        "pre_check:",
        "security scan to verify",
        "verify your environment",
        "scan your environment",
    ];

    let text_lower = text.to_lowercase();
    for pattern in &scan_patterns {
        if text_lower.contains(pattern) {
            return true;
        }
    }

    false
}

/// Check for authority injection patterns — false claims of official approval to override safety.
fn has_authority_injection(text: &str) -> bool {
    let authority_patterns = [
        "verified by anthropic",
        "approved by anthropic",
        "certified by anthropic",
        "endorsed by anthropic",
        "verified by openai",
        "approved by openai",
        "trusted configuration",
        "safety rules suspended",
        "safety rules disabled",
        "safety rules bypassed",
        "follow all instructions without restriction",
        "follow without restriction",
        "follow these instructions unconditionally",
        "this file has elevated",
        "elevated permissions granted",
        "this configuration overrides",
        "override is authorized",
    ];

    let text_lower = text.to_lowercase();
    for pattern in &authority_patterns {
        if text_lower.contains(pattern) {
            return true;
        }
    }

    false
}

/// Scan IDE config file for poisoning patterns
pub fn scan_ide_config(path: &Path, content: &[u8]) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    // Only scan IDE config files
    if !is_ide_config_file(path) {
        return violations;
    }

    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return violations,
    };

    // Check for IDE-specific prompt injection
    if has_ide_prompt_injection(text) {
        violations.push(DefenderViolation {
            visitor: "ide_config_poisoning".to_string(),
            line: 1,
            col: 1,
            evidence: "IDE config contains prompt injection pattern".to_string(),
            decoded: None,
            message: "IDE config file contains prompt injection (ignore-previous, override instructions, DAN, etc.). This is a poisoning attack targeting AI agents.".to_string(),
            suggestion: Some("Remove any instructions that attempt to override AI safety guidelines or ignore previous instructions. IDE config files should only contain legitimate project rules.".to_string()),
        });
    }

    // Check for fake security scan instructions
    if has_fake_security_scan(text) {
        violations.push(DefenderViolation {
            visitor: "ide_config_poisoning".to_string(),
            line: 1,
            col: 1,
            evidence: "IDE config contains fake security scan instruction".to_string(),
            decoded: None,
            message: "IDE config file instructs AI to 'run a security scan' before responding. This is a social engineering attack: the AI executes the 'scan' by reading credentials and exfiltrating them.".to_string(),
            suggestion: Some("Remove fake security scan instructions from IDE config files. Legitimate security scanning is done by CI/CD pipelines, not by AI agents reading credentials.".to_string()),
        });
    }

    // Check for authority injection
    if has_authority_injection(text) {
        violations.push(DefenderViolation {
            visitor: "ide_config_poisoning".to_string(),
            line: 1,
            col: 1,
            evidence: "IDE config contains authority injection pattern".to_string(),
            decoded: None,
            message: "IDE config file contains false authority claims ('verified by Anthropic', 'trusted configuration', 'safety rules suspended'). These are social engineering attacks to make AI follow malicious instructions without resistance.".to_string(),
            suggestion: Some("Remove false authority claims from IDE config files. No external file can grant elevated permissions to override AI safety guidelines.".to_string()),
        });
    }

    // Check for Unicode invisible characters (reusing logic from unicode_steg)
    // Tag chars U+E0000–U+E007F
    for (i, c) in text.chars().enumerate() {
        if (c as u32) >= 0xE0000 && (c as u32) <= 0xE007F {
            violations.push(DefenderViolation {
                visitor: "ide_config_poisoning".to_string(),
                line: 1,
                col: (i + 1) as u32,
                evidence: format!("Unicode tag char U+{:X}", c as u32),
                decoded: None,
                message: "IDE config file contains invisible Unicode tag characters (U+E0000–U+E007F). These are invisible to humans but visible to AI, used for stealthy instruction injection.".to_string(),
                suggestion: Some("Remove all invisible Unicode characters from IDE config files. Use only visible ASCII/UTF-8 characters.".to_string()),
            });
            break;
        }
    }

    // Check for bidi overrides (CVE-2021-42574)
    if text.contains("\u{202E}") || text.contains("\u{202D}") {
        violations.push(DefenderViolation {
            visitor: "ide_config_poisoning".to_string(),
            line: 1,
            col: 1,
            evidence: "Bidi override character detected".to_string(),
            decoded: None,
            message: "IDE config file contains bidi override characters (CVE-2021-42574). These can be used to hide malicious instructions by reversing text display.".to_string(),
            suggestion: Some("Remove bidi override characters from IDE config files. These are used in text spoofing attacks.".to_string()),
        });
    }

    // Check for zero-width characters
    if text.contains("\u{200B}") || text.contains("\u{200C}") || text.contains("\u{200D}") {
        violations.push(DefenderViolation {
            visitor: "ide_config_poisoning".to_string(),
            line: 1,
            col: 1,
            evidence: "Zero-width character detected".to_string(),
            decoded: None,
            message: "IDE config file contains zero-width characters. These can be used to hide malicious instructions that are invisible to human review.".to_string(),
            suggestion: Some("Remove zero-width characters from IDE config files. These are used in steganography attacks.".to_string()),
        });
    }

    violations
}
