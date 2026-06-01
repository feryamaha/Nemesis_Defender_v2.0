//! Byte-level scanner — no parser required.
//!
//! Detects:
//! - Unicode BiDi control characters (CVE-2021-42574 / Trojan Source / Glassworm)
//! - Unicode Private Use Area chars (os-info-checker-es6 attack, 2025)
//! - Homoglyph characters (CVE-2021-42694)
//!
//! Operates directly on &[u8] — fastest layer, runs on ALL files regardless of language.

use crate::DefenderViolation;

// ─────────────────────────────────────────────
// BiDi SCANNER
// ─────────────────────────────────────────────

/// Unicode BiDi control characters that can hide malicious code
/// References: CVE-2021-42574, Glassworm (Oct 2025), Aikido Research (Mar 2025)
const BIDI_CODEPOINTS: &[(u32, &str)] = &[
    (0x061C, "Arabic Letter Mark"),
    (0x200E, "Left-to-Right Mark"),
    (0x200F, "Right-to-Left Mark"),
    (0x202A, "Left-to-Right Embedding"),
    (0x202B, "Right-to-Left Embedding"),
    (0x202C, "Pop Directional Formatting"),
    (0x202D, "Left-to-Right Override"),
    (0x202E, "Right-to-Left Override"),
    (0x2066, "Left-to-Right Isolate"),
    (0x2067, "Right-to-Left Isolate"),
    (0x2068, "First Strong Isolate"),
    (0x2069, "Pop Directional Isolate"),
    (0x2028, "Line Separator"),
    (0x2029, "Paragraph Separator"),
    // Variation selectors (used in Glassworm — produce zero visual output)
    (0xFE00, "Variation Selector-1"),
    (0xFE01, "Variation Selector-2"),
    (0xFE0E, "Variation Selector-15"),
    (0xFE0F, "Variation Selector-16"),
];

pub fn scan_bidi(content: &[u8]) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return violations, // Binary file — skip
    };

    let (mut line, mut col) = (1u32, 1u32);

    for ch in text.chars() {
        let cp = ch as u32;

        if let Some(&(_, name)) = BIDI_CODEPOINTS.iter().find(|&&(c, _)| c == cp) {
            violations.push(DefenderViolation {
                visitor: "unicode_bidi".to_string(),
                line,
                col,
                evidence: format!("U+{:04X} ({})", cp, name),
                decoded: None,
                message: format!(
                    "Unicode BiDi control character U+{:04X} ({}) detected. \
                     CVE-2021-42574 (Trojan Source) / Glassworm 2025 — \
                     makes malicious code appear as comment to human reviewer. \
                     Compiler executes hidden logic invisible on screen.",
                    cp, name
                ),
                suggestion: Some(
                    "Remove the BiDi character. Use only ASCII in source code files.".to_string(),
                ),
            });
        }

        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }

    violations
}

// ─────────────────────────────────────────────
// PUA SCANNER
// ─────────────────────────────────────────────

pub fn scan_pua(content: &[u8]) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return violations,
    };

    let (mut line, mut col) = (1u32, 1u32);

    for ch in text.chars() {
        let cp = ch as u32;

        // Unicode Private Use Area: U+E000–U+F8FF (BMP PUA)
        // Used in os-info-checker-es6 attack (npm, May 2025) to hide preinstall payload
        if (0xE000..=0xF8FF).contains(&cp) {
            violations.push(DefenderViolation {
                visitor: "unicode_pua".to_string(),
                line,
                col,
                evidence: format!("U+{:04X} (Unicode Private Use Area)", cp),
                decoded: None,
                message: format!(
                    "Unicode Private Use Area character U+{:04X} in source code. \
                     Technique used in os-info-checker-es6 attack (npm, May 2025) \
                     to encode hidden preinstall payload invisible to reviewers.",
                    cp
                ),
                suggestion: Some("Remove the PUA character. Private Use Area characters have no place in source code.".to_string()),
            });
        }

        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }

    violations
}

// ─────────────────────────────────────────────
// HOMOGLYPH SCANNER
// ─────────────────────────────────────────────

/// Cyrillic and Greek characters visually identical to ASCII
/// CVE-2021-42694 — can create fake function names that look identical
const HOMOGLYPHS: &[(char, char, &str)] = &[
    // Cyrillic lowercase
    ('\u{0430}', 'a', "Cyrillic а"),
    ('\u{0435}', 'e', "Cyrillic е"),
    ('\u{043E}', 'o', "Cyrillic о"),
    ('\u{0440}', 'p', "Cyrillic р"),
    ('\u{0441}', 'c', "Cyrillic с"),
    ('\u{0445}', 'x', "Cyrillic х"),
    ('\u{0456}', 'i', "Cyrillic і"),
    // Cyrillic uppercase
    ('\u{0410}', 'A', "Cyrillic А"),
    ('\u{0412}', 'B', "Cyrillic В"),
    ('\u{0421}', 'C', "Cyrillic С"),
    ('\u{0415}', 'E', "Cyrillic Е"),
    ('\u{041D}', 'H', "Cyrillic Н"),
    ('\u{04B0}', 'Y', "Cyrillic Ү"),
    ('\u{041A}', 'K', "Cyrillic К"),
    ('\u{041C}', 'M', "Cyrillic М"),
    ('\u{041E}', 'O', "Cyrillic О"),
    ('\u{0420}', 'P', "Cyrillic Р"),
    ('\u{0422}', 'T', "Cyrillic Т"),
    ('\u{0425}', 'X', "Cyrillic Х"),
    // Greek lowercase
    ('\u{03B1}', 'a', "Greek α"),
    ('\u{03BF}', 'o', "Greek ο"),
    ('\u{03C1}', 'p', "Greek ρ"),
    ('\u{03B9}', 'i', "Greek ι"),
    // Greek uppercase
    ('\u{0391}', 'A', "Greek Α"),
    ('\u{0392}', 'B', "Greek Β"),
    ('\u{0395}', 'E', "Greek Ε"),
    ('\u{0396}', 'Z', "Greek Ζ"),
    ('\u{0397}', 'H', "Greek Η"),
    ('\u{0399}', 'I', "Greek Ι"),
    ('\u{039A}', 'K', "Greek Κ"),
    ('\u{039C}', 'M', "Greek Μ"),
    ('\u{039D}', 'N', "Greek Ν"),
    ('\u{039F}', 'O', "Greek Ο"),
    ('\u{03A1}', 'P', "Greek Ρ"),
    ('\u{03A4}', 'T', "Greek Τ"),
    ('\u{03A7}', 'X', "Greek Χ"),
    ('\u{03A5}', 'Y', "Greek Υ"),
];

pub fn scan_homoglyphs(content: &[u8]) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return violations,
    };

    let (mut line, mut col) = (1u32, 1u32);

    for ch in text.chars() {
        if let Some(&(_, ascii, name)) = HOMOGLYPHS.iter().find(|&&(hg, _, _)| hg == ch) {
            violations.push(DefenderViolation {
                visitor: "unicode_homoglyph".to_string(),
                line,
                col,
                evidence: format!("{} (U+{:04X}) looks like ASCII '{}'", ch, ch as u32, ascii),
                decoded: None,
                message: format!(
                    "Homoglyph {} ({}) visually identical to ASCII '{}'. \
                     CVE-2021-42694 — can define duplicate function names \
                     that execute different logic.",
                    ch, name, ascii
                ),
                suggestion: Some("Replace the homoglyph with the equivalent ASCII character. Use homoglyph linters in CI.".to_string()),
            });
        }

        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }

    violations
}

// ─────────────────────────────────────────────
// ZERO-WIDTH CHARACTER SCANNER
// ─────────────────────────────────────────────

/// Zero-width characters used for steganography in prompt injection
/// Can hide instructions invisible to human review
pub fn scan_zero_width(content: &[u8]) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return violations,
    };

    let (mut line, mut col) = (1u32, 1u32);

    for ch in text.chars() {
        let cp = ch as u32;
        match cp {
            // Zero-width space
            0x200B => violations.push(DefenderViolation {
                visitor: "unicode_zero_width".to_string(),
                line,
                col,
                evidence: "U+200B (Zero Width Space)".to_string(),
                decoded: None,
                message: "Zero-width space U+200B detected. Used in prompt injection to hide \
                     instructions in plain text by making them invisible to human reviewers."
                    .to_string(),
                suggestion: Some(
                    "Remove the zero-width character. Use only ASCII in source code files."
                        .to_string(),
                ),
            }),
            0x200C => violations.push(DefenderViolation {
                visitor: "unicode_zero_width".to_string(),
                line,
                col,
                evidence: "U+200C (Zero Width Non-Joiner)".to_string(),
                decoded: None,
                message: "Zero-width non-joiner U+200C detected. Can be used to bypass \
                     text-based filters in prompt injection attacks."
                    .to_string(),
                suggestion: Some(
                    "Remove the zero-width character. Use only ASCII in source code files."
                        .to_string(),
                ),
            }),
            0x200D => violations.push(DefenderViolation {
                visitor: "unicode_zero_width".to_string(),
                line,
                col,
                evidence: "U+200D (Zero Width Joiner)".to_string(),
                decoded: None,
                message: "Zero-width joiner U+200D detected. Used in steganography to embed \
                     hidden instructions within visible text."
                    .to_string(),
                suggestion: Some(
                    "Remove the zero-width character. Use only ASCII in source code files."
                        .to_string(),
                ),
            }),
            0xFEFF => violations.push(DefenderViolation {
                visitor: "unicode_zero_width".to_string(),
                line,
                col,
                evidence: "U+FEFF (Zero Width No-Break Space / BOM)".to_string(),
                decoded: None,
                message: "Zero-width no-break space U+FEFF detected. Can be used for BOM-based \
                     steganography to hide prompt injection payloads."
                    .to_string(),
                suggestion: Some(
                    "Remove the BOM/ZWBS. Use UTF-8 without BOM in source code files.".to_string(),
                ),
            }),
            _ => {}
        }

        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }

    violations
}
