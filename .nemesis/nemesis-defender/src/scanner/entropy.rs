//! Shannon entropy scanner
//!
//! Detects strings with abnormally high entropy — strong signal for:
//! - Base64-encoded payloads
//! - AES/XOR-encrypted command strings
//! - Hex-encoded shellcode
//!
//! Heuristic: entropy > 5.5 bits/char in a string literal of length 20–500
//! Threshold tuned to avoid false positives from Tailwind CSS classes (entropy ~4.9-5.1)
//! while still catching encoded payloads (entropy > 5.5).

use crate::DefenderViolation;

const ENTROPY_THRESHOLD: f64 = 5.5;
const MIN_STRING_LEN: usize = 20;
const MAX_STRING_LEN: usize = 500;

/// Calculate Shannon entropy of a byte slice
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0_f64;

    for &count in freq.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Extract candidate string literals from content (simplified — looks for quoted regions)
fn extract_string_candidates(content: &[u8]) -> Vec<(u32, u32, Vec<u8>)> {
    let mut results = Vec::new();
    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return results,
    };

    let (mut line, mut col) = (1u32, 1u32);
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        if ch == '"' || ch == '\'' || ch == '`' {
            let quote = ch;
            let start_line = line;
            let start_col = col;
            let mut content_bytes = Vec::new();
            i += 1;
            col += 1;

            while i < chars.len() && chars[i] != quote {
                if chars[i] == '\n' {
                    // Multi-line string (template literal) — still collect
                    content_bytes.push(b'\n');
                    line += 1;
                    col = 1;
                } else {
                    let mut buf = [0u8; 4];
                    let s = chars[i].encode_utf8(&mut buf);
                    content_bytes.extend_from_slice(s.as_bytes());
                    col += 1;
                }
                i += 1;
            }

            let len = content_bytes.len();
            if len >= MIN_STRING_LEN && len <= MAX_STRING_LEN {
                results.push((start_line, start_col, content_bytes));
            }
        }

        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
        i += 1;
    }

    results
}

pub fn scan_high_entropy(content: &[u8]) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    for (line, col, candidate) in extract_string_candidates(content) {
        let entropy = shannon_entropy(&candidate);

        if entropy > ENTROPY_THRESHOLD {
            let preview: String = candidate
                .iter()
                .take(60)
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();

            violations.push(DefenderViolation {
                visitor: "high_entropy".to_string(),
                line,
                col,
                evidence: format!("\"{}...\" (entropy: {:.2})", preview, entropy),
                decoded: None,
                message: format!(
                    "High-entropy string literal detected ({:.2} bits/char, threshold: {}). \
                     Strong indicator of Base64/hex/encrypted payload. \
                     Verify this is not an encoded malicious command.",
                    entropy, ENTROPY_THRESHOLD
                ),
                suggestion: Some("Verify whether this string is an encoded payload. Credentials and keys must be stored in secrets managers, not in code.".to_string()),
            });
        }
    }

    violations
}
