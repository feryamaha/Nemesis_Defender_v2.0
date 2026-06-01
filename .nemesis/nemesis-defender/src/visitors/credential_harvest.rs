//! credential_harvest visitor — Vetor 7: credential & secret harvesting
//!
//! Detects patterns of reading secrets and exfiltration:
//! - Reading ~/.npmrc, ~/.ssh/, ~/.aws/credentials
//! - Accessing env vars with _TOKEN, _KEY, _SECRET
//! - fs.readFile + fetch/axios.post (read → exfiltrate)

use crate::DefenderViolation;
use tree_sitter::Node;

/// Check if node text contains a legitimate env var (allowlisted)
fn contains_legitimate_env_var(node_text: &str) -> bool {
    for legitimate in LEGITIMATE_ENV_VARS {
        if let Some(prefix) = legitimate.strip_suffix('*') {
            // Prefix match (e.g., NEXT_PUBLIC_*)
            if node_text.contains(prefix) {
                return true;
            }
        } else if node_text.contains(legitimate) {
            return true;
        }
    }
    false
}

const SENSITIVE_PATHS: &[&str] = &[
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/authorized_keys",
    ".aws/credentials",
    ".env",
];

const SENSITIVE_ENV_PATTERNS: &[&str] = &[
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PAT",
    "API_KEY",
];

// Allowlist of legitimate env var names that should NOT trigger credential_harvest
// even if they match SENSITIVE_ENV_PATTERNS (e.g., CLIENT_TOKEN, CLIENT_ID in Next.js)
const LEGITIMATE_ENV_VARS: &[&str] = &[
    "CLIENT_TOKEN",
    "CLIENT_ID",
    "NODE_ENV",
    "NEXT_PUBLIC", // NEXT_PUBLIC_* is safe by design
];

/// Network exfil sinks: presence of these in the same code block indicates active exfiltration intent.
/// Used to distinguish SDK initialization (legitimate) from credential theft (malicious).
const NETWORK_EXFIL_INDICATORS: &[&str] = &[
    "fetch(",
    "fetch (",
    "axios.",
    "http.request",
    "https.request",
    "XMLHttpRequest",
    "new WebSocket",
    "socket.connect",
    "net.connect",
    "requests.post",
    "requests.get",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "urllib.request",
    ".urlopen(",
    "http.client",
];

fn has_network_exfil_sink(text: &str) -> bool {
    NETWORK_EXFIL_INDICATORS.iter().any(|s| text.contains(s))
}

const SUGGESTION_CRED: &str =
    "Never read credential files in application code. Use a secrets manager (Vault, AWS Secrets Manager, CI/CD-injected env vars).";

const SUGGESTION_EXFIL: &str =
    "Never read credential files and make network requests in the same code flow.";

pub fn visit_js_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node.kind() == "call_expression" && node_text.contains("readFile") {
        for path in SENSITIVE_PATHS {
            if node_text.contains(path) {
                violations.push(DefenderViolation {
                    visitor: "credential_harvest".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: format!("fs.readFile({})", path),
                    decoded: None,
                    message: format!(
                        "Reading sensitive file: {}. Credential theft pattern.",
                        path
                    ),
                    suggestion: Some(SUGGESTION_CRED.to_string()),
                });
                break;
            }
        }
    }

    if node_text.contains("process.env")
        && has_network_exfil_sink(node_text)
        && !contains_legitimate_env_var(node_text)
    {
        for pattern in SENSITIVE_ENV_PATTERNS {
            if node_text.contains(pattern) {
                violations.push(DefenderViolation {
                    visitor: "credential_harvest".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: format!("process.env.{}", pattern),
                    decoded: None,
                    message: format!("Credential env var {} read with active network sink — exfiltration pattern.", pattern),
                    suggestion: Some(SUGGESTION_CRED.to_string()),
                });
                break;
            }
        }
    }

    if node_text.contains("readFile")
        && (node_text.contains("fetch") || node_text.contains("axios"))
    {
        violations.push(DefenderViolation {
            visitor: "credential_harvest".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message:
                "File read followed by network request. Potential credential exfiltration pattern."
                    .to_string(),
            suggestion: Some(SUGGESTION_EXFIL.to_string()),
        });
    }

    violations
}

pub fn visit_bash_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node_text.contains("cat") || node_text.contains("read") {
        for path in SENSITIVE_PATHS {
            if node_text.contains(path) {
                violations.push(DefenderViolation {
                    visitor: "credential_harvest".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: format!("Reading {}", path),
                    decoded: None,
                    message: format!("Shell reading sensitive file: {}. Credential theft.", path),
                    suggestion: Some(SUGGESTION_CRED.to_string()),
                });
                break;
            }
        }
    }

    violations
}

pub fn visit_python_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node.kind() == "call_expression"
        && (node_text.contains("open(") || node_text.contains("Path("))
    {
        for path in SENSITIVE_PATHS {
            if node_text.contains(path) {
                violations.push(DefenderViolation {
                    visitor: "credential_harvest".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: format!("open({})", path),
                    decoded: None,
                    message: format!(
                        "Python reading sensitive file: {}. Credential harvesting.",
                        path
                    ),
                    suggestion: Some(SUGGESTION_CRED.to_string()),
                });
                break;
            }
        }
    }

    if (node_text.contains("os.environ") || node_text.contains("os.getenv"))
        && has_network_exfil_sink(node_text)
        && !contains_legitimate_env_var(node_text)
    {
        for pattern in SENSITIVE_ENV_PATTERNS {
            if node_text.contains(pattern) {
                violations.push(DefenderViolation {
                    visitor: "credential_harvest".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: format!("os.environ/{}", pattern),
                    decoded: None,
                    message: format!("Credential env var {} read with active network sink — exfiltration pattern.", pattern),
                    suggestion: Some(SUGGESTION_CRED.to_string()),
                });
                break;
            }
        }
    }

    violations
}
