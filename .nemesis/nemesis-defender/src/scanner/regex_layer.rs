//! Regex fast-path scanner — pre-AST pattern matching
//!
//! Catches well-known attack patterns that don't require AST context:
//! - Credential file paths (~/.npmrc, ~/.ssh/, ~/.aws/)
//! - Known C2 infrastructure patterns
//! - Download-and-execute one-liners
//! - Self-deletion patterns

use crate::{DefenderViolation, Language};

struct RegexPattern {
    visitor: &'static str,
    pattern: &'static str,
    message: &'static str,
}

/// Patterns that apply to ALL languages
const UNIVERSAL_PATTERNS: &[RegexPattern] = &[
    RegexPattern {
        visitor: "credential_harvest",
        pattern: r#"(~/\.npmrc|~/\.pypirc|~/\.netrc|home.*\.npmrc)"#,
        message: "Access to npm/pypi credential file. Shai-Hulud 2.0 attack pattern — reads tokens for exfiltration.",
    },
    RegexPattern {
        visitor: "credential_harvest",
        pattern: r#"(~/\.ssh/|/root/\.ssh/|home.*\.ssh/)(id_rsa|id_ed25519|authorized_keys|known_hosts)"#,
        message: "Access to SSH private key. Supply chain credential theft pattern.",
    },
    RegexPattern {
        visitor: "credential_harvest",
        pattern: r#"(~/\.aws/credentials|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)"#,
        message: "Access to AWS credentials. Cloud credential exfiltration pattern (Shai-Hulud 2.0).",
    },
    RegexPattern {
        visitor: "credential_harvest",
        pattern: r#"(GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|PYPI_TOKEN|npm_config_[a-z_]*token)"#,
        message: "Access to VCS/registry token. Used by self-propagating supply chain worms.",
    },
    RegexPattern {
        visitor: "url_in_exec",
        pattern: r#"(https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[/:])"#,
        message: "Raw IP address in HTTP URL. Known C2 infrastructure pattern (e.g., ClawHub attack: 91.92.242.30).",
    },
    RegexPattern {
        visitor: "decode_exec",
        pattern: r#"(eval|exec|execSync|spawnSync)\s*\(\s*(Buffer\.from|atob|btoa)"#,
        message: "decode-then-exec pattern detected. Base64 decode result passed directly to code execution.",
    },
    RegexPattern {
        visitor: "decode_exec",
        pattern: r#"String\.fromCharCode\s*\(\s*[0-9]+\s*,"#,
        message: "String.fromCharCode array detected. Known obfuscation technique to reconstruct commands at runtime.",
    },
    RegexPattern {
        visitor: "self_clean",
        pattern: r#"(fs\.unlink|fs\.unlinkSync|require\('fs'\)\.unlink).*__filename"#,
        message: "Self-deletion pattern: unlinks own file (__filename). Forensic evasion — malware deletes itself after execution.",
    },
    RegexPattern {
        visitor: "self_clean",
        pattern: r#"(rm\s+-f|unlink).*\$0"#,
        message: "Shell self-deletion: rm -f $0. Script deletes itself after execution to evade forensic analysis.",
    },
    RegexPattern {
        visitor: "url_in_exec",
        pattern: r#"(curl|wget)\s+.*\|\s*(bash|sh|zsh|python|node)"#,
        message: "Download-and-execute: curl/wget piped to shell interpreter. Classic one-liner malware delivery.",
    },
    RegexPattern {
        visitor: "prompt_injection",
        pattern: r#"(?i)(ignore\s+previous\s+instructions|disregard\s+(all|previous)|forget\s+your\s+(rules|instructions))"#,
        message: "Indirect prompt injection detected. Instruction to override AI agent safety rules.",
    },
    RegexPattern {
        visitor: "prompt_injection",
        pattern: r#"(?i)(<\|im_start\||<\|system\||<<SYS>>|\[INST\]|###\s*System:)"#,
        message: "AI instruction format token detected in source/skill file. Hidden system prompt injection.",
    },
    // ── Prompt injection / jailbreak (DAN, role-play override) ──
    RegexPattern {
        visitor: "prompt_injection",
        pattern: r#"(?i)\bDAN\b.{0,40}(?:Do\s+Anything\s+Now|mode)"#,
        message: "DAN jailbreak pattern detected. Attempts to force AI to operate without safety constraints.",
    },
    RegexPattern {
        visitor: "prompt_injection",
        pattern: r#"(?i)you\s+are\s+now\s+(?:unrestricted|free|god|DAN|evil|unfiltered)"#,
        message: "Role-override jailbreak detected. Attempts to replace AI identity to bypass restrictions.",
    },
    RegexPattern {
        visitor: "prompt_injection",
        pattern: r#"(?i)(?:bypass|ignore|disable)\s+(?:your\s+)?(?:safety|restrictions|filter|alignment|guidelines)"#,
        message: "Safety bypass directive detected in file content. Prompt injection attack.",
    },
    RegexPattern {
        visitor: "prompt_injection",
        pattern: r#"(?i)(?:do\.?anything\.?now|no\.?restrictions|no\.?limits|no\.?rules|no\.?boundaries)"#,
        message: "Unrestricted operation directive detected. AI jailbreak pattern.",
    },
    RegexPattern {
        visitor: "prompt_injection",
        pattern: r#"(?i)(?:jailbreak(?:ed|ing)?|developer\s+mode\s+enabled|maintenance\s+mode\s+on)"#,
        message: "Jailbreak activation phrase detected in file content.",
    },
    // ── Reverse shells (hardcoded — works without denylist) ──
    RegexPattern {
        visitor: "decode_exec",
        pattern: r#"socket\.socket\b.{0,60}\.connect\s*\("#,
        message: "Reverse shell pattern: socket.connect. Active exploitation technique — connect-back to attacker.",
    },
    RegexPattern {
        visitor: "decode_exec",
        pattern: r#"import\s+socket\s*;.{0,80}\.connect\s*\("#,
        message: "Python reverse shell pattern: import socket + connect. Remove immediately.",
    },
    RegexPattern {
        visitor: "decode_exec",
        pattern: r#"(?:/dev/tcp/|/dev/udp/|bash\s+-i\s+>&|nc\s+-e\s+/bin|socat\s+exec:)"#,
        message: "Reverse shell infrastructure pattern detected (bash /dev/tcp, netcat -e, socat). Active exploitation.",
    },
    // ── Supply chain: malicious registry ──
    RegexPattern {
        visitor: "credential_harvest",
        pattern: r#"(?i)registry\s*=\s*https?://(?!registry\.npmjs\.org|npm\.pkg\.github\.com)"#,
        message: "Non-standard npm registry in .npmrc. Supply chain redirect attack — packages pulled from attacker's server.",
    },
    // ── Supply chain: non-canonical PyPI index (requirements.txt / pip.ini) ──
    RegexPattern {
        visitor: "manifest_registry_redirect",
        pattern: r#"--(?:extra-)?index-url\s+https?://(?!pypi\.org|files\.pythonhosted\.org|test\.pypi\.org)\S+"#,
        message: "Non-canonical PyPI index URL in --extra-index-url / --index-url. Supply chain redirect: all pip installs resolve from attacker-controlled server instead of pypi.org.",
    },
    // ── Supply chain: non-canonical PyPI server in .pypirc / pip.ini ──
    RegexPattern {
        visitor: "manifest_registry_redirect",
        pattern: r#"(?:repository|index_url)\s*=\s*https?://(?!pypi\.org|files\.pythonhosted\.org|test\.pypi\.org)\S+"#,
        message: "Non-canonical PyPI server in registry config (.pypirc / pip.ini). Supply chain redirect: pip resolves packages from attacker's index server.",
    },
];

pub fn scan(content: &[u8], _lang: &Language) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return violations,
    };

    for pattern_def in UNIVERSAL_PATTERNS {
        // Build regex (compiled once per call — for Phase 3+ this will be cached)
        let re = match regex::Regex::new(pattern_def.pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for m in re.find_iter(text) {
            // Calculate line/col from byte offset
            let before = &text[..m.start()];
            let line = before.chars().filter(|&c| c == '\n').count() as u32 + 1;
            let last_newline = before.rfind('\n').map(|p| p + 1).unwrap_or(0);
            let col = (m.start() - last_newline) as u32 + 1;

            violations.push(DefenderViolation {
                visitor: pattern_def.visitor.to_string(),
                line,
                col,
                evidence: m.as_str().to_string(),
                decoded: None,
                message: pattern_def.message.to_string(),
                suggestion: None,
            });
        }
    }

    // ── Layer 3.5: External deny-list (denylist-defender.json) ──
    // Loads patterns from config file, applies on top of hardcoded patterns above
    for severity in &["malicious", "suspicious"] {
        for (category, pattern_str, description, suggestion) in
            super::denylist_loader::patterns_by_severity(severity)
        {
            let re = match regex::Regex::new(&pattern_str) {
                Ok(r) => r,
                Err(_) => continue, // Skip invalid patterns
            };

            for m in re.find_iter(text) {
                let before = &text[..m.start()];
                let line = before.chars().filter(|&c| c == '\n').count() as u32 + 1;
                let last_newline = before.rfind('\n').map(|p| p + 1).unwrap_or(0);
                let col = (m.start() - last_newline) as u32 + 1;

                let visitor = if *severity == "malicious" {
                    "denylist_malicious"
                } else {
                    "denylist_suspicious"
                };

                violations.push(DefenderViolation {
                    visitor: visitor.to_string(),
                    line,
                    col,
                    evidence: m.as_str().to_string(),
                    decoded: None,
                    message: format!(
                        "Hostile command detected (denylist-defender / {}): {}",
                        category, description
                    ),
                    suggestion: suggestion.clone(),
                });
            }
        }
    }

    violations
}
