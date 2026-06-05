/// Visitor: Detecta secrets em strings literais (no-secrets).
///
/// Detecta padrões comuns de secrets como API keys, tokens e credenciais
/// hardcoded no código fonte.
///
/// Padrões detectados:
/// - Strings com prefixo `sk-` (OpenAI/Stripe), `ghp_` (GitHub), `AKIA` (AWS), `AIza` (Google)
/// - Variáveis com nome suspeito (password, secret, api_key, token, credential, jwt, bearer)
///   atribuídas a string literal > 8 caracteres
/// - Strings contendo padrões de private key (BEGIN RSA/OPENSSH/DSA/EC/PGP PRIVATE KEY)
/// - JWT tokens (ey...)
/// - Slack tokens (xox[baprs]-)
/// - Slack webhook URLs
///
/// Exemplos de violação:
/// - `const secret = "AKIA1234567890EXAMPLE"`
/// - `const apiKey = "sk-abc123def456"`
/// - `const token = "ghp_1234567890abcdef"`
///
/// Exemplos válidos:
/// - `const nonSecret = "hello world"`

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};

const MIN_PATTERN_LEN: usize = 8;

pub fn visit(tree: &ParsedTree, source: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let cursor = &mut tree.tree.walk();
    visit_node(cursor, source, &mut violations);
    violations
}

fn visit_node(
    cursor: &mut tree_sitter::TreeCursor,
    source: &str,
    violations: &mut Vec<Violation>,
) {
    let node = cursor.node();

    match node.kind() {
        "string" => check_string_literal(&node, source, violations),
        "template_string" => check_string_literal(&node, source, violations),
        "variable_declarator" => check_variable_declarator(&node, source, violations),
        _ => {}
    }

    if cursor.goto_first_child() {
        loop {
            visit_node(cursor, source, violations);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

fn check_string_literal(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let text = &source[node.byte_range()];
    let inner = trim_quotes(text);

    if inner.len() < MIN_PATTERN_LEN {
        return;
    }

    if let Some(secret_type) = detect_secret_pattern(inner) {
        let line = node.start_position().row + 1;
        violations.push(
            Violation::new(
                format!("Potencial secret detectado: {}. Nunca armazene secrets no código fonte.", secret_type),
                line,
                RuleCategory::Security,
            )
            .with_suggestion("[STOP] Leia .windsurf/rules/Conformidade.md antes de reescrever. Use variável de ambiente server-side. OWASP A02: Cryptographic Failures.")
        );
    }
}

fn check_variable_declarator(
    node: &tree_sitter::Node,
    source: &str,
    violations: &mut Vec<Violation>,
) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    let mut var_name = String::new();
    let mut has_string_value = false;
    let mut string_value = String::new();

    for child in &children {
        if child.kind() == "identifier" {
            var_name = source[child.byte_range()].to_lowercase();
        }
        if child.kind() == "string" {
            has_string_value = true;
            string_value = trim_quotes(&source[child.byte_range()]).to_string();
        }
    }

    if has_string_value
        && is_suspicious_variable_name(&var_name)
        && string_value.len() > MIN_PATTERN_LEN
    {
        let line = node.start_position().row + 1;
        violations.push(
            Violation::new(
                format!("Variável '{}' contém possível secret hardcoded.", var_name),
                line,
                RuleCategory::Security,
            )
            .with_suggestion("[STOP] Leia .windsurf/rules/Conformidade.md antes de reescrever. Use variável de ambiente server-side. OWASP A02: Cryptographic Failures.")
        );
    }
}

fn trim_quotes(s: &str) -> &str {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"'))
        || (s.starts_with('\'') && s.ends_with('\''))
        || (s.starts_with('`') && s.ends_with('`'))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn is_suspicious_variable_name(name: &str) -> bool {
    let suspicious_words = [
        "password", "passwd", "secret", "api_key", "apikey",
        "token", "credential", "jwt", "bearer", "auth",
        "private_key", "privatekey",
    ];
    suspicious_words.iter().any(|w| name.contains(w))
}

fn detect_secret_pattern(text: &str) -> Option<&'static str> {
    // AWS API Key: AKIA followed by 16 alphanumeric chars
    if text.starts_with("AKIA") && text.len() >= 20 {
        return Some("AWS API Key (AKIA...)");
    }

    // Google OAuth: ya29...
    if text.starts_with("ya29.") {
        return Some("Google OAuth Token (ya29...)");
    }

    // Stripe/OpenAI: sk-
    if text.starts_with("sk-") && text.len() >= 20 {
        return Some("API Key (sk-...)");
    }

    // GitHub: ghp_
    if text.starts_with("ghp_") && text.len() >= 20 {
        return Some("GitHub Personal Access Token (ghp_...)");
    }

    // Twilio: SK... 32 chars
    if text.starts_with("SK") && text.len() >= 34 {
        let rest = &text[2..];
        if rest.chars().all(|c| c.is_alphanumeric()) {
            return Some("Twilio API Key (SK...)");
        }
    }

    // Slack Token: xox[baprs]-
    if (text.starts_with("xoxb-") || text.starts_with("xoxp-") || text.starts_with("xoxa-")
        || text.starts_with("xoxr-") || text.starts_with("xoxs-"))
        && text.len() >= 20
    {
        return Some("Slack Token (xox...)");
    }

    // Slack Webhook URL
    if text.contains("hooks.slack.com/services/") {
        return Some("Slack Webhook URL");
    }

    // JWT: ey... (base64 header)
    if text.starts_with("eyJ") && text.len() > 50 && text.contains('.') {
        return Some("JSON Web Token (JWT)");
    }

    // Private Keys
    if text.contains("-----BEGIN RSA PRIVATE KEY-----") {
        return Some("RSA Private Key");
    }
    if text.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
        return Some("SSH (OPENSSH) Private Key");
    }
    if text.contains("-----BEGIN DSA PRIVATE KEY-----") {
        return Some("SSH (DSA) Private Key");
    }
    if text.contains("-----BEGIN EC PRIVATE KEY-----") {
        return Some("SSH (EC) Private Key");
    }
    if text.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
        return Some("PGP Private Key Block");
    }

    // Password in URL: protocol://user:pass@...
    if text.contains("://") && text.contains('@') && text.contains(':') {
        let after_proto = text.split("://").nth(1).unwrap_or("");
        if after_proto.contains(':') && after_proto.contains('@') {
            return Some("Password in URL");
        }
    }

    // Google Service Account JSON
    if text.contains("\"type\"") && text.contains("service_account") {
        return Some("Google (GCP) Service-account");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_key_detected() {
        assert!(detect_secret_pattern("AKIA1234567890ABCDEF").is_some());
    }

    #[test]
    fn test_normal_string_not_detected() {
        assert!(detect_secret_pattern("hello world").is_none());
    }

    #[test]
    fn test_short_string_not_detected() {
        assert!(detect_secret_pattern("short").is_none());
    }

    #[test]
    fn test_suspicious_var_name() {
        assert!(is_suspicious_variable_name("password"));
        assert!(is_suspicious_variable_name("api_key"));
        assert!(is_suspicious_variable_name("my_secret_token"));
        assert!(!is_suspicious_variable_name("username"));
    }
}
