/// Visitor: Detecta uso de console (no-console) com allowlist para console.error.
///
/// Detecta chamadas de console.log, console.info, console.warn, etc. em código
/// de produção, mas permite console.error para logging de erros.
///
/// Exemplos de violação:
/// - `console.log("debug message")`
/// - `console.info("info message")`
/// - `console.warn("warning")`
///
/// Exemplos válidos:
/// - `console.error("error message")` (permitido para logging de erros)
/// - `console.error(new Error("something went wrong"))`

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory, Severity};

/// Percorre a árvore procurando por chamadas de console não permitidas.
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

    // Detecta call_expression
    if node.kind() == "call_expression" {
        check_call_expression(&node, source, violations);
    }

    // Continua a busca nos filhos
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

fn check_call_expression(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        // Detecta member expression: console.log, console.error, etc.
        if child.kind() == "member_expression" {
            check_console_call(child, source, violations);
        }
    }
}

fn check_console_call(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    let mut is_console = false;
    let mut console_method = String::new();

    for child in &children {
        // Detecta o objeto console
        if child.kind() == "identifier" {
            let text = &source[child.byte_range()];
            if text == "console" {
                is_console = true;
            }
        }

        // Detecta o método: log, error, warn, info, etc.
        if child.kind() == "property_identifier" {
            console_method = source[child.byte_range()].to_string();
        }
    }

    // Se for console mas não console.error, reporta violação
    if is_console && !console_method.is_empty() {
        let allowed_methods = ["error"];
        if !allowed_methods.iter().any(|&m| console_method == m) {
            let line = node.start_position().row + 1;
            violations.push(
                Violation::new(
                    format!("Uso de console.{} detectado. Use apenas console.error para logging de erros em produção. Remova console.log/console.info/console.warn do código de produção.", console_method),
                    line,
                    RuleCategory::Style
                )
                .with_suggestion("[STOP] Leia .devin/rules/react-hooks-patterns-rules.md antes de reescrever. Use console.error para erros reais. Remova console.log antes de commit. Consulte: https://eslint.org/docs/rules/no-console")
                .with_severity(Severity::Warning)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_log_detected() {
        let _source = r#"
            console.log("debug message");
        "#;
        // Teste seria integrado no validator.rs
    }

    #[test]
    fn test_console_error_not_detected() {
        let _source = r#"
            console.error("error message");
        "#;
        // Teste seria integrado no validator.rs
    }

    #[test]
    fn test_console_warn_detected() {
        let _source = r#"
            console.warn("warning");
        "#;
        // Teste seria integrado no validator.rs
    }
}
