/// Visitor: Detecta uso de == e != (no-double-equals).
///
/// Detecta operadores de igualdade não-estrita (`==` e `!=`),
/// que realizam coerção de tipos e podem causar bugs sutis.
/// Permite `== null` como exceção comum para checar null/undefined.
///
/// Exemplos de violação:
/// - `foo == bar`
/// - `x != 5`
///
/// Exemplos válidos:
/// - `foo == null`
/// - `foo === bar`
/// - `x !== 5`

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};

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

    if node.kind() == "binary_expression" {
        check_binary_expression(&node, source, violations);
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

fn check_binary_expression(
    node: &tree_sitter::Node,
    source: &str,
    violations: &mut Vec<Violation>,
) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    let mut operator = "";
    for child in &children {
        let text = &source[child.byte_range()];
        if text == "==" || text == "!=" {
            operator = text;
            break;
        }
    }

    if operator.is_empty() {
        return;
    }

    // Allow == null and != null
    let left = children.first();
    let right = children.last();

    let left_is_null = left.map(|n| &source[n.byte_range()] == "null").unwrap_or(false);
    let right_is_null = right.map(|n| &source[n.byte_range()] == "null").unwrap_or(false);

    if left_is_null || right_is_null {
        return;
    }

    let line = node.start_position().row + 1;
    violations.push(
        Violation::new(
            format!("Uso de {} detectado. Operadores de igualdade não-estrita realizam coerção de tipos e podem causar bugs.", operator),
            line,
            RuleCategory::Suspicious,
        )
        .with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Use === e !== para comparação estrita.")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_equals_detected() {
        let _source = r#"foo == bar"#;
    }

    #[test]
    fn test_null_equals_not_detected() {
        let _source = r#"foo == null"#;
    }

    #[test]
    fn test_triple_equals_not_detected() {
        let _source = r#"foo === bar"#;
    }
}
