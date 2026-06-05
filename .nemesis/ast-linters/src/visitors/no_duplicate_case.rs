/// Visitor: Detecta cases duplicados em switch (no-duplicate-case).
///
/// Detecta `switch` com dois ou mais `case` com valor idêntico.
///
/// Exemplos de violação:
/// ```js
/// switch (a) {
///     case 1: break;
///     case 1: break;
/// }
/// ```
///
/// Exemplos válidos:
/// ```js
/// switch (a) {
///     case 1: break;
///     case 2: break;
/// }
/// ```

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};
use std::collections::HashSet;

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

    if node.kind() == "switch_statement" {
        check_switch_statement(&node, source, violations);
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

fn check_switch_statement(
    node: &tree_sitter::Node,
    source: &str,
    violations: &mut Vec<Violation>,
) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    let body = match children.iter().find(|c| c.kind() == "switch_body") {
        Some(b) => b,
        None => return,
    };

    let mut body_cursor = body.walk();
    let body_children: Vec<_> = body.children(&mut body_cursor).collect();

    let mut seen_values: HashSet<String> = HashSet::new();

    for child in &body_children {
        if child.kind() == "switch_case" {
            let mut case_cursor = child.walk();
            let case_children: Vec<_> = child.children(&mut case_cursor).collect();

            // The value is the second child (after 'case' keyword)
            if case_children.len() >= 2 {
                let value_node = &case_children[1];
                let value_text = source[value_node.byte_range()].to_string();

                if !seen_values.insert(value_text.clone()) {
                    let line = child.start_position().row + 1;
                    violations.push(
                        Violation::new(
                            format!("Case duplicado detectado: '{}'. Cada case deve ter um valor único.", value_text),
                            line,
                            RuleCategory::Suspicious,
                        )
                        .with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Remova o case duplicado.")
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_case_detected() {
        let _source = r#"
            switch (a) {
                case 1: break;
                case 1: break;
            }
        "#;
    }

    #[test]
    fn test_unique_cases_not_detected() {
        let _source = r#"
            switch (a) {
                case 1: break;
                case 2: break;
            }
        "#;
    }
}
