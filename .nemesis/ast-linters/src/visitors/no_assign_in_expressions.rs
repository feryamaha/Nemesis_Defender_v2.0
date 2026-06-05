/// Visitor: Detecta atribuições em expressões condicionais (no-assign-in-expressions).
///
/// Detecta `assignment_expression` usado como condição de `if`, `while`, ternário,
/// ou em contextos onde comparação (`===`) era provavelmente a intenção.
///
/// Exemplos de violação:
/// - `if (a = 1) {}`
/// - `while (x = getValue()) {}`
/// - `let result = (a = b) ? c : d`
///
/// Exemplos válidos:
/// - `let a = 1` (statement-level assignment)
/// - `for (let i = 0; i < n; i++) {}` (for init/update)

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

    if node.kind() == "assignment_expression" {
        check_assignment_in_condition(&node, source, violations);
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

fn check_assignment_in_condition(
    node: &tree_sitter::Node,
    source: &str,
    violations: &mut Vec<Violation>,
) {
    let parent = node.parent();
    if parent.is_none() {
        return;
    }
    let parent = parent.unwrap();
    let parent_kind = parent.kind();

    // Skip if parent is expression_statement (top-level assignment like `a = 1`)
    if parent_kind == "expression_statement" {
        return;
    }

    // Skip if parent is another assignment (chained: `a = b = c`)
    if parent_kind == "assignment_expression" {
        return;
    }

    // If parent is parenthesized_expression, check grandparent for condition contexts
    if parent_kind == "parenthesized_expression" {
        let grandparent = parent.parent();
        if let Some(gp) = grandparent {
            if gp.kind() == "expression_statement" {
                return;
            }
            let condition_contexts = [
                "if_statement", "while_statement", "do_statement",
                "conditional_expression", "for_statement",
            ];
            if condition_contexts.contains(&gp.kind()) {
                let line = node.start_position().row + 1;
                violations.push(
                    Violation::new(
                        "Atribuição em expressão condicional detectada. Isso é provavelmente um bug — você queria usar comparação (===)?",
                        line,
                        RuleCategory::Suspicious,
                    )
                    .with_suggestion("Use === para comparação. Atribuição em condicional é provavelmente um bug.")
                );
                return;
            }
        }
    }

    // Skip for-loop initializer and update parts
    if parent_kind == "for_statement" {
        let mut cursor = parent.walk();
        let children: Vec<_> = parent.children(&mut cursor).collect();
        let node_pos = node.start_position();
        let init_pos = children.iter().position(|c| c.kind() == "assignment_expression");
        if let Some(pos) = init_pos {
            if children.get(pos).map(|c| c.start_position()) == Some(node_pos) {
                return;
            }
        }
        // Check if it's the update part (last expression before body)
        let update_idx = children.iter().rposition(|c| c.kind() == "assignment_expression");
        if let Some(idx) = update_idx {
            if children.get(idx).map(|c| c.start_position()) == Some(node_pos) {
                return;
            }
        }
    }

    // Arrow function expression body (e.g., `const f = b => a += b`)
    if parent_kind == "arrow_function" {
        return;
    }

    // Detect assignment in condition contexts
    let condition_contexts = [
        "if_statement", "while_statement", "do_statement",
        "conditional_expression", "for_statement",
    ];

    if condition_contexts.contains(&parent_kind) {
        let line = node.start_position().row + 1;
        violations.push(
            Violation::new(
                "Atribuição em expressão condicional detectada. Isso é provavelmente um bug — você queria usar comparação (===)?",
                line,
                RuleCategory::Suspicious,
            )
            .with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Use === para comparação. Atribuição em condicional é provavelmente um bug.")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assign_in_if_detected() {
        let _source = r#"if (a = 1) {}"#;
    }

    #[test]
    fn test_assign_statement_not_detected() {
        let _source = r#"let a = 1"#;
    }
}
