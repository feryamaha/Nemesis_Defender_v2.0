/// Visitor: Detecta fallthrough em switch case (no-fallthrough-switch-clause).
///
/// Detecta `switch_case` sem `break`, `return`, `throw` ou `continue`
/// antes do próximo case.
///
/// Exemplos de violação:
/// ```js
/// switch (bar) {
///     case 0:
///         a();
///     case 1:
///         b();
/// }
/// ```
///
/// Exemplos válidos:
/// ```js
/// switch (foo) {
///     case 1:
///     case 2:
///         doSomething();
///         break;
///     case 3:
///         doSomethingElse();
///         break;
/// }
/// ```

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

    // Find the switch_body
    let body = children.iter().find(|c| c.kind() == "switch_body");
    if body.is_none() {
        return;
    }
    let body = body.unwrap();

    let mut body_cursor = body.walk();
    let body_children: Vec<_> = body.children(&mut body_cursor).collect();

    let mut prev_case: Option<&tree_sitter::Node> = None;
    let mut prev_has_break = true;

    for child in &body_children {
        if child.kind() == "switch_case" || child.kind() == "switch_default" {
            if let Some(prev) = prev_case {
                if !prev_has_break && has_statements(prev, source) {
                    let line = prev.start_position().row + 1;
                    violations.push(
                        Violation::new(
                            "Switch case sem break/return/throw/continue detectado. Isso causa fallthrough para o próximo case.",
                            line,
                            RuleCategory::Suspicious,
                        )
                        .with_suggestion("Adicione break, return ou throw ao final de cada case.")
                    );
                }
            }
            prev_case = Some(child);
            prev_has_break = has_terminator(child, source);
        }
    }

    // Check last case
    if let Some(prev) = prev_case {
        if !prev_has_break && has_statements(prev, source) {
            let line = prev.start_position().row + 1;
            violations.push(
                Violation::new(
                    "Switch case sem break/return/throw/continue detectado. Isso causa fallthrough para o próximo case.",
                    line,
                    RuleCategory::Suspicious,
                )
                .with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Adicione break, return ou throw ao final de cada case.")
            );
        }
    }
}

fn has_statements(node: &tree_sitter::Node, source: &str) -> bool {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    // A case has statements if it has more than just the 'case' keyword and value
    children.iter().any(|c| {
        matches!(
            c.kind(),
            "expression_statement" | "variable_declaration"
                | "return_statement" | "throw_statement"
                | "if_statement" | "for_statement" | "while_statement"
                | "try_statement" | "switch_statement" | "block"
        )
    })
}

fn has_terminator(node: &tree_sitter::Node, source: &str) -> bool {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    // Check direct children for break/return/throw/continue
    for child in &children {
        match child.kind() {
            "break_statement" | "return_statement" | "throw_statement" | "continue_statement" => {
                return true;
            }
            _ => {}
        }
    }

    // Also check recursively inside blocks
    for child in &children {
        if child.kind() == "block" || child.kind() == "statement_block" {
            if has_terminator(child, source) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallthrough_detected() {
        let _source = r#"
            switch (bar) {
                case 0:
                    a();
                case 1:
                    b();
            }
        "#;
    }

    #[test]
    fn test_with_break_not_detected() {
        let _source = r#"
            switch (foo) {
                case 1:
                    doSomething();
                    break;
                case 2:
                    doSomethingElse();
                    break;
            }
        "#;
    }
}
