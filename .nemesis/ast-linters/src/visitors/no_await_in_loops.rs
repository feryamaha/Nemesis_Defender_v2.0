use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};

pub fn visit(tree: &ParsedTree, source: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let cursor = &mut tree.tree.walk();
    visit_node(cursor, source, &mut violations);
    violations
}

fn visit_node(cursor: &mut tree_sitter::TreeCursor, source: &str, violations: &mut Vec<Violation>) {
    let node = cursor.node();
    if node.kind() == "for_statement" || node.kind() == "for_in_statement"
        || node.kind() == "while_statement" || node.kind() == "do_statement"
    {
        if has_await_inside(&node, source) {
            let line = node.start_position().row + 1;
            violations.push(Violation::new(
                "await dentro de loop detectado. Isso executa operacoes assincronas sequencialmente.",
                line, RuleCategory::Suspicious,
            ).with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Use Promise.all() para executar em paralelo."));
        }
    }
    if cursor.goto_first_child() {
        loop {
            visit_node(cursor, source, violations);
            if !cursor.goto_next_sibling() { break; }
        }
        cursor.goto_parent();
    }
}

fn has_await_inside(node: &tree_sitter::Node, source: &str) -> bool {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "await_expression" {
                return true;
            }
            if child.kind() == "function_declaration" || child.kind() == "function_expression"
                || child.kind() == "arrow_function"
            {
                if !cursor.goto_next_sibling() { break; }
                continue;
            }
            if has_await_inside(&child, source) {
                return true;
            }
            if !cursor.goto_next_sibling() { break; }
        }
    }
    false
}
