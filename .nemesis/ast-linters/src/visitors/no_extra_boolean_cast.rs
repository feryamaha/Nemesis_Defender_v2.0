use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory, Severity};

pub fn visit(tree: &ParsedTree, source: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let cursor = &mut tree.tree.walk();
    visit_node(cursor, source, &mut violations);
    violations
}

fn visit_node(cursor: &mut tree_sitter::TreeCursor, source: &str, violations: &mut Vec<Violation>) {
    let node = cursor.node();
    if node.kind() == "unary_expression" {
        check_double_negation(&node, source, violations);
    }
    if node.kind() == "call_expression" {
        check_boolean_call(&node, source, violations);
    }
    if cursor.goto_first_child() {
        loop {
            visit_node(cursor, source, violations);
            if !cursor.goto_next_sibling() { break; }
        }
        cursor.goto_parent();
    }
}

fn is_boolean_context(node: &tree_sitter::Node) -> bool {
    if let Some(p) = node.parent() {
        matches!(p.kind(), "if_statement" | "while_statement" | "do_statement"
            | "for_statement" | "ternary_expression" | "unary_expression")
    } else {
        false
    }
}

fn check_double_negation(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let text = &source[node.byte_range()];
    if text.starts_with("!!") && is_boolean_context(node) {
        let line = node.start_position().row + 1;
        violations.push(Violation::new(
            "Double-negation redundante em contexto booleano.",
            line, RuleCategory::Suspicious,
        ).with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Use o valor diretamente sem cast booleano.").with_severity(Severity::Warning));
    }
}

fn check_boolean_call(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let text = &source[node.byte_range()];
    if text.starts_with("Boolean(") && is_boolean_context(node) {
        let line = node.start_position().row + 1;
        violations.push(Violation::new(
            "Boolean() redundante em contexto ja booleano.",
            line, RuleCategory::Suspicious,
        ).with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Use o valor diretamente sem Boolean().").with_severity(Severity::Warning));
    }
}
