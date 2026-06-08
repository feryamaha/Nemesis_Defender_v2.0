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
    if node.kind() == "debugger_statement" {
        let line = node.start_position().row + 1;
        violations.push(Violation::new(
            "Debugger statement detectado. Remova antes de commit.",
            line, RuleCategory::Suspicious,
        ).with_suggestion("[STOP] Leia .devin/rules/origin-rules.md antes de reescrever. Remova o debugger antes de commit. Consulte: https://eslint.org/docs/rules/no-debugger"));
    }
    if cursor.goto_first_child() {
        loop {
            visit_node(cursor, source, violations);
            if !cursor.goto_next_sibling() { break; }
        }
        cursor.goto_parent();
    }
}
