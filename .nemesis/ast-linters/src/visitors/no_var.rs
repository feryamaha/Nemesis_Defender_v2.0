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
    if node.kind() == "variable_declaration" {
        let text = &source[node.byte_range()];
        if text.starts_with("var ") {
            let line = node.start_position().row + 1;
            violations.push(Violation::new(
                "Uso de 'var' detectado. Use const para imutaveis ou let para mutaveis.",
                line, RuleCategory::Suspicious,
            ).with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Use const para imutaveis ou let para mutaveis."));
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
