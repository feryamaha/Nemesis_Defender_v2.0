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
    if node.kind() == "object_pattern" || node.kind() == "array_pattern" {
        let child_count = node.child_count();
        let is_empty = match node.kind() {
            "object_pattern" => child_count <= 2,
            "array_pattern" => child_count <= 2,
            _ => false,
        };
        if is_empty {
            let pattern_type = if node.kind() == "object_pattern" { "objeto" } else { "array" };
            let line = node.start_position().row + 1;
            violations.push(Violation::new(
                format!("Desestruturacao de {} vazia detectada. Nao extrai nenhum valor.", pattern_type),
                line, RuleCategory::Correctness,
            ).with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Adicione propriedades ou elementos a desestruturacao."));
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
