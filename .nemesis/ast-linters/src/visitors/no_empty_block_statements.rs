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
    match node.kind() {
        "statement_block" => {
            if node.child_count() == 2 {
                let line = node.start_position().row + 1;
                violations.push(Violation::new(
                    "Bloco vazio detectado. Blocos vazios sao geralmente resultado de refatoracao incompleta.",
                    line, RuleCategory::Suspicious,
                ).with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Adicione implementacao ou comentario explicando o bloco vazio.").with_severity(Severity::Warning));
            }
        }
        "switch_body" => {
            let has_cases = node.children(&mut node.walk()).any(|c| c.kind() == "switch_case" || c.kind() == "switch_default");
            if !has_cases {
                let line = node.start_position().row + 1;
                violations.push(Violation::new(
                    "Switch statement vazio detectado.",
                    line, RuleCategory::Suspicious,
                ).with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Adicione cases ou remova o switch.").with_severity(Severity::Warning));
            }
        }
        _ => {}
    }
    if cursor.goto_first_child() {
        loop {
            visit_node(cursor, source, violations);
            if !cursor.goto_next_sibling() { break; }
        }
        cursor.goto_parent();
    }
}
