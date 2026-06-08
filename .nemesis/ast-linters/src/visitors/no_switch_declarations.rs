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
    if node.kind() == "switch_case" || node.kind() == "switch_default" {
        check_switch_case(&node, source, violations);
    }
    if cursor.goto_first_child() {
        loop {
            visit_node(cursor, source, violations);
            if !cursor.goto_next_sibling() { break; }
        }
        cursor.goto_parent();
    }
}

fn check_switch_case(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    let mut found_colon = false;
    for child in &children {
        if child.kind() == ":" { found_colon = true; continue; }
        if found_colon {
            match child.kind() {
                "lexical_declaration" | "variable_declaration" | "function_declaration"
                | "class_declaration" => {
                    let text = &source[child.byte_range()];
                    let is_blocked = match child.kind() {
                        "variable_declaration" => text.starts_with("let ") || text.starts_with("const "),
                        _ => true,
                    };
                    if is_blocked {
                        let line = child.start_position().row + 1;
                        violations.push(Violation::new(
                        "Declaracao lexica diretamente em switch case sem bloco. Isso pode causar acesso indevido em outros cases.",
                        line, RuleCategory::Correctness,
                    ).with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Envolva o case em bloco: case x: { const y = ... }."));
                    }
                }
                _ => {}
            }
        }
    }
}
