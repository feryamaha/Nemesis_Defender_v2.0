use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};
use std::collections::HashSet;

pub fn visit(tree: &ParsedTree, source: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let cursor = &mut tree.tree.walk();
    visit_node(cursor, source, &mut violations);
    violations
}

fn visit_node(cursor: &mut tree_sitter::TreeCursor, source: &str, violations: &mut Vec<Violation>) {
    let node = cursor.node();
    if node.kind() == "jsx_opening_element" || node.kind() == "jsx_self_closing_element" {
        check_jsx_element(&node, source, violations);
    }
    if cursor.goto_first_child() {
        loop {
            visit_node(cursor, source, violations);
            if !cursor.goto_next_sibling() { break; }
        }
        cursor.goto_parent();
    }
}

fn check_jsx_element(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    let mut seen: HashSet<String> = HashSet::new();
    for child in &children {
        if child.kind() == "jsx_attribute" {
            let mut ac = child.walk();
            let acs: Vec<_> = child.children(&mut ac).collect();
            for a in &acs {
                if a.kind() == "property_identifier" || a.kind() == "jsx_identifier" {
                    let name = source[a.byte_range()].to_string();
                    if !seen.insert(name.clone()) {
                        let line = child.start_position().row + 1;
                        violations.push(Violation::new(
                            format!("Atributo JSX '{}' duplicado.", name),
                            line, RuleCategory::Suspicious,
                        ).with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Remova o atributo duplicado."));
                    }
                    break;
                }
            }
        }
    }
}
