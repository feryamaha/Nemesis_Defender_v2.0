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
    if node.kind() == "new_expression" {
        check_new_expression(&node, source, violations);
    }
    if cursor.goto_first_child() {
        loop {
            visit_node(cursor, source, violations);
            if !cursor.goto_next_sibling() { break; }
        }
        cursor.goto_parent();
    }
}

fn check_new_expression(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    let is_promise = children.iter().any(|c| c.kind() == "identifier" && &source[c.byte_range()] == "Promise");
    if !is_promise { return; }
    let args = match children.iter().find(|c| c.kind() == "arguments") {
        Some(a) => a, None => return,
    };
    let mut ac = args.walk();
    let acs: Vec<_> = args.children(&mut ac).collect();
    let first = match acs.iter().find(|c| c.kind() != "(" && c.kind() != ")" && c.kind() != ",") {
        Some(f) => f, None => return,
    };
    if is_async_function(first, source) {
        let line = node.start_position().row + 1;
        violations.push(Violation::new(
            "Executor de Promise nao deve ser async. Erros lancados em executor async nao sao capturados.",
            line, RuleCategory::Suspicious,
        ).with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Nao use async em executores de Promise. Erros nao sao capturados."));
    }
}

fn is_async_function(node: &tree_sitter::Node, source: &str) -> bool {
    let mut cur = *node;
    loop {
        match cur.kind() {
            "function_expression" | "arrow_function" => {
                let mut c = cur.walk();
                let ch: Vec<_> = cur.children(&mut c).collect();
                return ch.iter().any(|x| x.kind() == "async" || &source[x.byte_range()] == "async");
            }
            "parenthesized_expression" => {
                let mut c = cur.walk();
                let ch: Vec<_> = cur.children(&mut c).collect();
                match ch.iter().find(|x| x.kind() != "(" && x.kind() != ")") {
                    Some(inner) => cur = *inner,
                    None => return false,
                }
            }
            _ => return false,
        }
    }
}
