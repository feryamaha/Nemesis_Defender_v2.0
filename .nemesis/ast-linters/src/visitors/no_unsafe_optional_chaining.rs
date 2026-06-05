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
    if node.kind() == "optional_chain" {
        check_optional_chain(&node, source, violations);
    }
    if cursor.goto_first_child() {
        loop {
            visit_node(cursor, source, violations);
            if !cursor.goto_next_sibling() { break; }
        }
        cursor.goto_parent();
    }
}

fn check_optional_chain(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let parent = node.parent();
    if parent.is_none() { return; }
    let parent = parent.unwrap();
    match parent.kind() {
        "binary_expression" => {
            let line = node.start_position().row + 1;
            violations.push(Violation::new(
                "Uso inseguro de optional chaining em expressao binaria. Se short-circuitar com undefined, causara NaN ou TypeError.",
                line, RuleCategory::Correctness,
            ).with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Verifique se o valor pode ser undefined antes de operar."));
        }
        "member_expression" => {
            // optional_chain wrapped in member_expression (e.g. arr?.length + 1)
            let grandparent = parent.parent();
            if let Some(gp) = grandparent {
                if gp.kind() == "binary_expression" {
                    let line = node.start_position().row + 1;
                    violations.push(Violation::new(
                        "Uso inseguro de optional chaining em expressao binaria. Se short-circuitar com undefined, causara NaN ou TypeError.",
                        line, RuleCategory::Correctness,
                    ).with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Verifique se o valor pode ser undefined antes de operar."));
                }
            }
        }
        "arguments" => {
            let grandparent = parent.parent();
            if let Some(gp) = grandparent {
                if gp.kind() == "call_expression" {
                    let line = node.start_position().row + 1;
                    violations.push(Violation::new(
                        "Optional chaining usado como funcao. Se for undefined, causara TypeError.",
                        line, RuleCategory::Correctness,
                    ).with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Use (obj?.method)?.() ou verifique antes de chamar."));
                }
            }
        }
        _ => {}
    }
}
