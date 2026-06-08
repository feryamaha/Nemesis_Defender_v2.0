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
    if node.kind() == "return_statement" {
        check_return_statement(&node, source, violations);
    }
    if cursor.goto_first_child() {
        loop {
            visit_node(cursor, source, violations);
            if !cursor.goto_next_sibling() { break; }
        }
        cursor.goto_parent();
    }
}

fn check_return_statement(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    let has_value = children.iter().any(|c| {
        !matches!(c.kind(), "return" | ";" | "async")
    });
    if !has_value { return; }
    let mut parent = node.parent();
    while let Some(p) = parent {
        if p.kind() == "function_declaration" || p.kind() == "function_expression"
            || p.kind() == "arrow_function" || p.kind() == "method_definition"
        {
            let text = &source[p.byte_range()];
            if text.contains(": void") {
                let line = node.start_position().row + 1;
                violations.push(Violation::new(
                    "Retorno de valor em funcao com tipo void. Funcoes void nao devem retornar valor.",
                    line, RuleCategory::Correctness,
                ).with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Remova o valor de retorno ou mude o tipo da funcao."));
            }
            return;
        }
        parent = p.parent();
    }
}
