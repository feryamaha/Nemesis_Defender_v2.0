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
    if node.kind() == "return_statement" || node.kind() == "throw_statement"
        || node.kind() == "break_statement" || node.kind() == "continue_statement"
    {
        if is_inside_finally(&node) {
            let stmt_type = match node.kind() {
                "return_statement" => "return",
                "throw_statement" => "throw",
                "break_statement" => "break",
                _ => "continue",
            };
            let line = node.start_position().row + 1;
            violations.push(Violation::new(
                format!("{} dentro de bloco finally detectado. Isso suprime excecoes do try/catch.", stmt_type),
                line, RuleCategory::Correctness,
            ).with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Evite controle de fluxo em finally. Isso suprime excecoes do try."));
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

fn is_inside_finally(node: &tree_sitter::Node) -> bool {
    let mut parent = node.parent();
    while let Some(p) = parent {
        if p.kind() == "finally_clause" {
            return true;
        }
        if p.kind() == "function_expression" || p.kind() == "function_declaration"
            || p.kind() == "arrow_function" || p.kind() == "method_definition"
            || p.kind() == "program"
        {
            return false;
        }
        parent = p.parent();
    }
    false
}
