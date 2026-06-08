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
    match node.kind() {
        "if_statement" | "while_statement" | "do_statement" => {
            check_condition(&node, source, violations);
        }
        "for_statement" => {
            check_for_condition(&node, source, violations);
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

fn is_constant_literal(text: &str) -> bool {
    let t = text.trim();
    t == "true" || t == "false" || t == "null" || t == "undefined"
        || (t.starts_with("'") && t.ends_with("'"))
        || (t.starts_with("\"") && t.ends_with("\""))
        || t.parse::<f64>().is_ok()
}

/// Look backwards in the same statement_block for a const/let assignment of `var_name`.
/// Returns the assigned text if found.
fn find_const_assignment(block: &tree_sitter::Node, var_name: &str, source: &str) -> Option<String> {
    let mut cursor = block.walk();
    let children: Vec<_> = block.children(&mut cursor).collect();
    for child in &children {
        if child.kind() == "lexical_declaration" || child.kind() == "variable_declaration" {
            let mut dc = child.walk();
            let dcs: Vec<_> = child.children(&mut dc).collect();
            // Pattern: const/let x = <value>
            for dchild in &dcs {
                if dchild.kind() == "variable_declarator" {
                    let mut vc = dchild.walk();
                    let vcs: Vec<_> = dchild.children(&mut vc).collect();
                    if vcs.len() >= 3 {
                        let decl_name = &source[vcs[0].byte_range()];
                        if decl_name == var_name {
                            // vcs[2] is the value (after =)
                            if vcs.len() > 2 {
                                return Some(source[vcs[2].byte_range()].to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Check if a binary_expression with === or !== is a tautology/contradiction.
fn is_tautology_binary(node: &tree_sitter::Node, source: &str, condition_node: &tree_sitter::Node) -> bool {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    if children.len() < 3 { return false; }
    let left_text = &source[children[0].byte_range()];
    let op_text = &source[children[1].byte_range()];
    let right_text = &source[children[2].byte_range()];

    if op_text != "===" && op_text != "!==" { return false; }

    // Both sides are identical literals: 5 === 5, "str" === "str"
    if is_constant_literal(left_text) && is_constant_literal(right_text) && left_text == right_text {
        return true;
    }

    // Identifier compared to literal: check if identifier was assigned that literal
    if children[0].kind() == "identifier" && is_constant_literal(right_text) {
        if is_const_assigned(condition_node, left_text, right_text, source) {
            return true;
        }
    }
    if children[2].kind() == "identifier" && is_constant_literal(left_text) {
        if is_const_assigned(condition_node, right_text, left_text, source) {
            return true;
        }
    }

    false
}

/// Check if a const assignment exists in the scope block for var_name == value.
fn is_const_assigned(scope_node: &tree_sitter::Node, var_name: &str, value: &str, source: &str) -> bool {
    // scope_node is the if_statement/while_statement etc.
    // Walk up to find the statement_block
    let mut current = scope_node.parent();
    while let Some(parent) = current {
        if parent.kind() == "statement_block" {
            return find_const_assignment(&parent, var_name, source).as_deref() == Some(value);
        }
        if parent.kind() == "program" || parent.kind() == "function_declaration"
            || parent.kind() == "arrow_function" || parent.kind() == "function_expression" {
            // Search children for statement_block
            let mut c = parent.walk();
            let ch: Vec<_> = parent.children(&mut c).collect();
            for child in &ch {
                if child.kind() == "statement_block" {
                    return find_const_assignment(child, var_name, source).as_deref() == Some(value);
                }
            }
            return false;
        }
        current = parent.parent();
    }
    false
}

fn check_condition(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    for child in &children {
        if child.kind() == "parenthesized_expression" {
            let mut pc = child.walk();
            let pcs: Vec<_> = child.children(&mut pc).collect();
            for pc in &pcs {
                let text = &source[pc.byte_range()];
                if is_constant_literal(text) {
                    let line = node.start_position().row + 1;
                    violations.push(Violation::new(
                        "Condicao constante detectada. Revise a logica.",
                        line, RuleCategory::Correctness,
                    ).with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Substitua por uma condicao que dependa de valores em runtime."));
                    return;
                }
                // Check for binary_expression tautologies like x === 5 where const x = 5
                if pc.kind() == "binary_expression" {
                    if is_tautology_binary(pc, source, node) {
                        let line = node.start_position().row + 1;
                        violations.push(Violation::new(
                            "Condicao constante detectada (comparacao tautologica). Revise a logica.",
                            line, RuleCategory::Correctness,
                        ).with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Substitua por uma condicao que dependa de valores em runtime."));
                        return;
                    }
                }
            }
        }
    }
}

fn check_for_condition(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    let semicolons: Vec<_> = children.iter().filter(|c| c.kind() == ";").collect();
    if semicolons.len() >= 2 {
        let test_idx = children.iter().position(|c| c.kind() == ";").unwrap_or(0);
        if test_idx + 1 < children.len() {
            let test_node = &children[test_idx + 1];
            let text = &source[test_node.byte_range()];
            if is_constant_literal(text) && text != "true" {
                let line = node.start_position().row + 1;
                violations.push(Violation::new(
                    "Condicao constante em for detectada.",
                    line, RuleCategory::Correctness,
                ).with_suggestion("[STOP] Leia .devin/rules/typescript-typing-convention.md antes de reescrever. Revise a condicao do loop."));
            }
        }
    }
}
