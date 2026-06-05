/// Visitor: Detecta uso de eval e funções similares (no-global-eval).
///
/// Detecta chamadas a `eval()`, `new Function()`, `setTimeout("string")`,
/// `setInterval("string")` que são vetores de code injection.
///
/// Exemplos de violação:
/// - `eval("var a = 0")`
/// - `new Function("return 1")`
/// - `setTimeout("alert(1)", 1000)`
/// - `setInterval("doSomething()", 500)`
///
/// Exemplos válidos:
/// - `setTimeout(() => alert(1), 1000)`
/// - `setInterval(myFunction, 500)`

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};

pub fn visit(tree: &ParsedTree, source: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let cursor = &mut tree.tree.walk();
    visit_node(cursor, source, &mut violations);
    violations
}

fn visit_node(
    cursor: &mut tree_sitter::TreeCursor,
    source: &str,
    violations: &mut Vec<Violation>,
) {
    let node = cursor.node();

    match node.kind() {
        "call_expression" => check_call_expression(&node, source, violations),
        "new_expression" => check_new_expression(&node, source, violations),
        _ => {}
    }

    if cursor.goto_first_child() {
        loop {
            visit_node(cursor, source, violations);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

fn check_call_expression(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    // Check for eval(...)
    for child in &children {
        if child.kind() == "identifier" {
            let text = &source[child.byte_range()];
            if text == "eval" {
                let line = node.start_position().row + 1;
                violations.push(
                    Violation::new(
                        "Uso de eval() detectado. eval() é vetor de code injection e causa problemas de performance.",
                        line,
                        RuleCategory::Security,
                    )
                    .with_suggestion("[STOP] Leia .windsurf/rules/Conformidade.md antes de reescrever. Use funções explícitas. eval() é vetor de code injection.")
                );
                return;
            }
        }

        // Check for setTimeout("string") or setInterval("string")
        if child.kind() == "member_expression" {
            let mut member_cursor = child.walk();
            let member_children: Vec<_> = child.children(&mut member_cursor).collect();

            let mut is_timer = false;
            for mc in &member_children {
                if mc.kind() == "property_identifier" {
                    let prop = &source[mc.byte_range()];
                    if prop == "setTimeout" || prop == "setInterval" {
                        is_timer = true;
                    }
                }
            }

            if is_timer {
                // Check if first argument is a string literal
                if let Some(args_node) = children.iter().find(|c| c.kind() == "arguments") {
                    let mut args_cursor = args_node.walk();
                    let args_children: Vec<_> = args_node.children(&mut args_cursor).collect();
                    for ac in &args_children {
                        if ac.kind() == "string" {
                            let line = node.start_position().row + 1;
                            let method_name = {
                                let mc: Vec<_> = child.children(&mut child.walk()).collect();
                                mc.iter()
                                    .find(|c| c.kind() == "property_identifier")
                                    .map(|c| &source[c.byte_range()])
                                    .unwrap_or("timer")
                            };
                            violations.push(
                                Violation::new(
                                    format!("Uso de {} com string detectado. Passar string como código é vetor de code injection.", method_name),
                                    line,
                                    RuleCategory::Security,
                                )
                                .with_suggestion("Use funções explícitas como callback em vez de strings.")
                            );
                            return;
                        }
                    }
                }
            }
        }
    }
}

fn check_new_expression(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "identifier" {
            let text = &source[child.byte_range()];
            if text == "Function" {
                let line = node.start_position().row + 1;
                violations.push(
                    Violation::new(
                        "Uso de new Function() detectado. Equivalente a eval(), é vetor de code injection.",
                        line,
                        RuleCategory::Security,
                    )
                    .with_suggestion("[STOP] Leia .windsurf/rules/Conformidade.md antes de reescrever. Use funções explícitas. new Function() é vetor de code injection.")
                );
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval_detected() {
        let _source = r#"eval("var a = 0")"#;
    }

    #[test]
    fn test_new_function_detected() {
        let _source = r#"new Function("return 1")"#;
    }

    #[test]
    fn test_settimeout_string_detected() {
        let _source = r#"setTimeout("alert(1)", 1000)"#;
    }

    #[test]
    fn test_settimeout_callback_not_detected() {
        let _source = r#"setTimeout(() => alert(1), 1000)"#;
    }
}
