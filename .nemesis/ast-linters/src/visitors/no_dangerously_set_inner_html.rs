/// Visitor: Detecta uso de dangerouslySetInnerHTML (no-dangerously-set-inner-html).
///
/// Detecta atributos JSX `dangerouslySetInnerHTML` que expõem a XSS.
///
/// Exemplos de violação:
/// - `<div dangerouslySetInnerHTML={{ __html: 'child' }}></div>`
///
/// Exemplos válidos:
/// - `<div>safe content</div>`

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

    if node.kind() == "jsx_attribute" {
        check_jsx_attribute(&node, source, violations);
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

fn check_jsx_attribute(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "property_identifier" || child.kind() == "jsx_identifier" {
            let attr_name = &source[child.byte_range()];
            if attr_name == "dangerouslySetInnerHTML" {
                let line = node.start_position().row + 1;
                violations.push(
                    Violation::new(
                        "Uso de dangerouslySetInnerHTML detectado. Isso expõe a aplicação a ataques XSS (Cross-Site Scripting).",
                        line,
                        RuleCategory::Security,
                    )
                    .with_suggestion("[STOP] Leia .windsurf/rules/Conformidade.md antes de reescrever. Use DOMPurify.sanitize() ou reestruture sem HTML dinâmico.")
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
    fn test_dangerously_set_inner_html_detected() {
        let _source = r#"<div dangerouslySetInnerHTML={{ __html: 'child' }}></div>"#;
    }

    #[test]
    fn test_safe_element_not_detected() {
        let _source = r#"<div>safe content</div>"#;
    }
}
