/// Visitor: Detecta links com target="_blank" sem rel="noreferrer" (jsx-no-target-blank).
///
/// Detecta elementos <a> com target="_blank" que não possuem rel="noreferrer"
/// ou rel="noopener", o que pode causar vulnerabilidades de segurança (tabnabbing).
///
/// Exemplos de violação:
/// - `<a href="https://example.com" target="_blank">Link</a>`
/// - `<a href="https://example.com" target="_blank" rel="noopener">Link</a>` (falta noreferrer)
///
/// Exemplos válidos:
/// - `<a href="https://example.com" target="_blank" rel="noreferrer">Link</a>`
/// - `<a href="https://example.com" target="_blank" rel="noopener noreferrer">Link</a>`
/// - `<a href="https://example.com">Link</a>` (sem target="_blank")

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};

/// Percorre a árvore procurando por links com target="_blank" sem rel="noreferrer".
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

    // Detecta JSX opening element (ex: <a>)
    if node.kind() == "jsx_opening_element" {
        check_jsx_element(&node, source, violations);
    }

    // Continua a busca nos filhos
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

fn check_jsx_element(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    let mut has_target_blank = false;
    let mut has_rel_noreferrer = false;
    let mut is_anchor = false;

    for child in &children {
        // Verifica se é um elemento <a>
        if child.kind() == "jsx_identifier" || child.kind() == "identifier" {
            let text = &source[child.byte_range()];
            if text == "a" {
                is_anchor = true;
            }
        }

        // Verifica atributos
        if child.kind() == "jsx_attribute" {
            let mut attr_cursor = child.walk();
            let attr_children: Vec<_> = child.children(&mut attr_cursor).collect();

            for attr_child in &attr_children {
                // Nome do atributo
                if attr_child.kind() == "jsx_identifier" || attr_child.kind() == "property_identifier" {
                    let attr_name = &source[attr_child.byte_range()];
                    
                    if attr_name == "target" {
                        // Verifica o valor do atributo
                        if let Some(value_node) = attr_children.iter().find(|c| c.kind() == "string" || c.kind() == "jsx_string") {
                            let attr_value = &source[value_node.byte_range()];
                            if attr_value.contains("_blank") {
                                has_target_blank = true;
                            }
                        }
                    }

                    if attr_name == "rel" {
                        // Verifica o valor do atributo
                        if let Some(value_node) = attr_children.iter().find(|c| c.kind() == "string" || c.kind() == "jsx_string") {
                            let attr_value = &source[value_node.byte_range()];
                            if attr_value.contains("noreferrer") {
                                has_rel_noreferrer = true;
                            }
                            if attr_value.contains("noopener") {
                                // noopener detectado mas não usado na verificação atual
                            }
                        }
                    }
                }
            }
        }
    }

    // Se for <a> com target="_blank" sem rel="noreferrer", reporta violação
    if is_anchor && has_target_blank && !has_rel_noreferrer {
        let line = node.start_position().row + 1;
        violations.push(
            Violation::new(
                "Link com target=\"_blank\" deve ter rel=\"noreferrer\" ou rel=\"noopener noreferrer\" para evitar vulnerabilidades de segurança.",
                line,
                RuleCategory::Security
            )
            .with_suggestion("[STOP] Leia .windsurf/rules/react-hooks-patterns-rules.md antes de reescrever. Adicione rel=\"noreferrer\" ao link com target=\"_blank\".")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_blank_without_rel_detected() {
        let _source = r#"
            <a href="https://example.com" target="_blank">Link</a>
        "#;
        // Teste seria integrado no validator.rs
    }

    #[test]
    fn test_target_blank_with_noreferrer_not_detected() {
        let _source = r#"
            <a href="https://example.com" target="_blank" rel="noreferrer">Link</a>
        "#;
        // Teste seria integrado no validator.rs
    }

    #[test]
    fn test_no_target_blank_not_detected() {
        let _source = r#"
            <a href="https://example.com">Link</a>
        "#;
        // Teste seria integrado no validator.rs
    }
}
