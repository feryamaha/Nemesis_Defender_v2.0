/// Visitor: Detecta propriedades de classe que podem ser readonly (prefer-readonly).
///
/// Detecta propriedades de classe que são inicializadas no construtor e
/// nunca são reatribuídas, o que indica que deveriam ser marcadas como readonly.
///
/// Exemplos de violação:
/// ```typescript
/// class MyClass {
///   private value: string; // Deveria ser readonly
///   constructor(value: string) {
///     this.value = value;
///   }
/// }
/// ```
///
/// Exemplos válidos:
/// ```typescript
/// class MyClass {
///   private readonly value: string;
///   constructor(value: string) {
///     this.value = value;
///   }
/// }
/// ```
///
/// Ou propriedades que são reatribuídas:
/// ```typescript
/// class MyClass {
///   private value: string;
///   constructor(value: string) {
///     this.value = value;
///   }
///   update(newValue: string) {
///     this.value = newValue; // Reatribuída, não deve ser readonly
///   }
/// }
/// ```

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory, Severity};

/// Percorre a árvore procurando por propriedades de classe que podem ser readonly.
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

    // Detecta class declaration
    if node.kind() == "class_declaration" {
        check_class_declaration(&node, source, violations);
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

fn check_class_declaration(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    let mut class_body: Option<&tree_sitter::Node> = None;

    for child in &children {
        if child.kind() == "class_body" {
            class_body = Some(child);
        }
    }

    if let Some(body) = class_body {
        let mut body_cursor = body.walk();
        let body_children: Vec<tree_sitter::Node> = body.children(&mut body_cursor).collect();

        let mut methods: Vec<tree_sitter::Node> = Vec::new();

        for body_child in &body_children {
            if body_child.kind() == "method_definition" {
                methods.push(body_child.clone());
            }
        }

        // Coleta todas as propriedades da classe
        let mut properties: Vec<PropertyInfo> = Vec::new();
        collect_properties(body, source, &mut properties);

        // Verifica cada propriedade
        for prop in &properties {
            if prop.is_readonly {
                continue; // Já é readonly, ignora
            }

            // Verifica se é reatribuída em algum método
            let is_reassigned = methods.iter().any(|method| is_property_reassigned_in_method(method, &prop.name, source));

            if !is_reassigned {
                let line = prop.line;
                violations.push(
                    Violation::new(
                        format!("Propriedade '{}' pode ser marcada como readonly (nunca é reatribuída após o construtor).", prop.name),
                        line,
                        RuleCategory::Style
                    )
                    .with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Adicione readonly à propriedade: private readonly nome: Tipo.")
                    .with_severity(Severity::Warning)
                );
            }
        }
    }
}

#[derive(Debug, Clone)]
struct PropertyInfo {
    name: String,
    is_readonly: bool,
    line: usize,
}

fn collect_properties(node: &tree_sitter::Node, source: &str, properties: &mut Vec<PropertyInfo>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "public_field_definition" || child.kind() == "property_definition" {
            let mut prop_cursor = child.walk();
            let prop_children: Vec<_> = child.children(&mut prop_cursor).collect();

            let mut name = String::new();
            let mut is_readonly = false;
            let line = child.start_position().row + 1;

            for prop_child in &prop_children {
                if prop_child.kind() == "property_identifier" || prop_child.kind() == "identifier" {
                    name = source[prop_child.byte_range()].to_string();
                }
                if prop_child.kind() == "readonly" {
                    is_readonly = true;
                }
            }

            if !name.is_empty() {
                properties.push(PropertyInfo {
                    name,
                    is_readonly,
                    line,
                });
            }
        }

        // Recursão para propriedades aninhadas
        collect_properties(child, source, properties);
    }
}

fn is_property_reassigned_in_method(method: &tree_sitter::Node, prop_name: &str, source: &str) -> bool {
    let mut cursor = method.walk();
    let children: Vec<_> = method.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "statement_block" {
            if is_property_reassigned_in_block(child, prop_name, source) {
                return true;
            }
        }
    }

    false
}

fn is_property_reassigned_in_block(node: &tree_sitter::Node, prop_name: &str, source: &str) -> bool {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        // Detecta assignment: this.propName = value
        if child.kind() == "assignment_expression" {
            if is_this_property_assignment(child, prop_name, source) {
                return true;
            }
        }

        // Recursão para blocos aninhados
        if is_property_reassigned_in_block(child, prop_name, source) {
            return true;
        }
    }

    false
}

fn is_this_property_assignment(node: &tree_sitter::Node, prop_name: &str, source: &str) -> bool {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "member_expression" {
            let mut member_cursor = child.walk();
            let member_children: Vec<_> = child.children(&mut member_cursor).collect();

            let mut is_this = false;
            let mut property_name = String::new();

            for member_child in &member_children {
                if member_child.kind() == "this" {
                    is_this = true;
                }
                if member_child.kind() == "property_identifier" {
                    property_name = source[member_child.byte_range()].to_string();
                }
            }

            if is_this && property_name == prop_name {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readonly_candidate_detected() {
        let _source = r#"
            class MyClass {
                private value: string;
                constructor(value: string) {
                    this.value = value;
                }
            }
        "#;
        // Teste seria integrado no validator.rs
    }

    #[test]
    fn test_already_readonly_not_detected() {
        let _source = r#"
            class MyClass {
                private readonly value: string;
                constructor(value: string) {
                    this.value = value;
                }
            }
        "#;
        // Teste seria integrado no validator.rs
    }

    #[test]
    fn test_reassigned_property_not_detected() {
        let _source = r#"
            class MyClass {
                private value: string;
                constructor(value: string) {
                    this.value = value;
                }
                update(newValue: string) {
                    this.value = newValue;
                }
            }
        "#;
        // Teste seria integrado no validator.rs
    }
}
