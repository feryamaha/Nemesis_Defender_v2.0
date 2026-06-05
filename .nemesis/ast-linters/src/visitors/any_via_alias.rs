/// Visitor: Detecta `any` via alias de tipo.
///
/// Regex detecta `: any` direto, mas não pega:
/// - `type X = any` (alias de tipo)
/// - `interface X { prop: any }` (propriedade de interface)
/// - `type X<T = any>` (type parameter default)
///
/// Este visitor percorre a árvore tree-sitter procurando por nós `type_alias`
/// ou `interface_declaration` cujo tipo resolva para `any`.

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};

/// Percorre a árvore procurando por usos de `any` via alias.
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

    // Detecta type alias cujo valor é `any`
    if node.kind() == "type_alias_declaration" {
        check_type_alias_for_any(&node, source, violations);
    }

    // Detecta interface com propriedade `any`
    if node.kind() == "interface_declaration" {
        check_interface_for_any(&node, source, violations);
    }

    // Detecta type parameters com default `any`
    if node.kind() == "type_parameter" {
        check_type_parameter_for_any(&node, source, violations);
    }

    // Detecta `any` em type annotation de parâmetro: `props: any`
    if node.kind() == "required_parameter" || node.kind() == "optional_parameter" {
        check_parameter_type(&node, source, violations);
    }

    // Detecta `any` em type arguments: `useState<any>`, `useState<SomeType<any>>`
    if node.kind() == "type_arguments" {
        check_type_arguments_for_any(&node, source, violations);
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

fn check_parameter_type(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "type_annotation" {
            let mut ta_cursor = child.walk();
            let ta_children: Vec<_> = child.children(&mut ta_cursor).collect();
            for ta_child in &ta_children {
                if ta_child.kind() == "predefined_type" && is_any_type(ta_child, source) {
                    let line = node.start_position().row + 1;
                    violations.push(
                        Violation::new("Parâmetro tipado como 'any'. Declare tipos corretos.", line, RuleCategory::Suspicious)
                            .with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Use unknown, generics <T> ou tipo específico em src/types/.")
                    );
                }
            }
        }
    }
}

fn check_type_arguments_for_any(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "predefined_type" && is_any_type(child, source) {
            let line = child.start_position().row + 1;
            violations.push(
                Violation::new("Tipo 'any' utilizado como argumento de tipo (ex: useState<any>). Declare tipos corretos.", line, RuleCategory::Suspicious)
                    .with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Use unknown, generics <T> ou tipo específico em src/types/.")
            );
        }
        // Suporta aninhamento: SomeType<any>
        if child.kind() == "type_arguments" {
            check_type_arguments_for_any(child, source, violations);
        }
    }
}

fn check_type_alias_for_any(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "predefined_type" && is_any_type(child, source) {
            let line = node.start_position().row + 1;
            let name = node_text(node, source).unwrap_or_else(|| "<unknown>".to_string());
            violations.push(
                Violation::new(format!("Tipo 'any' utilizado através de type alias: \"{}\". Declare tipos corretos.", name), line, RuleCategory::Suspicious)
                    .with_suggestion("Use unknown, generics <T> ou tipo específico em src/types/")
            );
        }
    }
}

fn check_interface_for_any(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "interface_body" {
            let mut body_cursor = child.walk();
            let body_children: Vec<_> = child.children(&mut body_cursor).collect();

            for prop in &body_children {
                if prop.kind() == "property_signature" {
                    check_property_type(prop, source, violations);
                }
            }
        }
    }
}

fn check_property_type(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "type_annotation" {
            let mut ta_cursor = child.walk();
            let ta_children: Vec<_> = child.children(&mut ta_cursor).collect();
            for ta_child in &ta_children {
                if ta_child.kind() == "predefined_type" && is_any_type(ta_child, source) {
                    let line = node.start_position().row + 1;
                    violations.push(
                        Violation::new("Propriedade de interface tipada como 'any'. Declare tipos corretos.", line, RuleCategory::Suspicious)
                            .with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Use unknown, generics <T> ou tipo específico em src/types/.")
                    );
                }
            }
        }
    }
}

fn check_type_parameter_for_any(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "type_annotation" {
            let mut ta_cursor = child.walk();
            let ta_children: Vec<_> = child.children(&mut ta_cursor).collect();
            for ta_child in &ta_children {
                if ta_child.kind() == "predefined_type" && is_any_type(ta_child, source) {
                    let line = node.start_position().row + 1;
                    violations.push(
                        Violation::new("Type parameter com default 'any'. Declare tipos corretos.", line, RuleCategory::Suspicious)
                            .with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Use unknown, generics <T> ou tipo específico em src/types/.")
                    );
                }
            }
        }
    }
}

fn is_any_type(node: &tree_sitter::Node, source: &str) -> bool {
    if node.kind() == "predefined_type" {
        if let Some(text) = node.utf8_text(source.as_bytes()).ok() {
            return text.trim() == "any";
        }
    }
    false
}

fn node_text(node: &tree_sitter::Node, source: &str) -> Option<String> {
    node.utf8_text(source.as_bytes())
        .map(|t| t.lines().next().unwrap_or(t).trim().to_string())
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_content;
    use crate::language::Language;

    fn check(content: &str) -> Vec<Violation> {
        let tree = parse_content(content, Language::TypeScript).expect("parse failed");
        visit(&tree, content)
    }

    #[test]
    fn test_detects_type_alias_any() {
        let violations = check("type X = any;");
        assert!(!violations.is_empty(), "Should detect type alias any");
        assert!(violations[0].message.contains("any"));
    }

    #[test]
    fn test_detects_interface_property_any() {
        let violations = check("interface X { prop: any; }");
        assert!(!violations.is_empty(), "Should detect interface property any");
    }

    #[test]
    fn test_no_violation_for_proper_type() {
        let violations = check("type X = string;");
        assert!(violations.is_empty(), "Should not flag proper types");
    }

    #[test]
    fn test_no_violation_for_unknown() {
        let violations = check("type X = Record<string, unknown>;");
        assert!(violations.is_empty(), "Should not flag unknown");
    }
}
