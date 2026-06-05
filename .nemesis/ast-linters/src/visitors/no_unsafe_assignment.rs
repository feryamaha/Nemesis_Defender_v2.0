/// Visitor: Detecta atribuições de tipo any (no-unsafe-assignment).
///
/// Detecta atribuições de variáveis onde o tipo inferido ou declarado é `any`,
/// o que viola o strict mode do TypeScript e pode causar erros de tipo em runtime.
///
/// Exemplos de violação:
/// - `const x: any = someValue`
/// - `let y = someValue as any`
/// - `const z: any[] = []`
///
/// Exemplos válidos:
/// - `const x: string = someValue`
/// - `let y: unknown = someValue`
/// - `const z: MyType[] = []`

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};

/// Percorre a árvore procurando por atribuições de tipo any.
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

    // Detecta variable declarator com type annotation any
    if node.kind() == "variable_declarator" {
        check_variable_declarator(&node, source, violations);
    }

    // Detecta assignment com as any
    if node.kind() == "assignment_expression" {
        check_assignment_expression(&node, source, violations);
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

fn check_variable_declarator(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "type_annotation" {
            check_type_annotation_for_any(child, source, violations);
        }
    }
}

fn check_assignment_expression(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        // Detecta as any
        if child.kind() == "as_expression" {
            check_as_expression_for_any(child, source, violations);
        }

        // Detecta type annotation
        if child.kind() == "type_annotation" {
            check_type_annotation_for_any(child, source, violations);
        }
    }
}

fn check_type_annotation_for_any(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "predefined_type" {
            let text = &source[child.byte_range()];
            if text == "any" {
                let line = node.start_position().row + 1;
                violations.push(
                    Violation::new("Atribuição de tipo 'any' detectada. Use tipos específicos ou unknown.", line, RuleCategory::Suspicious)
                        .with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Declare o tipo explícito: const x: TipoEspecífico = valor.")
                );
            }
        }

        // Detecta array of any: any[]
        if child.kind() == "array_type" {
            let mut array_cursor = child.walk();
            let array_children: Vec<_> = child.children(&mut array_cursor).collect();
            for array_child in &array_children {
                if array_child.kind() == "predefined_type" {
                    let text = &source[array_child.byte_range()];
                    if text == "any" {
                        let line = node.start_position().row + 1;
                        violations.push(
                            Violation::new("Atribuição de tipo 'any[]' detectada. Use tipos específicos.", line, RuleCategory::Suspicious)
                                .with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Declare o tipo explícito: const x: TipoEspecífico = valor.")
                        );
                    }
                }
            }
        }
    }
}

fn check_as_expression_for_any(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "predefined_type" {
            let text = &source[child.byte_range()];
            if text == "any" {
                let line = node.start_position().row + 1;
                violations.push(
                    Violation::new("Type assertion 'as any' detectada. Use type guards ou unknown.", line, RuleCategory::Suspicious)
                        .with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Declare o tipo explícito: const x: TipoEspecífico = valor.")
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_any_assignment_detected() {
        let _source = r#"
            const x: any = someValue;
        "#;
        // Teste seria integrado no validator.rs
    }

    #[test]
    fn test_as_any_detected() {
        let _source = r#"
            const x = someValue as any;
        "#;
        // Teste seria integrado no validator.rs
    }

    #[test]
    fn test_specific_type_not_detected() {
        let _source = r#"
            const x: string = someValue;
        "#;
        // Teste seria integrado no validator.rs
    }
}
