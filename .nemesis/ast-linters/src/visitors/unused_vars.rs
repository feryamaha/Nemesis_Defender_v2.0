/// Visitor: Detecta variáveis declaradas mas não utilizadas.
///
/// Percorre escopos de função/bloco, coleta declarações (const/let/var)
/// e verifica se cada variável é referenciada em algum lugar do mesmo escopo.
///
/// Exclui:
/// - Variáveis com prefixo `_` (intencionalmente não usadas)
/// - Exportações
/// - Declarações de tipo (type/interface)

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};
use std::collections::HashSet;

/// Representa uma declaração de variável.
#[derive(Debug)]
struct VarDecl {
    name: String,
    line: usize,
    is_exported: bool,
}

/// Coleta declarações de variáveis em um escopo.
fn collect_declarations(node: &tree_sitter::Node, source: &str) -> Vec<VarDecl> {
    let mut decls = Vec::new();
    let mut cursor = node.walk();

    // Para statement_block, pega os children que não são pontuação
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        match child.kind() {
            "lexical_declaration" | "variable_declaration" => {
                let mut child_cursor = child.walk();
                let var_children: Vec<_> = child.children(&mut child_cursor).collect();
                for var_child in &var_children {
                    if var_child.kind() == "variable_declarator" {
                        let mut vc = var_child.walk();
                        let decl_parts: Vec<_> = var_child.children(&mut vc).collect();
                        for part in &decl_parts {
                            if part.kind() == "identifier" {
                                if let Ok(name) = part.utf8_text(source.as_bytes()) {
                                    let name = name.to_string();
                                    if !name.starts_with('_') {
                                        let is_exported = node_text_safe(node, source)
                                            .map(|t| t.starts_with("export"))
                                            .unwrap_or(false);
                                        decls.push(VarDecl {
                                            name,
                                            line: part.start_position().row + 1,
                                            is_exported,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    decls
}

/// Coleta todos os identificadores usados em um nó (referências, não declarações).
fn collect_references(node: &tree_sitter::Node, source: &str, decl_names: &HashSet<String>) -> HashSet<String> {
    let mut refs = HashSet::new();
    collect_references_recursive(node, source, decl_names, &mut refs);
    refs
}

fn collect_references_recursive(
    node: &tree_sitter::Node,
    source: &str,
    decl_names: &HashSet<String>,
    refs: &mut HashSet<String>,
) {
    // Ignora declarações (não conta como referência)
    if node.kind() == "variable_declarator" {
        let mut c = node.walk();
        let children: Vec<_> = node.children(&mut c).collect();
        for child in &children {
            if child.kind() != "identifier" {
                collect_references_recursive(child, source, decl_names, refs);
            } else if is_value_context(child, node) {
                if let Ok(name) = child.utf8_text(source.as_bytes()) {
                    if decl_names.contains(name) {
                        refs.insert(name.to_string());
                    }
                }
            }
        }
        return;
    }

    if node.kind() == "identifier" {
        if let Ok(name) = node.utf8_text(source.as_bytes()) {
            if decl_names.contains(name) && !matches!(name, "true" | "false" | "undefined" | "null") {
                refs.insert(name.to_string());
            }
        }
        return;
    }

    // Use children collection to avoid shared cursor state
    let mut child_cursor = node.walk();
    let children: Vec<_> = node.children(&mut child_cursor).collect();
    for child in &children {
        collect_references_recursive(child, source, decl_names, refs);
    }
}

/// Verifica se um identifier está em contexto de valor (após `=`) no declarator.
fn is_value_context(id_node: &tree_sitter::Node, declarator: &tree_sitter::Node) -> bool {
    let mut cursor = declarator.walk();
    let children: Vec<_> = declarator.children(&mut cursor).collect();

    // Encontra a posição do `=` no declarator
    let eq_pos = children.iter().position(|c| c.kind() == "=");

    match eq_pos {
        Some(pos) => {
            // Verifica se o identifier está depois do `=`
            let id_start = id_node.start_byte();
            if let Some(eq_node) = children.get(pos) {
                id_start > eq_node.end_byte()
            } else {
                false
            }
        }
        None => false,
    }
}

fn node_text_safe(node: &tree_sitter::Node, source: &str) -> Option<String> {
    node.utf8_text(source.as_bytes()).map(|s| s.to_string()).ok()
}

fn has_unused_vars(node: &tree_sitter::Node, source: &str) -> Vec<VarDecl> {
    // Encontra o statement_block se não estivermos já em um
    let body = if node.kind() == "statement_block" {
        *node
    } else {
        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();
        let block = children.iter().find(|c| c.kind() == "statement_block");
        match block {
            Some(b) => *b,
            None => return vec![],
        }
    };

    let decls = collect_declarations(&body, source);
    if decls.is_empty() {
        return vec![];
    }

    let decl_names: HashSet<String> = decls.iter().map(|d| d.name.clone()).collect();
    let refs = collect_references(&body, source, &decl_names);

    decls.into_iter()
        .filter(|d| !d.is_exported && !refs.contains(&d.name))
        .collect()
}

/// Percorre a árvore procurando por escopos de função e bloco.
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

    // Analisa escopos de função e o escopo global (program)
    if matches!(node.kind(), "function_declaration" | "arrow_function" | "function_expression" | "method_definition" | "program") {
        let unused = has_unused_vars(&node, source);
        for var in unused {
            violations.push(
                Violation::new(
                    format!("Variável '{}' declarada mas não utilizada (linha {}). Remova ou renomeie com prefixo '_'.", var.name, var.line),
                    var.line,
                    RuleCategory::Correctness
                )
                .with_suggestion("[STOP] Leia .windsurf/rules/typescript-typing-convention.md antes de reescrever. Remova a variável ou prefixe com _ se for intencional.")
            );
        }
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
    fn test_detects_unused_var() {
        let content = r#"
            function foo() {
                const x = 1;
                const y = 2;
                console.log(x);
            }
        "#;
        let violations = check(content);
        assert!(!violations.is_empty(), "Should detect unused var");
        assert!(violations[0].message.contains("y"), "Should mention y");
    }

    #[test]
    fn test_no_violation_for_used_var() {
        let content = r#"
            function foo() {
                const x = 1;
                console.log(x);
            }
        "#;
        let violations = check(content);
        assert!(violations.is_empty(), "Used vars should be fine");
    }

    #[test]
    fn test_no_violation_for_underscore_prefix() {
        let content = r#"
            function foo() {
                const _x = 1;  // intentionally unused
                const y = 2;
                console.log(y);
            }
        "#;
        let violations = check(content);
        assert!(violations.is_empty(), "Underscore prefix should skip");
    }
}

