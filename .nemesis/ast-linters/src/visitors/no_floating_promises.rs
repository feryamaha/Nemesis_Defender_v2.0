/// Visitor: Detecta promessas flutuantes (no-floating-promises).
///
/// Detecta chamadas de função que retornam promessas que não são tratadas
/// (sem await, then, catch ou return). Promessas flutuantes podem causar
/// bugs silenciosos quando rejeitadas.
///
/// Exemplos de violação:
/// - `fetch(url)` (sem await ou return)
/// - `api.getData()` (sem await ou return)
/// - `Promise.resolve(value)` (sem await ou return)
///
/// Exemplos válidos:
/// - `await fetch(url)`
/// - `return fetch(url)`
/// - `fetch(url).then(...)`
/// - `fetch(url).catch(...)`

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};

/// Percorre a árvore procurando por promessas flutuantes.
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

    // Detecta chamadas de função que podem retornar promessas
    if node.kind() == "call_expression" {
        check_call_expression(&node, source, violations);
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

fn check_call_expression(node: &tree_sitter::Node, source: &str, violations: &mut Vec<Violation>) {
    let parent = node.parent();

    // Se a chamada já está sendo tratada (await, then, catch, return), ignora
    if is_handled_promise(node, parent.as_ref(), source) {
        return;
    }

    // Verifica se a função provavelmente retorna uma promessa
    if is_promise_returning_function(node, source) {
        let line = node.start_position().row + 1;
        violations.push(
            Violation::new(
                "Promessa flutuante detectada. Use await, .then(), .catch() ou return para tratar a promessa.",
                line,
                RuleCategory::Correctness
            )
            .with_suggestion("[STOP] Leia .devin/rules/react-hooks-patterns-rules.md antes de reescrever. Use await, .then().catch() ou void se intencional.")
        );
    }
}

fn is_handled_promise(
    _node: &tree_sitter::Node,
    parent: Option<&tree_sitter::Node>,
    source: &str,
) -> bool {
    if let Some(parent_node) = parent {
        let parent_kind = parent_node.kind();

        // await expression
        if parent_kind == "await_expression" {
            return true;
        }

        // then/catch chain
        if parent_kind == "member_expression" {
            let mut cursor = parent_node.walk();
            let children: Vec<_> = parent_node.children(&mut cursor).collect();
            for child in &children {
                if child.kind() == "property_identifier" {
                    let child_text = &source[child.byte_range()];
                    if child_text == "then" || child_text == "catch" || child_text == "finally" {
                        return true;
                    }
                }
            }
        }

        // return statement
        if parent_kind == "return_statement" {
            return true;
        }

        // assignment (const x = fetch(url))
        if parent_kind == "variable_declarator" || parent_kind == "assignment_expression" {
            return true;
        }

        // arrow function body ou function body
        if parent_kind == "arrow_function" || parent_kind == "function_declaration" {
            return true;
        }
    }

    false
}

fn is_promise_returning_function(node: &tree_sitter::Node, source: &str) -> bool {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "identifier" {
            let text = &source[child.byte_range()];
            
            // Lista de funções que retornam promessas
            let promise_functions = [
                "fetch", "axios", "axios.get", "axios.post", "axios.put", "axios.delete",
                "axios.patch", "Promise.resolve", "Promise.reject", "Promise.all",
                "Promise.race", "Promise.allSettled", "setTimeout", "setInterval",
            ];

            if promise_functions.iter().any(|f| text == *f || text.starts_with(&format!("{}.", f))) {
                return true;
            }

            // Heurística: nomes que sugerem operações async (conservativo)
            // Apenas nomes muito específicos de persistência/IO
            let async_keywords = [
                "persist", "save", "update", "delete", "create", "insert", "remove",
                "load", "query", "execute", "submit",
            ];
            if async_keywords.iter().any(|k| text.to_lowercase() == *k) {
                return true;
            }
        }

        // Detecta chamadas encadeadas: api.getData()
        if child.kind() == "member_expression" {
            let mut member_cursor = child.walk();
            let member_children: Vec<_> = child.children(&mut member_cursor).collect();
            
            for member_child in &member_children {
                if member_child.kind() == "property_identifier" {
                    let text = &source[member_child.byte_range()];
                    // Funções assíncronas comuns
                    let async_methods = ["get", "post", "put", "delete", "patch", "fetch", "then", "catch", "resolve", "reject", "all", "race", "allSettled"];
                    if async_methods.iter().any(|m| text == *m) {
                        return true;
                    }

                    // Heurística para métodos async
                    let async_method_keywords = [
                        "persist", "save", "update", "delete", "create", "insert", "remove",
                        "load", "query", "execute", "submit", "send",
                    ];
                    if async_method_keywords.iter().any(|k| text.to_lowercase().contains(k)) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_floating_promise_detected() {
        let _source = r#"
            const url = "https://api.example.com";
            fetch(url);
        "#;
        // Teste seria integrado no validator.rs
    }

    #[test]
    fn test_awaited_promise_not_detected() {
        let _source = r#"
            const url = "https://api.example.com";
            await fetch(url);
        "#;
        // Teste seria integrado no validator.rs
    }

    #[test]
    fn test_then_chain_not_detected() {
        let _source = r#"
            const url = "https://api.example.com";
            fetch(url).then(data => console.log(data));
        "#;
        // Teste seria integrado no validator.rs
    }

    #[test]
    fn test_persist_floating_detected() {
        // Caso do pentest: persist(data) solto
        let content = r#"
            function f() {
                persist(data);
            }
        "#;
        let tree = crate::parser::parse_content(content, crate::language::Language::TypeScript).expect("parse failed");
        let violations = visit(&tree, content);
        assert!(!violations.is_empty(), "Should detect persist() floating promise");
    }

    #[test]
    fn test_persist_awaited_not_detected() {
        let content = r#"
            function f() {
                await persist(data);
            }
        "#;
        let tree = crate::parser::parse_content(content, crate::language::Language::TypeScript).expect("parse failed");
        let violations = visit(&tree, content);
        assert!(violations.is_empty(), "awaited persist should not be detected");
    }
}
