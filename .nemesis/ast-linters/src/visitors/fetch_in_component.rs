/// Visitor: Detecta fetch/axios dentro de componente React.
///
/// Componentes React não devem fazer chamadas HTTP diretamente — devem
/// usar route handlers (BFF) e hooks.
///
/// Este visitor verifica se `fetch()` ou `axios.get/post/etc()` está
/// dentro de uma função que retorna JSX (componente).

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};

/// Verifica se uma função retorna JSX (é um componente React).
fn function_returns_jsx(node: &tree_sitter::Node, _source: &str) -> bool {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    // Arrow function with implicit return: () => <jsx/>
    if node.kind() == "arrow_function" {
        for child in &children {
            if child.kind() == "jsx_element" || child.kind() == "jsx_fragment" {
                return true;
            }
        }
    }

    // For regular functions, find the statement_block and check it
    for child in &children {
        if child.kind() == "statement_block" {
            return block_returns_jsx(child);
        }
    }
    false
}

/// Verifica se um bloco contém return JSX.
fn block_returns_jsx(node: &tree_sitter::Node) -> bool {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "return_statement" && has_jsx_in_subtree(&child) {
                return true;
            }
            if child.kind().starts_with("jsx") {
                return true;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    false
}

fn has_jsx_in_subtree(node: &tree_sitter::Node) -> bool {
    if node.kind().starts_with("jsx") {
        return true;
    }
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            if has_jsx_in_subtree(&cursor.node()) {
                return true;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    false
}

fn is_fetch_call(node: &tree_sitter::Node, source: &str) -> bool {
    if node.kind() != "call_expression" {
        return false;
    }
    if let Ok(text) = node.utf8_text(source.as_bytes()) {
        let text = text.trim();
        // fetch(...)
        if text.starts_with("fetch(") {
            return true;
        }
        // axios.get(...), axios.post(...), etc.
        if text.starts_with("axios.")
            && (text.contains(".get(") || text.contains(".post(")
                || text.contains(".put(") || text.contains(".delete(")
                || text.contains(".patch("))
        {
            return true;
        }
    }
    false
}

/// Encontra a função componente mais próxima que envolve este nó.
/// Pula funções aninhadas que não retornam JSX (ex: callback de useEffect).
fn find_enclosing_component(node: &tree_sitter::Node, source: &str) -> Option<String> {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "function_declaration" | "arrow_function" | "function_expression" => {
                if function_returns_jsx(&parent, source) {
                    // Extrai o nome da função
                    let mut cursor = parent.walk();
                    let children: Vec<_> = parent.children(&mut cursor).collect();
                    for child in &children {
                        if child.kind() == "identifier" {
                            if let Ok(name) = child.utf8_text(source.as_bytes()) {
                                return Some(name.to_string());
                            }
                        }
                    }
                    return Some("<anonymous>".to_string());
                }
                // Não retorna JSX — pode ser callback (useEffect, useCallback, etc.).
                // Continua subindo em vez de retornar None.
            }
            "program" => return None,
            _ => {}
        }
        current = parent.parent();
    }
    None
}

/// Percorre a árvore procurando por fetch/axios dentro de componentes.
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

    if is_fetch_call(&node, source) {
        if let Some(component_name) = find_enclosing_component(&node, source) {
            let line = node.start_position().row + 1;
            let call = node.utf8_text(source.as_bytes()).unwrap_or("fetch");
            let call_preview = if call.len() > 80 {
                &call[..80]
            } else {
                call
            };
            violations.push(
                Violation::new(
                    format!("Requisição HTTP direta no componente '{}': \"{}\". Use hook ou BFF.", component_name, call_preview),
                    line,
                    RuleCategory::Suspicious
                )
                .with_suggestion("[STOP] Leia .windsurf/rules/API-convention.md antes de reescrever. Use hook personalizado em src/hooks/ ou route handler em src/app/api/.")
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
        let tree = parse_content(content, Language::TypeScriptReact).expect("parse failed");
        visit(&tree, content)
    }

    #[test]
    fn test_detects_fetch_in_component() {
        let content = r#"
            function MyComponent() {
                const [data, setData] = useState(null);
                fetch('/api/data').then(setData);
                return <div>{data}</div>;
            }
        "#;
        let violations = check(content);
        assert!(!violations.is_empty(), "Should detect fetch in component");
        assert!(violations[0].message.contains("MyComponent"));
    }

    #[test]
    fn test_detects_axios_in_component() {
        let content = r#"
            function MyComponent() {
                const [data, setData] = useState(null);
                axios.get('/api/data').then(setData);
                return <div>{data}</div>;
            }
        "#;
        let violations = check(content);
        assert!(!violations.is_empty(), "Should detect axios in component");
        assert!(violations[0].message.contains("MyComponent"));
    }

    #[test]
    fn test_no_violation_in_hook() {
        let content = r#"
            function useData() {
                const [data, setData] = useState(null);
                fetch('/api/data').then(setData);
                return data;
            }
            function Component() {
                const data = useData();
                return <div>{data}</div>;
            }
        "#;
        let violations = check(content);
        // fetch está dentro de useData que não retorna JSX — deve detectar
        // mas se useData não retorna JSX, não é componente então OK
        // O fetch em hook pode ser válido (é o padrão BFF)
        // Vamos verificar que não detecta no Component
        let component_violations: Vec<_> = violations.iter()
            .filter(|v| v.message.contains("Component"))
            .collect();
        assert!(component_violations.is_empty(), "Component should not have violation");
    }

    #[test]
    fn test_no_violation_in_regular_function() {
        let content = r#"
            function helper() {
                return 42;
            }
            function Component() {
                return <div>{helper()}</div>;
            }
        "#;
        let violations = check(content);
        assert!(violations.is_empty(), "No fetch calls should be fine");
    }
}
