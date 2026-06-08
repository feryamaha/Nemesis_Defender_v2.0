/// Visitor: Detecta hooks condicionais.
///
/// React exige que hooks (useState, useEffect, useCallback, etc.) sejam
/// chamados na raiz do componente, nunca dentro de condicionais.
///
/// Este visitor percorre a árvore sintática procurando por chamadas de hook
/// que estejam dentro de blocos if, else, for, while, switch, ou após
/// early return.

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};

const HOOK_NAMES: &[&str] = &[
    "useState",
    "useEffect",
    "useCallback",
    "useMemo",
    "useRef",
    "useContext",
    "useReducer",
    "useImperativeHandle",
    "useLayoutEffect",
    "useDebugValue",
    "useTransition",
    "useDeferredValue",
    "useSyncExternalStore",
    "useInsertionEffect",
];

/// Verifica se um nó ou seus ancestrais estão dentro de um bloco condicional.
fn is_inside_conditional(node: &tree_sitter::Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "if_statement" | "else_clause" | "for_statement" | "while_statement"
            | "do_statement" | "switch_case" | "switch_body" | "conditional_expression" => {
                return true;
            }
            "function_declaration" | "arrow_function" | "function_expression"
            | "method_definition" | "program" | "statement_block" => {
                // Não cruza fronteira de função — hooks em outra função são ok
                // Mas statement_block dentro da mesma função não interrompe a busca
                if parent.kind() != "statement_block" {
                    return false;
                }
            }
            _ => {}
        }
        current = parent.parent();
    }
    false
}

/// Verifica recursivamente se um nó contém um return_statement.
fn contains_return(node: &tree_sitter::Node) -> bool {
    if node.kind() == "return_statement" {
        return true;
    }
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    for child in &children {
        if contains_return(child) {
            return true;
        }
    }
    false
}

/// Verifica se um hook está após um early return.
fn is_after_early_return(node: &tree_sitter::Node, _source: &str) -> bool {
    let mut current = node.parent();
    // Sobe até o bloco que contém o hook
    while let Some(parent) = current {
        if parent.kind() == "statement_block" {
            // Verifica se há um `return` antes do hook neste bloco
            let hook_start = node.start_position().row;
            let mut block_cursor = parent.walk();
            if block_cursor.goto_first_child() {
                loop {
                    let child = block_cursor.node();
                    if child.start_position().row >= hook_start {
                        break;
                    }
                    if child.kind() == "return_statement" || (child.kind() == "if_statement" && contains_return(&child)) {
                        return true;
                    }
                    if !block_cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
            return false;
        }
        if matches!(parent.kind(), "function_declaration" | "arrow_function" | "function_expression" | "program") {
            return false;
        }
        current = parent.parent();
    }
    false
}

/// Verifica se um nome de função é um hook do React.
fn is_hook_name(name: &str) -> bool {
    HOOK_NAMES.contains(&name)
}

/// Percorre a árvore procurando por hooks condicionais.
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

    // Procura por chamadas de função que são hooks
    if node.kind() == "call_expression" {
        if let Some(func) = get_called_function_name(&node, source) {
            if is_hook_name(&func) {
                let line = node.start_position().row + 1;
                let in_conditional = is_inside_conditional(&node);
                let after_return = is_after_early_return(&node, source);

                if in_conditional || after_return {
                    let reason = if in_conditional {
                        "dentro de bloco condicional"
                    } else {
                        "após early return"
                    };
                    violations.push(
                        Violation::new(
                            format!("Hook condicional detectado: '{}' chamado {}. React exige hooks na raiz do componente.", func, reason),
                            line,
                            RuleCategory::Correctness
                        )
                        .with_suggestion("[STOP] Leia .devin/rules/react-hooks-patterns-rules.md antes de reescrever. Mova hooks para o topo do componente, antes de qualquer return. Consulte: https://react.dev/reference/rules/rules-of-hooks")
                    );
                }
            }
        }
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

fn get_called_function_name(node: &tree_sitter::Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "identifier" || child.kind() == "property_identifier" {
            return child.utf8_text(source.as_bytes()).ok().map(|s| s.to_string());
        }
        // member_expression: foo.useState
        if child.kind() == "member_expression" {
            let mem_text = child.utf8_text(source.as_bytes()).ok()?;
            let parts: Vec<&str> = mem_text.rsplitn(2, '.').collect();
            if parts.len() == 2 && is_hook_name(parts[0]) {
                return Some(parts[0].to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_content;
    use crate::language::Language;

    fn check(content: &str, lang: Language) -> Vec<Violation> {
        let tree = parse_content(content, lang).expect("parse failed");
        visit(&tree, content)
    }

    #[test]
    fn test_detects_state_in_if() {
        let content = r#"
            function Component() {
                if (condition) {
                    const [x, setX] = useState(0);
                }
                return <div/>;
            }
        "#;
        let violations = check(content, Language::TypeScriptReact);
        assert!(!violations.is_empty(), "Should detect hook inside if");
        assert!(violations[0].message.contains("useState"));
    }

    #[test]
    fn test_detects_effect_in_else() {
        let content = r#"
            function Component() {
                if (a) {
                    return null;
                } else {
                    useEffect(() => {});
                }
                return <div/>;
            }
        "#;
        let violations = check(content, Language::TypeScriptReact);
        assert!(!violations.is_empty(), "Should detect hook inside else");
    }

    #[test]
    fn test_no_violation_hook_at_root() {
        let content = r#"
            function Component() {
                const [x, setX] = useState(0);
                useEffect(() => {}, []);
                if (condition) {
                    return <div/>;
                }
            }
        "#;
        let violations = check(content, Language::TypeScriptReact);
        assert!(violations.is_empty(), "Hooks at root should be fine");
    }

    #[test]
    fn test_no_violation_for_regular_function_call() {
        let content = r#"
            function Component() {
                if (condition) {
                    helperFunction();
                }
                return <div/>;
            }
        "#;
        let violations = check(content, Language::TypeScriptReact);
        assert!(violations.is_empty(), "Non-hook calls should be fine");
    }
}
