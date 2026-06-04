/// Visitor: Detecta useEffect com dependências incompletas.
///
/// Versão básica: extrai variáveis usadas dentro do corpo do useEffect
/// e compara com o array de dependências. Reporta as que estão faltando.
///
/// Casos detectados:
/// - useEffect com `[]` vazio mas corpo que usa variáveis do escopo
/// - useEffect com dependências incompletas (variáveis do corpo não listadas)
/// - useEffect com dependências do escopo de factory function (outer closure)

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};

/// Nomes que não devem ser considerados como dependências de useEffect
/// por serem globais do runtime ou APIs do React.
const BUILTIN_GLOBALS: &[&str] = &[
    "console", "window", "document", "global", "globalThis",
    "process", "Buffer", "setTimeout", "setInterval", "clearTimeout",
    "clearInterval", "fetch", "Math", "JSON", "Promise", "Array",
    "Object", "String", "Number", "Boolean", "Date", "RegExp", "Map",
    "Set", "WeakMap", "WeakSet", "Symbol", "Reflect", "Proxy",
    "undefined", "null", "true", "false", "isNaN", "parseInt", "parseFloat",
];

/// Extrai nomes de identificadores dentro de um nó (exceto declarações locais e globais).
fn extract_identifiers(node: &tree_sitter::Node, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    extract_identifiers_recursive(node, source, &mut names);
    names
}

fn extract_identifiers_recursive(
    node: &tree_sitter::Node,
    source: &str,
    names: &mut Vec<String>,
) {
    // Ignora declarações locais (const/let/var dentro do efeito)
    if matches!(node.kind(), "variable_declaration" | "lexical_declaration") {
        return;
    }

    if node.kind() == "identifier" {
        if let Ok(name) = node.utf8_text(source.as_bytes()) {
            let name = name.to_string();
            // Filtra nomes comuns que não são variáveis do escopo
            if !BUILTIN_GLOBALS.contains(&name.as_str()) {
                names.push(name);
            }
        }
        return; // Não desce nos filhos de um identifier
    }

    // Use children collection to avoid shared cursor state
    let mut child_cursor = node.walk();
    let children: Vec<_> = node.children(&mut child_cursor).collect();
    for child in &children {
        extract_identifiers_recursive(child, source, names);
    }
}

/// Extrai as dependências do array de um `useEffect`.
fn extract_deps(array_node: &tree_sitter::Node, source: &str) -> Vec<String> {
    let mut deps = Vec::new();
    let mut cursor = array_node.walk();
    let children: Vec<_> = array_node.children(&mut cursor).collect();

    for child in &children {
        if child.kind() == "identifier" {
            if let Ok(name) = child.utf8_text(source.as_bytes()) {
                deps.push(name.to_string());
            }
        }
    }
    deps
}

/// Sobe na árvore a partir de `node` e retorna os parâmetros da função
/// que contém a função imediata (ou seja, parâmetros do escopo de factory).
/// Retorna Vec vazio se o useEffect não estiver dentro de uma factory.
fn collect_outer_function_params(
    node: &tree_sitter::Node,
    source: &str,
) -> Vec<String> {
    let mut params = Vec::new();
    let mut depth = 0usize;

    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "function_declaration" | "function_expression" | "arrow_function"
        ) {
            depth += 1;
            if depth == 2 {
                // Este é o escopo de factory — coleta os parâmetros
                let mut cursor = parent.walk();
                let children: Vec<_> = parent.children(&mut cursor).collect();
                for child in &children {
                    if child.kind() == "formal_parameters" {
                        let mut p_cursor = child.walk();
                        let params_children: Vec<_> = child.children(&mut p_cursor).collect();
                        for p in &params_children {
                            // Parâmetro simples: (apiRoute)
                            if p.kind() == "identifier" {
                                if let Ok(name) = p.utf8_text(source.as_bytes()) {
                                    params.push(name.to_string());
                                }
                            }
                            // Parâmetro tipado: (apiRoute: string)
                            if p.kind() == "required_parameter" {
                                let mut rp_cursor = p.walk();
                                let rp_children: Vec<_> = p.children(&mut rp_cursor).collect();
                                for rp in &rp_children {
                                    if rp.kind() == "identifier" {
                                        if let Ok(name) = rp.utf8_text(source.as_bytes()) {
                                            params.push(name.to_string());
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
                return params;
            }
        }
        current = parent.parent();
    }
    params
}

/// Procura por useEffect na árvore e valida suas dependências.
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

    // Procura por call_expression onde a função é `useEffect`
    if node.kind() == "call_expression" {
        if let Ok(text) = node.utf8_text(source.as_bytes()) {
            if text.trim().starts_with("useEffect(") {
                check_useeffect_deps(&node, source, violations);
            }
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

fn check_useeffect_deps(
    node: &tree_sitter::Node,
    source: &str,
    violations: &mut Vec<Violation>,
) {
    let line = node.start_position().row + 1;

    // Pega os argumentos do useEffect — eles estão dentro do nó `arguments`
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();

    // call_expression has: [identifier "useEffect", arguments "(...)"]
    let args_node = children.iter().find(|c| c.kind() == "arguments");

    let args_node = match args_node {
        Some(n) => n,
        None => return,
    };

    // Get the actual argument nodes inside arguments: (arrow_fn, array)
    let mut args_cursor = args_node.walk();
    let arg_children: Vec<_> = args_node.children(&mut args_cursor).collect();

    // Filter out punctuation: find arrow_function and array
    let callback_arg = arg_children.iter().find(|c| {
        matches!(c.kind(), "arrow_function" | "function_expression")
    });
    let deps_arg = arg_children.iter().find(|c| c.kind() == "array");

    let (Some(callback_arg), Some(deps_arg)) = (callback_arg, deps_arg) else {
        return;
    };

    // Extrai identificadores usados no callback
    let used_vars = extract_identifiers(callback_arg, source);

    // Extrai dependências declaradas
    let declared_deps = extract_deps(deps_arg, source);

    // Encontra variáveis usadas mas não declaradas nas deps
    let missing: Vec<&String> = used_vars
        .iter()
        .filter(|v| !declared_deps.contains(v))
        .collect();

    if !missing.is_empty() && !declared_deps.is_empty() {
        let missing_strs: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
        violations.push(
            Violation::new(
                format!("useEffect com dependências incompletas. Variáveis usadas mas não listadas: [{}]. Adicione ao array de dependências.", missing_strs.join(", ")),
                line,
                RuleCategory::Correctness
            )
            .with_suggestion("[STOP] Leia .windsurf/rules/react-hooks-patterns-rules.md antes de reescrever. Adicione as variáveis usadas no body ao array de dependências. Consulte: https://biomejs.dev/")
        );
    }

    // Caso específico: array vazio [] com corpo não-trivial
    if declared_deps.is_empty() && !used_vars.is_empty() {
        violations.push(
            Violation::new(
                "useEffect com array de dependências vazio [] e corpo usando variáveis do escopo. Adicione as dependências ou mova a lógica.",
                line,
                RuleCategory::Correctness
            )
            .with_suggestion("[STOP] Leia .windsurf/rules/react-hooks-patterns-rules.md antes de reescrever. Adicione as variáveis usadas no body ao array de dependências. Consulte: https://biomejs.dev/")
        );
    }

    // Detecta deps que vêm do escopo de factory function (outer closure params).
    // Esses valores são capturados no fechamento da factory e não são reativos
    // ao ciclo de render do componente — o hook deve ser reestruturado.
    let outer_params = collect_outer_function_params(node, source);
    if !outer_params.is_empty() {
        let factory_deps: Vec<&String> = declared_deps
            .iter()
            .filter(|d| outer_params.contains(d))
            .collect();

        if !factory_deps.is_empty() {
            let names: Vec<&str> = factory_deps.iter().map(|s| s.as_str()).collect();
            violations.push(
                Violation::new(
                    format!("useEffect contém dependências do escopo de factory function: [{}]. Esses valores são capturados no fechamento da factory e não são reativos ao ciclo de render do componente. Reestruture o hook para receber esses valores como parâmetros diretos.", names.join(", ")),
                    line,
                    RuleCategory::Correctness
                )
                .with_suggestion("[STOP] Leia .windsurf/rules/react-hooks-patterns-rules.md antes de reescrever. Reestruture o hook para receber esses valores como parâmetros diretos. Consulte: https://biomejs.dev/")
            );
        }
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
    fn test_detects_empty_deps_with_body() {
        let content = r#"
            function Component({ id }: { id: string }) {
                useEffect(() => {
                    fetch(`/api/${id}`);
                }, []);
                return <div/>;
            }
        "#;
        let violations = check(content);
        assert!(!violations.is_empty(), "Should detect empty deps with used vars");
    }

    #[test]
    fn test_detects_missing_deps() {
        let content = r#"
            function Component({ id }: { id: string }) {
                useEffect(() => {
                    console.log(id);
                }, []);
                return <div/>;
            }
        "#;
        let violations = check(content);
        assert!(!violations.is_empty(), "Should detect missing deps");
    }

    #[test]
    fn test_no_violation_with_correct_deps() {
        let content = r#"
            function Component({ id }: { id: string }) {
                useEffect(() => {
                    console.log(id);
                }, [id]);
                return <div/>;
            }
        "#;
        let violations = check(content);
        assert!(violations.is_empty(), "Correct deps should be fine");
    }

    #[test]
    fn test_no_violation_empty_effect() {
        let content = r#"
            function Component() {
                useEffect(() => {
                    // nothing
                }, []);
                return <div/>;
            }
        "#;
        let violations = check(content);
        assert!(violations.is_empty(), "Empty effect with [] should be fine");
    }

    #[test]
    fn test_detects_factory_outer_scope_deps() {
        let content = r#"
            export function createUseArquivosData(apiRoute: string) {
                return function useArquivosData() {
                    useEffect(() => {
                        fetch(apiRoute);
                    }, [apiRoute]);
                }
            }
        "#;
        let violations = check(content);
        assert!(!violations.is_empty(), "Should detect factory outer scope dep");
        assert!(violations[0].message.contains("factory function"));
    }

    #[test]
    fn test_detects_factory_multiple_params() {
        let content = r#"
            export function createUseData(apiRoute: string, paramKey: string) {
                return function useData() {
                    useEffect(() => {
                        fetch(`${apiRoute}?key=${paramKey}`);
                    }, [apiRoute, paramKey]);
                }
            }
        "#;
        let violations = check(content);
        assert!(!violations.is_empty(), "Should detect multiple factory params as deps");
        assert!(violations[0].message.contains("factory function"));
    }

    #[test]
    fn test_no_violation_normal_hook_with_correct_deps() {
        let content = r#"
            function useData(id: string) {
                useEffect(() => {
                    fetch(`/api/${id}`);
                }, [id]);
            }
        "#;
        let violations = check(content);
        assert!(violations.is_empty(), "Normal hook with correct deps should be fine");
    }

    #[test]
    fn test_detects_clinicId_case_from_pentest() {
        // Caso real do pentest: useEffect com [] usando clinicId do escopo
        let content = r#"
            function Component({ clinicId }: { clinicId: string }) {
                useEffect(() => {
                    console.log(clinicId);
                }, []);
                return <div/>;
            }
        "#;
        let violations = check(content);
        assert!(!violations.is_empty(), "Should detect clinicId missing from deps");
        assert!(violations[0].message.contains("clinicId") || violations[0].message.contains("array de dependências vazio"));
    }
}
