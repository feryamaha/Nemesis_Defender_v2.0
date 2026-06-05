/// Visitor: dependências de hooks React (motor unificado).
///
/// Cobre useEffect, useLayoutEffect, useInsertionEffect, useCallback, useMemo
/// e useImperativeHandle. Usa o SemanticModel próprio para ignorar valores
/// estáveis (setters de useState, useRef, etc.), evitando falsos-positivos.

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};
use crate::semantic::{build_model, SemanticModel};
use crate::semantic::reference::{called_function_name, collect_identifier_refs};

/// Globais de runtime que nunca são dependências.
const BUILTIN_GLOBALS: &[&str] = &[
    "console", "window", "document", "global", "globalThis",
    "process", "Buffer", "setTimeout", "setInterval", "clearTimeout",
    "clearInterval", "fetch", "Math", "JSON", "Promise", "Array",
    "Object", "String", "Number", "Boolean", "Date", "RegExp", "Map",
    "Set", "WeakMap", "WeakSet", "Symbol", "Reflect", "Proxy",
    "undefined", "null", "true", "false", "isNaN", "parseInt", "parseFloat",
];

/// (nome_hook, índice_do_closure, índice_do_array_de_deps)
const DEP_HOOKS: &[(&str, usize, usize)] = &[
    ("useEffect", 0, 1),
    ("useLayoutEffect", 0, 1),
    ("useInsertionEffect", 0, 1),
    ("useCallback", 0, 1),
    ("useMemo", 0, 1),
    ("useImperativeHandle", 1, 2),
];

fn hook_indices(name: &str) -> Option<(usize, usize)> {
    DEP_HOOKS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, c, d)| (*c, *d))
}

pub fn visit(tree: &ParsedTree, source: &str) -> Vec<Violation> {
    let model = build_model(tree, source);
    let mut violations = Vec::new();
    let cursor = &mut tree.tree.walk();
    visit_node(cursor, source, &model, &mut violations);
    violations
}

fn visit_node(
    cursor: &mut tree_sitter::TreeCursor,
    source: &str,
    model: &SemanticModel,
    out: &mut Vec<Violation>,
) {
    let node = cursor.node();
    if node.kind() == "call_expression" {
        if let Some(name) = called_function_name(&node, source) {
            if let Some((ci, di)) = hook_indices(&name) {
                check_hook_deps(&node, source, model, &name, ci, di, out);
            }
        }
    }
    if cursor.goto_first_child() {
        loop {
            visit_node(cursor, source, model, out);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// Retorna os nós de argumento (sem pontuação) de um call_expression.
fn argument_nodes<'a>(node: &tree_sitter::Node<'a>) -> Vec<tree_sitter::Node<'a>> {
    let mut result = Vec::new();
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    if let Some(args) = children.iter().find(|c| c.kind() == "arguments") {
        let mut acur = args.walk();
        for arg in args.children(&mut acur) {
            if !matches!(arg.kind(), "(" | ")" | ",") {
                result.push(arg);
            }
        }
    }
    result
}

fn check_hook_deps(
    node: &tree_sitter::Node,
    source: &str,
    model: &SemanticModel,
    hook: &str,
    closure_idx: usize,
    deps_idx: usize,
    out: &mut Vec<Violation>,
) {
    let line = node.start_position().row + 1;
    let args = argument_nodes(node);

    let Some(callback) = args.get(closure_idx) else {
        return;
    };
    if !matches!(callback.kind(), "arrow_function" | "function_expression") {
        return;
    }
    let deps_node = args.get(deps_idx);

    let used = collect_identifier_refs(callback, source);
    let declared: Vec<String> = match deps_node {
        Some(d) if d.kind() == "array" => extract_deps(d, source),
        _ => Vec::new(),
    };

    // Variáveis que realmente precisam estar nas deps:
    // - não builtin
    // - reativas (não estáveis) segundo o SemanticModel
    let needs: Vec<String> = used
        .into_iter()
        .filter(|v| !BUILTIN_GLOBALS.contains(&v.as_str()))
        .filter(|v| !model.is_stable(v))
        .collect();

    let missing: Vec<String> = needs
        .iter()
        .filter(|v| !declared.contains(v))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    if deps_node.is_some() && !missing.is_empty() {
        out.push(
            Violation::new(
                format!(
                    "{} com dependências incompletas. Variáveis reativas usadas mas não listadas: [{}]. Adicione-as ao array de dependências.",
                    hook,
                    missing.join(", ")
                ),
                line,
                RuleCategory::Correctness,
            )
            .with_suggestion("[STOP] Leia .windsurf/rules/react-hooks-patterns-rules.md antes de reescrever. Adicione as variáveis reativas usadas no corpo ao array de dependências."),
        );
    }
}

fn extract_deps(array_node: &tree_sitter::Node, source: &str) -> Vec<String> {
    let mut deps = Vec::new();
    let mut cursor = array_node.walk();
    for child in array_node.children(&mut cursor) {
        if child.kind() == "identifier" {
            if let Ok(name) = child.utf8_text(source.as_bytes()) {
                deps.push(name.to_string());
            }
        }
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_content;
    use crate::language::Language;

    fn check(c: &str) -> Vec<Violation> {
        visit(&parse_content(c, Language::TypeScriptReact).unwrap(), c)
    }

    #[test]
    fn effect_missing() {
        assert!(!check("function C({id}){ useEffect(()=>{console.log(id);},[]); return null; }").is_empty());
    }

    #[test]
    fn effect_ok() {
        assert!(check("function C({id}){ useEffect(()=>{console.log(id);},[id]); return null; }").is_empty());
    }

    #[test]
    fn callback_missing() {
        let v = check("function C({onUpdate,value}){ const h=useCallback(()=>{onUpdate(value);},[onUpdate]); return null; }");
        assert!(!v.is_empty());
        assert!(v[0].message.contains("value"));
    }

    #[test]
    fn memo_missing() {
        assert!(!check("function C({data,filter}){ const f=useMemo(()=>data.filter(filter),[data]); return null; }").is_empty());
    }

    #[test]
    fn setter_ok() {
        assert!(check("function C(){ const [v,setV]=useState(0); useEffect(()=>{setV(v+1);},[v]); return null; }").is_empty());
    }

    #[test]
    fn ref_ok() {
        assert!(check("function C(){ const r=useRef(0); useEffect(()=>{r.current=1;},[]); return null; }").is_empty());
    }
}
