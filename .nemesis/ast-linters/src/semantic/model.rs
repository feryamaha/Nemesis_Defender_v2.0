/// SemanticModel próprio: resolução simplificada de bindings e estabilidade.
///
/// Modelo de escopo simplificado (flat por arquivo): imports e declarações
/// top-level são tratados como estáveis; parâmetros e variáveis dentro de função
/// são reativos, exceto resultados estáveis de hooks (setters de useState,
/// dispatch de useReducer, useRef, etc.). Shadowing entre escopos não é resolvido
/// nesta versão (limitação declarada), o que é suficiente para os hooks-alvo.

use std::collections::HashMap;

use crate::parser::ParsedTree;
use crate::semantic::binding::{Binding, BindingKind, Stability};
use crate::semantic::scope::is_top_level;

/// Para hooks com resultado estável, retorna:
/// - `Some(Some(i))`: o elemento de índice `i` do destructuring de array é estável.
/// - `Some(None)`: a identidade inteira do retorno é estável.
/// - `None`: hook sem resultado estável.
fn stable_hook_index(hook: &str) -> Option<Option<usize>> {
    match hook {
        "useState" => Some(Some(1)),
        "useReducer" => Some(Some(1)),
        "useTransition" => Some(Some(1)),
        "useRef" => Some(None),
        "useEffectEvent" => Some(None),
        _ => None,
    }
}

/// Modelo semântico de um arquivo (escopo flat).
#[derive(Debug, Default)]
pub struct SemanticModel {
    bindings: HashMap<String, Binding>,
}

impl SemanticModel {
    /// Retorna o binding de um nome, se existir.
    pub fn binding(&self, name: &str) -> Option<&Binding> {
        self.bindings.get(name)
    }

    /// Indica se o nome corresponde a um binding estável (não precisa ser dependência).
    pub fn is_stable(&self, name: &str) -> bool {
        self.bindings
            .get(name)
            .map(|b| b.stability == Stability::Stable)
            .unwrap_or(false)
    }

    /// Indica se o nome é conhecido pelo modelo.
    pub fn is_known(&self, name: &str) -> bool {
        self.bindings.contains_key(name)
    }

    fn insert(&mut self, binding: Binding) {
        self.bindings.insert(binding.name.clone(), binding);
    }
}

/// Constrói o SemanticModel a partir de uma árvore tree-sitter.
pub fn build_model(tree: &ParsedTree, source: &str) -> SemanticModel {
    let mut model = SemanticModel::default();
    let root = tree.tree.root_node();
    walk_collect(&root, source, &mut model);
    model
}

fn walk_collect(node: &tree_sitter::Node, source: &str, model: &mut SemanticModel) {
    match node.kind() {
        "import_statement" => {
            let line = node.start_position().row + 1;
            for name in import_bindings(node, source) {
                model.insert(Binding::new(name, BindingKind::Import, Stability::Stable, line));
            }
        }
        "variable_declarator" => collect_declarator(node, source, model),
        "function_declaration" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source.as_bytes()).ok())
            {
                let line = node.start_position().row + 1;
                model.insert(Binding::new(
                    name.to_string(),
                    BindingKind::Function,
                    Stability::Stable,
                    line,
                ));
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    for child in &children {
        walk_collect(child, source, model);
    }
}

/// Processa `const X = ...` / `const [a, b] = useHook()`.
fn collect_declarator(node: &tree_sitter::Node, source: &str, model: &mut SemanticModel) {
    let line = node.start_position().row + 1;
    let top = is_top_level(node);

    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let value_node = node.child_by_field_name("value");

    // Caso destructuring de array: const [a, setA] = useState(...)
    if name_node.kind() == "array_pattern" {
        let elems = array_pattern_names(&name_node, source);
        let stable_idx = value_node
            .as_ref()
            .and_then(|v| hook_call_name(v, source))
            .as_deref()
            .and_then(stable_hook_index);

        for (i, elem) in elems.iter().enumerate() {
            let Some(elem) = elem else { continue };
            let stable = match stable_idx {
                Some(Some(idx)) => i == idx,
                Some(None) => true,
                None => false,
            };
            let (kind, stability) = if stable {
                (BindingKind::StableHookResult, Stability::Stable)
            } else if top {
                (BindingKind::TopLevel, Stability::Stable)
            } else {
                (BindingKind::Variable, Stability::Reactive)
            };
            model.insert(Binding::new(elem.clone(), kind, stability, line));
        }
        return;
    }

    // Caso identifier simples: const ref = useRef() | const x = expr
    if name_node.kind() == "identifier" {
        if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
            let stable_identity = matches!(
                value_node
                    .as_ref()
                    .and_then(|v| hook_call_name(v, source))
                    .as_deref()
                    .and_then(stable_hook_index),
                Some(None)
            );
            let (kind, stability) = if stable_identity {
                (BindingKind::StableHookResult, Stability::Stable)
            } else if top {
                (BindingKind::TopLevel, Stability::Stable)
            } else {
                (BindingKind::Variable, Stability::Reactive)
            };
            model.insert(Binding::new(name.to_string(), kind, stability, line));
        }
    }
}

/// Extrai o nome do hook chamado em um valor de inicialização, se for `call_expression`.
fn hook_call_name(value: &tree_sitter::Node, source: &str) -> Option<String> {
    if value.kind() != "call_expression" {
        return None;
    }
    let fn_node = value.child_by_field_name("function")?;
    match fn_node.kind() {
        "identifier" => fn_node.utf8_text(source.as_bytes()).ok().map(|s| s.to_string()),
        "member_expression" => fn_node
            .utf8_text(source.as_bytes())
            .ok()
            .and_then(|t| t.rsplit('.').next().map(|s| s.to_string())),
        _ => None,
    }
}

/// Nomes dos elementos de um array_pattern (None para holes/padrões complexos).
fn array_pattern_names(node: &tree_sitter::Node, source: &str) -> Vec<Option<String>> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => {
                out.push(child.utf8_text(source.as_bytes()).ok().map(|s| s.to_string()));
            }
            "[" | "]" | "," => {}
            _ => out.push(None),
        }
    }
    out
}

fn import_bindings(node: &tree_sitter::Node, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    collect_import_identifiers(node, source, &mut out);
    out
}

fn collect_import_identifiers(node: &tree_sitter::Node, source: &str, out: &mut Vec<String>) {
    if node.kind() == "identifier" {
        if let Ok(name) = node.utf8_text(source.as_bytes()) {
            out.push(name.to_string());
        }
        return;
    }
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    for child in &children {
        collect_import_identifiers(child, source, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_content;
    use crate::language::Language;

    fn m(c: &str) -> SemanticModel {
        build_model(&parse_content(c, Language::TypeScriptReact).unwrap(), c)
    }

    #[test]
    fn setter_stable() {
        let x = m("function C(){ const [v,setV]=useState(0); }");
        assert!(x.is_stable("setV"));
        assert!(!x.is_stable("v"));
    }

    #[test]
    fn ref_stable() {
        assert!(m("function C(){ const r=useRef(null); }").is_stable("r"));
    }

    #[test]
    fn dispatch_stable() {
        let x = m("function C(){ const [s,d]=useReducer(r,0); }");
        assert!(x.is_stable("d"));
        assert!(!x.is_stable("s"));
    }

    #[test]
    fn var_reactive() {
        assert!(!m("function C({id}){ const x=id+1; }").is_stable("x"));
    }
}
