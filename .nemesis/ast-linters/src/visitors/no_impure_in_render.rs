/// Visitor: chamadas impuras (Math.random, Date.now) diretamente no render.
///
/// Render de componentes React deve ser puro. Detecta chamadas impuras feitas
/// no corpo imediato de um componente (function_declaration cujo nome inicia
/// em maiúscula), fora de hooks/handlers/callbacks aninhados.

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};

const IMPURE_CALLS: &[&str] = &["Math.random", "Date.now"];

pub fn visit(tree: &ParsedTree, source: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    let cursor = &mut tree.tree.walk();
    walk(cursor, source, &mut out);
    out
}

fn walk(cursor: &mut tree_sitter::TreeCursor, source: &str, out: &mut Vec<Violation>) {
    let node = cursor.node();
    if node.kind() == "call_expression" && is_impure_call(&node, source) && in_render_scope(&node, source) {
        let line = node.start_position().row + 1;
        out.push(
            Violation::new(
                "Chamada impura (Math.random/Date.now) durante o render. Mova para useEffect, useMemo ou um event handler.",
                line,
                RuleCategory::Correctness,
            )
            .with_suggestion("[STOP] Leia .windsurf/rules/react-hooks-patterns-rules.md. Render deve ser puro; mova efeitos colaterais para fora do corpo do componente."),
        );
    }
    if cursor.goto_first_child() {
        loop {
            walk(cursor, source, out);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

fn is_impure_call(node: &tree_sitter::Node, source: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "member_expression" {
            if let Ok(text) = child.utf8_text(source.as_bytes()) {
                return IMPURE_CALLS.contains(&text);
            }
        }
    }
    false
}

/// `true` se o ancestral de função mais próximo é um componente (function_declaration
/// com nome iniciando em maiúscula) e não há arrow/callback intermediário.
fn in_render_scope(node: &tree_sitter::Node, source: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            // Dentro de callback/handler/hook — não é o corpo direto do render.
            "arrow_function" | "function_expression" => return false,
            "function_declaration" => {
                if let Some(name) = parent.child_by_field_name("name") {
                    let starts_upper = name
                        .utf8_text(source.as_bytes())
                        .ok()
                        .and_then(|s| s.chars().next())
                        .map(|c| c.is_uppercase())
                        .unwrap_or(false);
                    return starts_upper;
                }
                return false;
            }
            _ => {}
        }
        current = parent.parent();
    }
    false
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
    fn detects_random() {
        assert!(!check("function C(){ const x = Math.random(); return <div>{x}</div>; }").is_empty());
    }

    #[test]
    fn ok_in_effect() {
        assert!(check("function C(){ useEffect(()=>{ const x = Math.random(); },[]); return null; }").is_empty());
    }
}
