/// Visitor: setState síncrono dentro de useEffect (risco de loop de render).
///
/// Detecta a chamada direta de um setter de useState como statement no corpo
/// imediato do useEffect (não dentro de condicional/callback aninhado). Usa o
/// SemanticModel para identificar setters estáveis (StableHookResult, nome `set*`).

use crate::parser::ParsedTree;
use crate::lint_rule::{Violation, RuleCategory};
use crate::semantic::{build_model, SemanticModel, BindingKind};
use crate::semantic::reference::called_function_name;

pub fn visit(tree: &ParsedTree, source: &str) -> Vec<Violation> {
    let model = build_model(tree, source);
    let mut out = Vec::new();
    let cursor = &mut tree.tree.walk();
    walk(cursor, source, &model, &mut out);
    out
}

fn walk(
    cursor: &mut tree_sitter::TreeCursor,
    source: &str,
    model: &SemanticModel,
    out: &mut Vec<Violation>,
) {
    let node = cursor.node();
    if node.kind() == "call_expression" {
        if let Some(name) = called_function_name(&node, source) {
            if name == "useEffect" {
                check_effect(&node, source, model, out);
            }
        }
    }
    if cursor.goto_first_child() {
        loop {
            walk(cursor, source, model, out);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

fn check_effect(
    node: &tree_sitter::Node,
    source: &str,
    model: &SemanticModel,
    out: &mut Vec<Violation>,
) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    let Some(args) = children.iter().find(|c| c.kind() == "arguments") else {
        return;
    };
    let mut acur = args.walk();
    let Some(callback) = args
        .children(&mut acur)
        .find(|c| matches!(c.kind(), "arrow_function" | "function_expression"))
    else {
        return;
    };
    let Some(body) = callback.child_by_field_name("body") else {
        return;
    };
    if body.kind() != "statement_block" {
        return;
    }

    // Inspeciona statements diretos do corpo: expression_statement -> call_expression de setter.
    let mut bcur = body.walk();
    for stmt in body.children(&mut bcur) {
        if stmt.kind() != "expression_statement" {
            continue;
        }
        let mut scur = stmt.walk();
        for inner in stmt.children(&mut scur) {
            if inner.kind() == "call_expression" {
                if let Some(callee) = called_function_name(&inner, source) {
                    let is_setter = model
                        .binding(&callee)
                        .map(|b| {
                            b.kind == BindingKind::StableHookResult && callee.starts_with("set")
                        })
                        .unwrap_or(false);
                    if is_setter {
                        let line = inner.start_position().row + 1;
                        out.push(
                            Violation::new(
                                format!(
                                    "setState síncrono ('{}') no corpo do useEffect pode causar loop de render. Use dependências/condição ou derive o valor.",
                                    callee
                                ),
                                line,
                                RuleCategory::Correctness,
                            )
                            .with_suggestion("[STOP] Leia .devin/rules/react-hooks-patterns-rules.md. Evite setState direto no effect; condicione ou derive o estado."),
                        );
                    }
                }
            }
        }
    }
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
    fn detects() {
        assert!(!check("function C(){ const [v,setV]=useState(0); useEffect(()=>{ setV(1); },[]); return null; }").is_empty());
    }

    #[test]
    fn ok_guarded() {
        assert!(check("function C(){ const [v,setV]=useState(0); useEffect(()=>{ if(v<1){setV(1);} },[v]); return null; }").is_empty());
    }
}
