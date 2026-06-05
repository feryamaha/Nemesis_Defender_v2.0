/// Helpers de extração de identificadores e nomes de chamadas para o SemanticModel.

/// Extrai o nome da função chamada em um `call_expression`
/// (identifier ou member_expression `obj.method`).
pub fn called_function_name(node: &tree_sitter::Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    for child in &children {
        match child.kind() {
            "identifier" => {
                return child.utf8_text(source.as_bytes()).ok().map(|s| s.to_string());
            }
            "member_expression" => {
                let text = child.utf8_text(source.as_bytes()).ok()?;
                return text.rsplit('.').next().map(|s| s.to_string());
            }
            _ => {}
        }
    }
    None
}

/// Coleta nomes de identificadores referenciados dentro de um nó,
/// ignorando declarações locais e descendo recursivamente.
pub fn collect_identifier_refs(node: &tree_sitter::Node, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    collect_refs_recursive(node, source, &mut out);
    out
}

fn collect_refs_recursive(node: &tree_sitter::Node, source: &str, out: &mut Vec<String>) {
    // Ignora declarações locais dentro do nó (não são "uso" de escopo externo).
    if matches!(node.kind(), "variable_declaration" | "lexical_declaration") {
        return;
    }
    if node.kind() == "identifier" {
        if let Ok(name) = node.utf8_text(source.as_bytes()) {
            out.push(name.to_string());
        }
        return;
    }
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    for child in &children {
        collect_refs_recursive(child, source, out);
    }
}
