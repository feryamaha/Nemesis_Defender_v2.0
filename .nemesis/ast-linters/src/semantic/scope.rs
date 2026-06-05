/// Representação simplificada de escopos para o SemanticModel.

/// Tipo de escopo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    /// Escopo de módulo (top-level do arquivo).
    Module,
    /// Escopo de função (component, hook, callback).
    Function,
}

/// Intervalo de bytes de um escopo na árvore.
#[derive(Debug, Clone)]
pub struct Scope {
    pub kind: ScopeKind,
    pub start_byte: usize,
    pub end_byte: usize,
}

impl Scope {
    pub fn new(kind: ScopeKind, start_byte: usize, end_byte: usize) -> Self {
        Self {
            kind,
            start_byte,
            end_byte,
        }
    }

    /// Verifica se um byte está contido neste escopo.
    pub fn contains(&self, byte: usize) -> bool {
        byte >= self.start_byte && byte < self.end_byte
    }
}

/// `true` se o nó não tem ancestral de função (escopo de módulo / top-level).
pub fn is_top_level(node: &tree_sitter::Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
        ) {
            return false;
        }
        current = parent.parent();
    }
    true
}
