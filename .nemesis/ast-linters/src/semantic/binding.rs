/// Tipos de binding e classificação de estabilidade para análise de hooks.

/// Estabilidade de um binding para fins de dependência de hooks React.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stability {
    /// Identidade estável entre renders — não precisa (e não deve) ser dependência.
    /// Ex.: setters de useState, dispatch de useReducer, useRef, decls top-level.
    Stable,
    /// Valor reativo: pode mudar entre renders; deve ser dependência se usado.
    Reactive,
}

/// Origem/tipo de um binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingKind {
    /// Parâmetro de função/componente.
    Parameter,
    /// Declaração const/let/var dentro de função.
    Variable,
    /// Import (top-level).
    Import,
    /// Declaração top-level (fora de função).
    TopLevel,
    /// Resultado estável de hook (setter de useState, useRef, etc.).
    StableHookResult,
    /// Declaração de função.
    Function,
}

/// Binding resolvido pelo SemanticModel.
#[derive(Debug, Clone)]
pub struct Binding {
    pub name: String,
    pub kind: BindingKind,
    pub stability: Stability,
    /// Linha (1-based) da declaração.
    pub decl_line: usize,
    /// Indica se o binding foi reatribuído em algum ponto do arquivo.
    pub reassigned: bool,
}

impl Binding {
    pub fn new(
        name: impl Into<String>,
        kind: BindingKind,
        stability: Stability,
        decl_line: usize,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            stability,
            decl_line,
            reassigned: false,
        }
    }
}
