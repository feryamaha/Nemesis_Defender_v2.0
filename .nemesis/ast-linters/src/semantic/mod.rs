/// Camada de análise semântica própria sobre tree-sitter.
pub mod binding;
pub mod scope;
pub mod reference;
pub mod model;

pub use binding::{Binding, BindingKind, Stability};
pub use model::{build_model, SemanticModel};
