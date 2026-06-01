//! Scanner modules — layered analysis pipeline
//!
//! Execution order (fastest to slowest):
//! 1. byte_scanner   — raw byte inspection, no parser
//! 2. entropy        — Shannon entropy heuristics
//! 3. regex_layer    — fast regex pre-AST
//! 4. manifest_scanner — structured file analysis
//! 5. ast_scanner    — tree-sitter semantic analysis
//! 6. decoder        — recursive payload decode + rescan (max 3 levels)

pub mod ast_scanner;
pub mod byte_scanner;
pub mod decoder;
pub mod denylist_loader;
pub mod entropy;
pub mod manifest_scanner;
pub mod regex_layer;
