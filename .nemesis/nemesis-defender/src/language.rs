use crate::Language;
use std::path::Path;

pub fn detect_language(path: &Path) -> Language {
    // First: extension-based detection
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        match ext {
            "js" | "mjs" | "cjs" => return Language::JavaScript,
            "ts" | "tsx" | "mts" | "cts" => return Language::TypeScript,
            "sh" | "bash" | "zsh" | "fish" | "ksh" => return Language::Bash,
            "py" | "pyw" => return Language::Python,
            "toml" => return Language::Toml,
            "json" | "jsonc" => return Language::Json,
            _ => {}
        }
    }

    // Second: filename-based detection (no extension)
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        match name {
            "Dockerfile" | "Makefile" | ".envrc" | ".env" => return Language::Bash,
            "package.json" | "tsconfig.json" | "bun.lockb" => return Language::Json,
            "Cargo.toml" | "pyproject.toml" => return Language::Toml,
            "build.rs" => return Language::Unknown, // Scanned as manifest, not AST
            "__init__.py" => return Language::Python, // Python package initializer
            _ => {}
        }
    }

    Language::Unknown
}
