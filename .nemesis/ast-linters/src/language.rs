/// Detecção de linguagem de programação por extensão de arquivo.
/// Mapeia extensões para parsers tree-sitter suportados.

/// Linguagens suportadas pelos AST linters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    TypeScript,
    TypeScriptReact,
    JavaScript,
    JavaScriptReact,
}

impl Language {
    /// Retorna o nome do parser tree-sitter para esta linguagem.
    pub fn parser_name(&self) -> &'static str {
        match self {
            Language::TypeScript => "typescript",
            Language::TypeScriptReact => "typescript",
            Language::JavaScript => "javascript",
            Language::JavaScriptReact => "javascript",
        }
    }

    /// Retorna se a linguagem é TS/JS (React).
    pub fn is_react(&self) -> bool {
        matches!(self, Language::TypeScriptReact | Language::JavaScriptReact)
    }
}

/// Detecta a linguagem a partir da extensão do arquivo.
///
/// Retorna `None` se a extensão não for suportada (não é erro).
pub fn detect_language(file_path: &str) -> Option<Language> {
    let ext = std::path::Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    match ext {
        "ts" => Some(Language::TypeScript),
        "tsx" => Some(Language::TypeScriptReact),
        "js" => Some(Language::JavaScript),
        "jsx" => Some(Language::JavaScriptReact),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ts() {
        assert_eq!(detect_language("file.ts"), Some(Language::TypeScript));
        assert_eq!(detect_language("src/file.ts"), Some(Language::TypeScript));
    }

    #[test]
    fn test_detect_tsx() {
        assert_eq!(detect_language("Component.tsx"), Some(Language::TypeScriptReact));
    }

    #[test]
    fn test_detect_jsx() {
        assert_eq!(detect_language("Component.jsx"), Some(Language::JavaScriptReact));
    }

    #[test]
    fn test_detect_unsupported() {
        assert_eq!(detect_language("file.py"), None);
        assert_eq!(detect_language("file.go"), None);
        assert_eq!(detect_language("file.rs"), None);
        assert_eq!(detect_language("file.rb"), None);
        assert_eq!(detect_language("file.kt"), None);
        assert_eq!(detect_language(""), None);
    }

    #[test]
    fn test_is_react() {
        assert!(Language::TypeScriptReact.is_react());
        assert!(Language::JavaScriptReact.is_react());
        assert!(!Language::TypeScript.is_react());
        assert!(!Language::JavaScript.is_react());
    }
}
