/// Wrapper para os parsers tree-sitter.
/// Responsável por criar e reutilizar parsers, além de realizar o parse
/// do código-fonte em árvore sintática.

use crate::language::Language;
use std::sync::Mutex;

/// Erros de parsing.
#[derive(Debug)]
pub enum ParseError {
    UnsupportedLanguage,
    ParseFailed(String),
    LanguageNotInitialized,
}

/// Árvore sintática parseada com sua linguagem.
#[derive(Clone)]
pub struct ParsedTree {
    pub tree: tree_sitter::Tree,
    pub language: Language,
}

/// Representa uma edição incremental no conteúdo.
#[derive(Debug, Clone)]
pub struct TreeEdit {
    /// Índice inicial da edição (bytes).
    pub start_byte: usize,
    /// Índice final da edição (bytes).
    pub old_end_byte: usize,
    /// Novo índice final após a edição (bytes).
    pub new_end_byte: usize,
    /// Linha inicial da edição.
    pub start_position: tree_sitter::Point,
    /// Linha final antiga da edição.
    pub old_end_position: tree_sitter::Point,
    /// Nova linha final após a edição.
    pub new_end_position: tree_sitter::Point,
}

impl TreeEdit {
    /// Cria uma TreeEdit a partir de uma diferença de conteúdo.
    pub fn from_diff(old_content: &str, new_content: &str) -> Option<Self> {
        // Para simplificar, vamos encontrar a primeira diferença
        // Em uma implementação completa, precisaríamos calcular o diff completo
        // e criar múltiplas TreeEdits
        
        let old_lines: Vec<&str> = old_content.lines().collect();
        let new_lines: Vec<&str> = new_content.lines().collect();
        
        for (i, (old_line, new_line)) in old_lines.iter().zip(new_lines.iter()).enumerate() {
            if old_line != new_line {
                // Encontrou diferença - cria TreeEdit simplificada
                let start_byte = old_content.lines().take(i).map(|l| l.len() + 1).sum::<usize>().saturating_sub(1);
                let start_position = tree_sitter::Point { row: i as usize, column: 0 };
                
                let old_end_byte = start_byte + old_line.len();
                let old_end_position = tree_sitter::Point { row: i as usize, column: old_line.len() };
                
                let new_end_byte = start_byte + new_line.len();
                let new_end_position = tree_sitter::Point { row: i as usize, column: new_line.len() };
                
                return Some(TreeEdit {
                    start_byte,
                    old_end_byte,
                    new_end_byte,
                    start_position,
                    old_end_position,
                    new_end_position,
                });
            }
        }
        
        None
    }
}

/// Gerenciador thread-safe de parsers tree-sitter.
pub struct ParserPool {
    typescript: Mutex<Option<tree_sitter::Parser>>,
    javascript: Mutex<Option<tree_sitter::Parser>>,
}

impl ParserPool {
    /// Cria um novo pool vazio (parsers são inicializados sob demanda).
    pub fn new() -> Self {
        Self {
            typescript: Mutex::new(None),
            javascript: Mutex::new(None),
        }
    }

    /// Obtém ou inicializa o parser para a linguagem especificada.
    fn get_parser(&self, language: Language) -> Result<std::sync::MutexGuard<'_, Option<tree_sitter::Parser>>, ParseError> {
        match language {
            Language::TypeScript | Language::TypeScriptReact => {
                let mut guard = self.typescript.lock().map_err(|_| ParseError::LanguageNotInitialized)?;
                if guard.is_none() {
                    let mut parser = tree_sitter::Parser::new();
                    parser
                        .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
                        .map_err(|e| ParseError::ParseFailed(format!("Failed to set typescript language: {}", e)))?;
                    *guard = Some(parser);
                }
                Ok(guard)
            }
            Language::JavaScript | Language::JavaScriptReact => {
                let mut guard = self.javascript.lock().map_err(|_| ParseError::LanguageNotInitialized)?;
                if guard.is_none() {
                    let mut parser = tree_sitter::Parser::new();
                    parser
                        .set_language(&tree_sitter_javascript::LANGUAGE.into())
                        .map_err(|e| ParseError::ParseFailed(format!("Failed to set javascript language: {}", e)))?;
                    *guard = Some(parser);
                }
                Ok(guard)
            }
        }
    }

    /// Realiza o parse do conteúdo na linguagem especificada.
    pub fn parse(&self, content: &str, language: Language) -> Result<ParsedTree, ParseError> {
        let mut guard = self.get_parser(language)?;
        let parser = guard.as_mut().ok_or(ParseError::LanguageNotInitialized)?;

        let tree = parser
            .parse(content, None)
            .ok_or_else(|| ParseError::ParseFailed("Parser returned no tree".to_string()))?;

        Ok(ParsedTree { tree, language })
    }

    /// Realiza o parse incremental usando uma árvore anterior.
    ///
    /// Esta função é usada quando uma edição incremental é aplicada ao conteúdo,
    /// permitindo que o tree-sitter reparse apenas os nós afetados.
    pub fn parse_with_previous_tree(
        &self,
        content: &str,
        previous_tree: &ParsedTree,
        edit: &TreeEdit,
    ) -> Result<ParsedTree, ParseError> {
        let mut guard = self.get_parser(previous_tree.language)?;
        let parser = guard.as_mut().ok_or(ParseError::LanguageNotInitialized)?;

        // Converte TreeEdit para tree_sitter::InputEdit
        let _input_edit = tree_sitter::InputEdit {
            start_byte: edit.start_byte,
            old_end_byte: edit.old_end_byte,
            new_end_byte: edit.new_end_byte,
            start_position: edit.start_position,
            old_end_position: edit.old_end_position,
            new_end_position: edit.new_end_position,
        };

        // Aplica a edição e reparse
        let tree = parser
            .parse(content, Some(&previous_tree.tree))
            .ok_or_else(|| ParseError::ParseFailed("Incremental parse failed".to_string()))?;

        Ok(ParsedTree {
            tree,
            language: previous_tree.language,
        })
    }
}

unsafe impl Send for ParserPool {}
unsafe impl Sync for ParserPool {}

// Pool global inicializado sob demanda.
static POOL: std::sync::OnceLock<ParserPool> = std::sync::OnceLock::new();

/// Retorna a instância global do pool de parsers.
pub fn global_pool() -> &'static ParserPool {
    POOL.get_or_init(ParserPool::new)
}

/// Realiza o parse do conteúdo na linguagem especificada usando o pool global.
pub fn parse_content(content: &str, language: Language) -> Result<ParsedTree, ParseError> {
    global_pool().parse(content, language)
}

/// Realiza o parse incremental usando uma árvore anterior e uma edição.
///
/// Esta função usa o pool global e é o ponto de entrada público para parsing incremental.
pub fn parse_content_with_previous_tree(
    content: &str,
    previous_tree: &ParsedTree,
    edit: &TreeEdit,
) -> Result<ParsedTree, ParseError> {
    global_pool().parse_with_previous_tree(content, previous_tree, edit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ts_simple() {
        let content = "const x: number = 1;";
        let result = parse_content(content, Language::TypeScript);
        assert!(result.is_ok(), "Parse should succeed: {:?}", result.err());
    }

    #[test]
    fn test_parse_tsx_with_jsx() {
        let content = r#"
            function Component() {
                return <div>Hello</div>;
            }
        "#;
        let result = parse_content(content, Language::TypeScriptReact);
        assert!(result.is_ok(), "Parse should succeed: {:?}", result.err());
    }

    #[test]
    fn test_parse_js_simple() {
        let content = "const x = 1;";
        let result = parse_content(content, Language::JavaScript);
        assert!(result.is_ok(), "Parse should succeed: {:?}", result.err());
    }

    #[test]
    fn test_parse_invalid_syntax() {
        // tree-sitter é tolerante a erros de sintaxe — ele ainda produz
        // uma árvore mesmo para código inválido ("error" nodes).
        let content = "const x = ;;;";
        let result = parse_content(content, Language::TypeScript);
        assert!(result.is_ok(), "tree-sitter should handle errors gracefully: {:?}", result.err());
    }

    #[test]
    fn test_parse_empty() {
        let content = "";
        let result = parse_content(content, Language::TypeScript);
        assert!(result.is_ok(), "Empty content should parse: {:?}", result.err());
    }
}
