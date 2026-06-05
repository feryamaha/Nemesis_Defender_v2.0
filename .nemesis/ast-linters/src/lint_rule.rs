/// Trait LintRule - Interface para regras de lint dinâmicas.
///
/// Este trait define a interface comum para todas as regras de lint,
/// permitindo que sejam ativadas/desativadas dinamicamente sem recompilar.
use crate::parser::ParsedTree;
use crate::language::Language;

/// Categoria da regra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleCategory {
    Correctness, // bugs reais, crashes
    Suspicious,  // provavelmente errado
    Security,    // vulnerabilidades OWASP
    Style,       // formatação, preferências
}

/// Configuração de severidade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Off,
    Info,
    Warning,
    Error,
    Critical,
}

impl Severity {
    /// Converte de string para Severity.
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "off" => Severity::Off,
            "info" => Severity::Info,
            "warn" | "warning" => Severity::Warning,
            "error" => Severity::Error,
            "critical" => Severity::Critical,
            _ => Severity::Error, // Default para error
        }
    }

    /// Converte Severity para string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Off => "off",
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
        }
    }
}

/// Contexto de execução para uma regra de lint.
pub struct Context<'a> {
    /// Conteúdo do arquivo sendo validado.
    pub source: &'a str,
    /// Linguagem do arquivo.
    pub language: Language,
    /// Caminho do arquivo.
    pub file_path: &'a str,
}

impl<'a> Context<'a> {
    pub fn new(source: &'a str, language: Language, file_path: &'a str) -> Self {
        Self {
            source,
            language,
            file_path,
        }
    }
}

/// Sugestão de código correto.
#[derive(Debug, Clone)]
pub struct Suggestion {
    /// O que usar no lugar — código ou padrão correto.
    pub message: String,
}

/// Violação detectada por um visitor AST.
#[derive(Debug, Clone)]
pub struct Violation {
    pub rule_name: String,
    pub message: String,
    pub line: usize,
    pub category: RuleCategory,
    pub severity: Severity,
    pub suggestion: Option<Suggestion>,
    pub notes: Vec<String>,
}

impl Violation {
    /// Constructor principal — todos os visitors usam esse.
    pub fn new(
        message: impl Into<String>,
        line: usize,
        category: RuleCategory,
    ) -> Self {
        Self {
            rule_name: String::new(), // preenchido pelo registry
            message: message.into(),
            line,
            category,
            severity: Severity::Error, // default
            suggestion: None,
            notes: vec![],
        }
    }

    /// Builder: adicionar suggestion.
    pub fn with_suggestion(mut self, msg: impl Into<String>) -> Self {
        self.suggestion = Some(Suggestion { message: msg.into() });
        self
    }

    /// Builder: adicionar nota explicativa.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    /// Builder: sobrescrever severidade.
    pub fn with_severity(mut self, s: Severity) -> Self {
        self.severity = s;
        self
    }

    /// Builder: definir rule_name (útil para testes diretos de visitors).
    pub fn with_rule_name(mut self, name: impl Into<String>) -> Self {
        self.rule_name = name.into();
        self
    }
}

/// Trait para regras de lint dinâmicas.
pub trait LintRule: Send + Sync {
    /// Nome único da regra (ex: "no-floating-promises").
    fn name(&self) -> &str;

    /// Categoria da regra para classificação e filtragem.
    fn category(&self) -> RuleCategory;

    /// Severidade padrão da regra.
    fn default_severity(&self) -> Severity;

    /// Executa a regra em uma árvore parseada.
    ///
    /// # Arguments
    ///
    /// * `tree` - Árvore parseada pelo tree-sitter
    /// * `ctx` - Contexto de execução
    ///
    /// # Returns
    ///
    /// Lista de violações detectadas.
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation>;

    /// Linguagens suportadas por esta regra.
    ///
    /// Se a linguagem não estiver nesta lista, a regra não será executada.
    fn supported_languages(&self) -> &[Language] {
        &[
            Language::TypeScript,
            Language::TypeScriptReact,
            Language::JavaScript,
            Language::JavaScriptReact,
        ]
    }

    /// Verifica se a regra deve ser executada para a linguagem dada.
    fn should_run(&self, language: Language) -> bool {
        self.supported_languages().contains(&language)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_str("error"), Severity::Error);
        assert_eq!(Severity::from_str("warn"), Severity::Warning);
        assert_eq!(Severity::from_str("warning"), Severity::Warning);
        assert_eq!(Severity::from_str("off"), Severity::Off);
        assert_eq!(Severity::from_str("info"), Severity::Info);
        assert_eq!(Severity::from_str("unknown"), Severity::Error); // Default
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(Severity::Error.as_str(), "error");
        assert_eq!(Severity::Warning.as_str(), "warning");
        assert_eq!(Severity::Off.as_str(), "off");
        assert_eq!(Severity::Info.as_str(), "info");
    }

    #[test]
    fn test_violation_builder() {
        let v = Violation::new("test message", 42, RuleCategory::Correctness)
            .with_suggestion("use this instead")
            .with_severity(Severity::Warning)
            .with_note("additional context");
        assert_eq!(v.message, "test message");
        assert_eq!(v.line, 42);
        assert_eq!(v.category, RuleCategory::Correctness);
        assert_eq!(v.severity, Severity::Warning);
        assert!(v.suggestion.is_some());
        assert_eq!(v.suggestion.as_ref().unwrap().message, "use this instead");
        assert_eq!(v.notes.len(), 1);
    }
}
