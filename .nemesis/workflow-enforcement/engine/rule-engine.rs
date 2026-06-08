use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Padrão de regra pode ser: regex, string ou função customizada
#[derive(Clone, Debug)]
pub enum RulePattern {
    Regex(Regex),
    String(String),
    Function(fn(&str, &ValidationContext) -> bool),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub category: Category,
    pub suggestion: String,
    #[serde(skip)]
    #[serde(default)]
    pub pattern: Option<RulePattern>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exceptions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Typescript,
    React,
    Css,
    Security,
    Architecture,
    General,
}

#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub file_path: String,
    pub file_type: String,
    pub is_ui_component: bool,
    pub is_shared_component: bool,
    pub is_hook: bool,
    pub is_type_file: bool,
    pub project_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleViolation {
    pub rule_id: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    pub severity: Severity,
    pub suggestion: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub violations: Vec<RuleViolation>,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Summary {
    pub errors: usize,
    pub warnings: usize,
    pub info: usize,
}

pub struct RuleEngine {
    rules: HashMap<String, Rule>,
    rules_path: PathBuf,
    project_root: PathBuf,
}

impl RuleEngine {
    pub fn new(rules_path: Option<&str>, project_root: Option<&str>) -> Self {
        let project_root = project_root
            .map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        
        let rules_path = rules_path
            .map(PathBuf::from)
            .unwrap_or_else(|| project_root.join(".devin/rules"));

        let mut engine = Self {
            rules: HashMap::new(),
            rules_path,
            project_root: project_root.clone(),
        };
        
        engine.load_builtin_rules();
        engine.load_custom_rules();
        engine
    }

    fn load_builtin_rules(&mut self) {
        let builtin_rules = vec![
            // TypeScript Rules
            Rule {
                id: "ts-any-prohibited".to_string(),
                name: "Proibir uso de any".to_string(),
                description: "Uso de tipo any é proibido".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r":\s*any\b").unwrap())),
                severity: Severity::Error,
                category: Category::Typescript,
                suggestion: "Criar tipo específico em src/types/ ou usar tipo mais específico".to_string(),
                file_patterns: Some(vec!["*.ts".to_string(), "*.tsx".to_string()]),
                exceptions: Some(vec!["Button.tsx".to_string(), "Container.tsx".to_string(), "InputPesquisaAjuda.tsx".to_string()]),
            },
            Rule {
                id: "ts-as-any-prohibited".to_string(),
                name: "Proibir cast as any".to_string(),
                description: "Cast \"as any\" é proibido".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r"\bas\s+any\b").unwrap())),
                severity: Severity::Error,
                category: Category::Typescript,
                suggestion: "Usar tipo explícito ou unknown com type guard".to_string(),
                file_patterns: Some(vec!["*.ts".to_string(), "*.tsx".to_string()]),
                exceptions: None,
            },
            Rule {
                id: "ts-suppression-prohibited".to_string(),
                name: "Proibir supressão de erros TypeScript".to_string(),
                description: "@ts-ignore e @ts-nocheck são proibidos".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r"@ts-ignore|@ts-nocheck").unwrap())),
                severity: Severity::Error,
                category: Category::Typescript,
                suggestion: "Corrija o tipo ou use unknown com type guard adequado".to_string(),
                file_patterns: Some(vec!["*.ts".to_string(), "*.tsx".to_string()]),
                exceptions: None,
            },
            Rule {
                id: "ts-inline-types-prohibited".to_string(),
                name: "Proibir tipagem inline em componentes".to_string(),
                description: "Tipagem inline em componentes reutilizáveis é proibida".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r"export\s+function\s+[A-Z]\w+\s*\(\s*\{[^}]*\}\s*:\s*\{[^}]*\}\s*\)").unwrap())),
                severity: Severity::Error,
                category: Category::Typescript,
                suggestion: "Mover tipagem para src/types/ui/[componente].types.ts".to_string(),
                file_patterns: Some(vec!["src/components/**/*.tsx".to_string()]),
                exceptions: Some(vec!["layout.tsx".to_string(), "page.tsx".to_string()]),
            },
            // Config File Rules
            Rule {
                id: "config-strict-false-prohibited".to_string(),
                name: "Proibir strict: false em tsconfig".to_string(),
                description: "strict: false desabilita TypeScript strict mode globalmente".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r#""strict"\s*:\s*false"#).unwrap())),
                severity: Severity::Error,
                category: Category::Typescript,
                suggestion: "TypeScript strict mode é obrigatório. Não desabilite via tsconfig.".to_string(),
                file_patterns: Some(vec!["tsconfig*.json".to_string()]),
                exceptions: None,
            },
            Rule {
                id: "config-noimplicitany-false-prohibited".to_string(),
                name: "Proibir noImplicitAny: false".to_string(),
                description: "noImplicitAny: false permite any implícito em todo o projeto".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r#""noImplicitAny"\s*:\s*false"#).unwrap())),
                severity: Severity::Error,
                category: Category::Typescript,
                suggestion: "noImplicitAny deve permanecer habilitado.".to_string(),
                file_patterns: Some(vec!["tsconfig*.json".to_string()]),
                exceptions: None,
            },
            Rule {
                id: "config-strictnullchecks-false-prohibited".to_string(),
                name: "Proibir strictNullChecks: false".to_string(),
                description: "strictNullChecks: false desabilita verificação de null/undefined".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r#""strictNullChecks"\s*:\s*false"#).unwrap())),
                severity: Severity::Error,
                category: Category::Typescript,
                suggestion: "strictNullChecks deve permanecer habilitado.".to_string(),
                file_patterns: Some(vec!["tsconfig*.json".to_string()]),
                exceptions: None,
            },
            Rule {
                id: "config-styled-jsx-prohibited".to_string(),
                name: "Proibir dependência styled-jsx".to_string(),
                description: "styled-jsx é proibido — apenas Tailwind é permitido".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r#""styled-jsx""#).unwrap())),
                severity: Severity::Error,
                category: Category::Css,
                suggestion: "Use classes Tailwind definidas em tailwind.config.ts.".to_string(),
                file_patterns: Some(vec!["package.json".to_string()]),
                exceptions: None,
            },
            // React Rules
            Rule {
                id: "react-hooks-conditional".to_string(),
                name: "Proibir hooks condicionais".to_string(),
                description: "Hooks não podem ser chamados dentro de condicionais".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r"if\s*\([^)]*\)\s*\{[^}]*\b(useState|useEffect|useCallback|useMemo)\b").unwrap())),
                severity: Severity::Error,
                category: Category::React,
                suggestion: "Mover todos os hooks para o topo do componente".to_string(),
                file_patterns: Some(vec!["*.tsx".to_string(), "*.ts".to_string()]),
                exceptions: None,
            },
            Rule {
                id: "react-setstate-in-useeffect".to_string(),
                name: "Proibir setState síncrono em useEffect".to_string(),
                description: "setState não pode ser chamado diretamente no corpo do useEffect".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r"useEffect\s*\(\s*\(\s*\)\s*=>\s*\{\s*set[A-Z][a-zA-Z]*\s*\(").unwrap())),
                severity: Severity::Error,
                category: Category::React,
                suggestion: "Usar callbacks ou lógica condicional antes de setState".to_string(),
                file_patterns: Some(vec!["*.tsx".to_string(), "*.ts".to_string()]),
                exceptions: None,
            },
            // UI Separation Rules
            Rule {
                id: "ui-logic-in-pure-components".to_string(),
                name: "Proibir lógica em componentes UI pura".to_string(),
                description: "Componentes UI não devem conter lógica de negócio".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r"\b(useState|useEffect|useMemo|useCallback)\s*\(").unwrap())),
                severity: Severity::Error,
                category: Category::Architecture,
                suggestion: "Mover lógica para hooks em src/hooks/".to_string(),
                file_patterns: Some(vec!["src/components/ui/*.tsx".to_string()]),
                exceptions: Some(vec!["Button.tsx".to_string(), "Container.tsx".to_string(), "InputPesquisaAjuda.tsx".to_string()]),
            },
            // Design System Rules
            Rule {
                id: "ds-css-inline-prohibited".to_string(),
                name: "Proibir CSS inline".to_string(),
                description: "CSS inline é proibido".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r"style\s*=\s*\{\s*\{").unwrap())),
                severity: Severity::Error,
                category: Category::Css,
                suggestion: "Usar classes Tailwind definidas no tailwind.config.ts".to_string(),
                file_patterns: Some(vec!["*.tsx".to_string()]),
                exceptions: None,
            },
            Rule {
                id: "ds-hex-colors-prohibited".to_string(),
                name: "Proibir cores hexadecimais diretas".to_string(),
                description: "Cores hexadecimais diretas são proibidas".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r#"(?:bg|text|border|ring|fill|stroke)-\[#[0-9A-Fa-f]{3,6}\]|(?:color|background|backgroundColor|borderColor)\s*:\s*['"]#[0-9A-Fa-f]{3,6}['"]"#).unwrap())),
                severity: Severity::Warning,
                category: Category::Css,
                suggestion: "Usar tokens semânticos do design system (ex: bg-primary-500)".to_string(),
                file_patterns: Some(vec!["*.tsx".to_string(), "*.css".to_string()]),
                exceptions: None,
            },
            // Security Rules
            Rule {
                id: "sec-localstorage-token".to_string(),
                name: "Proibir token em localStorage".to_string(),
                description: "localStorage não deve armazenar tokens de autenticação".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r"localStorage\s*\.\s*setItem\s*\([^)]*[Tt]oken").unwrap())),
                severity: Severity::Error,
                category: Category::Security,
                suggestion: "Use cookies HttpOnly para tokens de autenticação".to_string(),
                file_patterns: Some(vec!["*.ts".to_string(), "*.tsx".to_string(), "*.js".to_string()]),
                exceptions: None,
            },
            Rule {
                id: "sec-cors-wildcard".to_string(),
                name: "Proibir CORS wildcard".to_string(),
                description: "CORS com * é proibido em route handlers".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r#"'Access-Control-Allow-Origin'\s*[:=]\s*['"]\*['"]"#).unwrap())),
                severity: Severity::Error,
                category: Category::Security,
                suggestion: "Especifique as origens permitidas explicitamente".to_string(),
                file_patterns: Some(vec!["*.ts".to_string(), "*.tsx".to_string()]),
                exceptions: None,
            },
            Rule {
                id: "sec-dangerous-bash-commands".to_string(),
                name: "Proibir comandos bash perigosos".to_string(),
                description: "Comandos perigosos não são permitidos".to_string(),
                pattern: Some(RulePattern::Regex(Regex::new(r"rm\s+-rf\s+/|sudo\s+rm|curl\s+\|\s*bash|wget\s+\|\s*bash").unwrap())),
                severity: Severity::Error,
                category: Category::Security,
                suggestion: "Evitar comandos perigosos ou usar alternativas seguras".to_string(),
                file_patterns: Some(vec!["*.sh".to_string(), "*.bash".to_string()]),
                exceptions: None,
            },
        ];

        for rule in builtin_rules {
            self.rules.insert(rule.id.clone(), rule);
        }
    }

    fn load_custom_rules(&mut self) {
        if !self.rules_path.exists() {
            return;
        }

        let rule_files: Vec<_> = match fs::read_dir(&self.rules_path) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path().extension()
                        .map(|ext| ext == "md")
                        .unwrap_or(false)
                })
                .map(|e| e.path())
                .collect(),
            Err(_) => return,
        };

        for rule_file in rule_files {
            // Parser de regras markdown não implementado.
            // Os arquivos de regras são lidos pelo TerminalReaderService durante
            // o workflow-main (Etapa 1) para internalização pelo modelo.
            println!("[RuleEngine] Rule file available (not parsed as code): {:?}", rule_file);
        }
    }

    pub fn validate(&self, content: &str, file_path: &str) -> ValidationResult {
        let context = self.create_validation_context(file_path);
        let mut violations: Vec<RuleViolation> = Vec::new();

        for (_, rule) in &self.rules {
            if !self.is_rule_applicable(rule, &context) {
                continue;
            }

            if let Some(ref exceptions) = rule.exceptions {
                let file_basename = Path::new(file_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(file_path);
                if exceptions.iter().any(|e| e == file_basename) {
                    continue;
                }
            }

            if let Some(violation) = self.check_rule(rule, content, &context) {
                violations.push(violation);
            }
        }

        let summary = Summary {
            errors: violations.iter().filter(|v| matches!(v.severity, Severity::Error)).count(),
            warnings: violations.iter().filter(|v| matches!(v.severity, Severity::Warning)).count(),
            info: violations.iter().filter(|v| matches!(v.severity, Severity::Info)).count(),
        };

        ValidationResult {
            valid: summary.errors == 0,
            violations,
            summary,
        }
    }

    fn create_validation_context(&self, file_path: &str) -> ValidationContext {
        let relative_path = file_path
            .strip_prefix(&self.project_root.to_string_lossy().to_string())
            .unwrap_or(file_path)
            .trim_start_matches('/')
            .to_string();
        
        let file_type = self.get_file_type(&relative_path);

        ValidationContext {
            file_path: relative_path.clone(),
            file_type,
            is_ui_component: relative_path.contains("src/components/ui/"),
            is_shared_component: relative_path.contains("src/components/shared/"),
            is_hook: relative_path.contains("src/hooks/"),
            is_type_file: relative_path.contains("src/types/"),
            project_root: self.project_root.to_string_lossy().to_string(),
        }
    }

    fn get_file_type(&self, file_path: &str) -> String {
        match Path::new(file_path).extension().and_then(|e| e.to_str()) {
            Some("ts") => "ts".to_string(),
            Some("tsx") => "tsx".to_string(),
            Some("js") => "js".to_string(),
            Some("jsx") => "jsx".to_string(),
            Some("css") => "css".to_string(),
            Some("md") => "md".to_string(),
            Some(ext) => ext.to_string(),
            None => String::new(),
        }
    }

    fn is_rule_applicable(&self, rule: &Rule, context: &ValidationContext) -> bool {
        let patterns = match &rule.file_patterns {
            Some(p) => p,
            None => return true,
        };

        patterns.iter().any(|pattern| {
            let regex_pattern = pattern
                .replace("**", "(.+)")
                .replace("*", "[^/]+")
                .replace('?', ".");
            
            let regex_str = format!("(^|/){}$", regex_pattern);
            Regex::new(&regex_str)
                .map(|re| re.is_match(&context.file_path))
                .unwrap_or(false)
        })
    }

    fn check_rule(&self, rule: &Rule, content: &str, context: &ValidationContext) -> Option<RuleViolation> {
        let pattern = rule.pattern.as_ref()?;
        
        let (matched, line) = match pattern {
            RulePattern::Function(func) => {
                let m = func(content, context);
                (m, None)
            }
            RulePattern::String(s) => {
                let m = content.contains(s);
                let line = if m { self.find_line_number(content, s) } else { None };
                (m, line)
            }
            RulePattern::Regex(re) => {
                let m = re.is_match(content);
                let line = if m {
                    re.find(content).map(|m| self.get_line_number_from_index(content, m.start())).flatten()
                } else {
                    None
                };
                (m, line)
            }
        };

        if !matched {
            return None;
        }

        Some(RuleViolation {
            rule_id: rule.id.clone(),
            message: rule.description.clone(),
            line,
            column: None,
            severity: rule.severity,
            suggestion: rule.suggestion.clone(),
            category: format!("{:?}", rule.category).to_lowercase(),
        })
    }

    fn find_line_number(&self, content: &str, pattern: &str) -> Option<usize> {
        content.lines().enumerate()
            .find(|(_, line)| line.contains(pattern))
            .map(|(i, _)| i + 1)
    }

    fn get_line_number_from_index(&self, content: &str, index: usize) -> Option<usize> {
        if index >= content.len() {
            return None;
        }
        let before_index = &content[..index];
        Some(before_index.lines().count())
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.insert(rule.id.clone(), rule);
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        self.rules.remove(rule_id).is_some()
    }

    pub fn list_rules(&self) -> Vec<&Rule> {
        self.rules.values().collect()
    }

    pub fn get_rule(&self, rule_id: &str) -> Option<&Rule> {
        self.rules.get(rule_id)
    }

    pub fn reload_rules(&mut self) {
        self.rules.clear();
        self.load_builtin_rules();
        self.load_custom_rules();
    }
}
