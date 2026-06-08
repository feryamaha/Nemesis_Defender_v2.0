use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IAAction {
    pub action_type: String, // "edit", "create", "delete", "bash"
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub allowed: bool,
    pub reason: String,
    pub violated_rules: Vec<String>,
    pub severity: Severity,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone)]
pub struct RulePattern {
    pub name: String,
    pub pattern: Regex,
    pub message: String,
    pub rule: String,
    pub severity: Severity,
    pub suggestion: String,
}

pub struct IAActionValidator {
    rules_path: PathBuf,
    rule_patterns: Vec<RulePattern>,
}

impl IAActionValidator {
    pub fn new(rules_path: Option<&str>) -> Self {
        let rules_path = rules_path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".devin/rules"));

        let rule_patterns = Self::initialize_rule_patterns();

        Self {
            rules_path,
            rule_patterns,
        }
    }

    fn initialize_rule_patterns() -> Vec<RulePattern> {
        vec![
            RulePattern {
                name: "css-inline-prohibited".to_string(),
                pattern: Regex::new(r"style\s*=\s*\{[^}]*\}").unwrap(),
                message: "CSS inline é proibido pelo design-system-convention.md".to_string(),
                rule: "design-system-convention.md".to_string(),
                severity: Severity::Error,
                suggestion: "Mover estilos para classes Tailwind no tailwind.config.ts".to_string(),
            },
            RulePattern {
                name: "any-type-prohibited".to_string(),
                pattern: Regex::new(r":\s*any\b").unwrap(),
                message: "Uso de \"any\" é proibido pelo typescript-typing-convention.md".to_string(),
                rule: "typescript-typing-convention.md".to_string(),
                severity: Severity::Error,
                suggestion: "Criar tipo específico em src/types/ ou usar tipo mais específico".to_string(),
            },
            RulePattern {
                name: "inline-types-in-components".to_string(),
                pattern: Regex::new(r"interface\s+\w+Props\s*\{[^}]*\}").unwrap(),
                message: "Tipagem inline em componentes é proibida".to_string(),
                rule: "typescript-typing-convention.md".to_string(),
                severity: Severity::Error,
                suggestion: "Mover tipagem para src/types/ui/[componente].types.ts".to_string(),
            },
            RulePattern {
                name: "logic-in-pure-ui".to_string(),
                pattern: Regex::new(r"useState|useEffect").unwrap(),
                message: "Lógica em componentes UI pura é proibida".to_string(),
                rule: "ui-separation-convention.md".to_string(),
                severity: Severity::Error,
                suggestion: "Mover lógica para hooks em src/hooks/".to_string(),
            },
            RulePattern {
                name: "conditional-hooks".to_string(),
                pattern: Regex::new(r"if\s*\([^)]*\)\s*\{[^}]*useState|useEffect").unwrap(),
                message: "Hooks condicionais são proibidos".to_string(),
                rule: "react-hooks-patterns-rules.md".to_string(),
                severity: Severity::Error,
                suggestion: "Mover todos os hooks para o topo do componente".to_string(),
            },
            RulePattern {
                name: "sync-setstate-in-useeffect".to_string(),
                pattern: Regex::new(r"useEffect\([^)]*\)\s*\{[^}]*\b(set[A-Z]\w*|dispatch)\s*\([^)]*\)[^}]*\}").unwrap(),
                message: "setState síncrono no corpo do useEffect é proibido".to_string(),
                rule: "react-hooks-patterns-rules.md".to_string(),
                severity: Severity::Error,
                suggestion: "Usar callbacks ou lógica condicional antes de setState".to_string(),
            },
            RulePattern {
                name: "any-setstate-in-useeffect-body".to_string(),
                pattern: Regex::new(r"useEffect\([^)]*\)\s*\{[\s\S]*?\b(set[A-Z]\w*|dispatch)\s*\(").unwrap(),
                message: "Qualquer chamada de setState/dispatch no corpo do useEffect é proibida".to_string(),
                rule: "react-hooks-patterns-rules.md".to_string(),
                severity: Severity::Error,
                suggestion: "Mover setState para callback ou para fora do corpo do useEffect".to_string(),
            },
            RulePattern {
                name: "hex-colors-prohibited".to_string(),
                pattern: Regex::new(r"#[0-9a-fA-F]{3,6}\b").unwrap(),
                message: "Cores hexadecimais diretas são proibidas".to_string(),
                rule: "design-system-convention.md".to_string(),
                severity: Severity::Warning,
                suggestion: "Usar tokens do tailwind.config.ts".to_string(),
            },
        ]
    }

    pub fn validate_action(&self, action: &IAAction) -> ValidationResult {
        let mut violated_rules: Vec<String> = Vec::new();
        let mut suggestions: Vec<String> = Vec::new();
        let mut max_severity = Severity::Info;

        match action.action_type.as_str() {
            "edit" | "create" => {
                if let Some(ref content) = action.content {
                    let content_validation = self.validate_content(content, &action.target);
                    violated_rules.extend(content_validation.violated_rules);
                    suggestions.extend(content_validation.suggestions);
                    if content_validation.severity == Severity::Error {
                        max_severity = Severity::Error;
                    } else if content_validation.severity == Severity::Warning && max_severity == Severity::Info {
                        max_severity = Severity::Warning;
                    }
                }
            }
            "bash" => {
                let bash_validation = self.validate_bash_command(&action.target);
                violated_rules.extend(bash_validation.violated_rules);
                suggestions.extend(bash_validation.suggestions);
                if bash_validation.severity == Severity::Error {
                    max_severity = Severity::Error;
                } else if bash_validation.severity == Severity::Warning && max_severity == Severity::Info {
                    max_severity = Severity::Warning;
                }
            }
            "delete" => {
                let delete_validation = self.validate_delete_action(&action.target);
                violated_rules.extend(delete_validation.violated_rules);
                suggestions.extend(delete_validation.suggestions);
                if delete_validation.severity == Severity::Error {
                    max_severity = Severity::Error;
                } else if delete_validation.severity == Severity::Warning && max_severity == Severity::Info {
                    max_severity = Severity::Warning;
                }
            }
            _ => {}
        }

        let has_error = violated_rules.iter().any(|rule| {
            self.rule_patterns
                .iter()
                .find(|p| p.name == *rule)
                .map(|p| p.severity == Severity::Error)
                .unwrap_or(false)
        });

        let allowed = !has_error;
        let reason = if allowed {
            "Ação permitida".to_string()
        } else {
            format!("Violações detectadas: {}", violated_rules.join(", "))
        };

        ValidationResult {
            allowed,
            reason,
            violated_rules,
            severity: max_severity,
            suggestions,
        }
    }

    fn validate_content(&self, content: &str, file_path: &str) -> ValidationResult {
        let mut violated_rules: Vec<String> = Vec::new();
        let mut suggestions: Vec<String> = Vec::new();
        let mut max_severity = Severity::Info;

        let is_ui_component = file_path.contains("src/components/ui/")
            || file_path.contains("src/components/shared/");

        let advanced_validation = self.validate_advanced_react_hooks(content);
        violated_rules.extend(advanced_validation.violated_rules);
        suggestions.extend(advanced_validation.suggestions);
        if advanced_validation.severity == Severity::Error {
            max_severity = Severity::Error;
        }

        for pattern in &self.rule_patterns {
            if pattern.pattern.is_match(content) {
                if is_ui_component && pattern.name == "logic-in-pure-ui" {
                    violated_rules.push(pattern.name.clone());
                    suggestions.push(pattern.suggestion.clone());
                    max_severity = Severity::Error;
                } else if !is_ui_component || pattern.name != "logic-in-pure-ui" {
                    violated_rules.push(pattern.name.clone());
                    suggestions.push(pattern.suggestion.clone());
                    if pattern.severity == Severity::Error {
                        max_severity = Severity::Error;
                    } else if pattern.severity == Severity::Warning && max_severity == Severity::Info {
                        max_severity = Severity::Warning;
                    }
                }
            }
        }

        ValidationResult {
            allowed: max_severity != Severity::Error,
            reason: if max_severity == Severity::Error {
                "Conteúdo viola regras críticas".to_string()
            } else {
                "Conteúdo com advertências".to_string()
            },
            violated_rules,
            severity: max_severity,
            suggestions,
        }
    }

    fn validate_advanced_react_hooks(&self, content: &str) -> ValidationResult {
        let mut violated_rules: Vec<String> = Vec::new();
        let mut suggestions: Vec<String> = Vec::new();
        let mut severity = Severity::Info;

        let use_effect_set_state_pattern = Regex::new(
            r"useEffect\([^)]*\)\s*\{[\s\S]*?if\s*\([^)]*\)\s*\{[\s\S]*?\b(set[A-Z]\w*|dispatch)\s*\([^)]*\)[\s\S]*?\}"
        ).unwrap();
        if use_effect_set_state_pattern.is_match(content) {
            violated_rules.push("useeffect-setstate-direct-body".to_string());
            suggestions.push("Mover setState para dentro de callback ou usar lógica condicional antes".to_string());
            severity = Severity::Error;
        }

        let use_effect_any_set_state_pattern = Regex::new(
            r"useEffect\([^)]*\)\s*\{[\s\S]*?\b(set[A-Z]\w*|dispatch)\s*\([^)]*[^)]*\)[\s\S]*?\}"
        ).unwrap();
        if use_effect_any_set_state_pattern.is_match(content) && !content.contains("prev =>") {
            violated_rules.push("useeffect-setstate-no-callback".to_string());
            suggestions.push("Usar callback de setState: setPrev(prev => ({ ...prev, field: value }))".to_string());
            severity = Severity::Error;
        }

        let sync_set_state_pattern = Regex::new(
            r"useEffect\([^)]*\)\s*\{[^}]*\b(set[A-Z]\w*|dispatch)\s*\([^}]*\([^}]*\)[^}]*\}"
        ).unwrap();
        if sync_set_state_pattern.is_match(content) {
            violated_rules.push("sync-setstate-in-useeffect".to_string());
            suggestions.push("Evitar setState síncrono no corpo do useEffect".to_string());
            severity = Severity::Error;
        }

        let hooks_after_return_pattern = Regex::new(
            r"return\s+[^;]*;[\s\S]*?\b(useState|useEffect|useCallback|useMemo|useRef|useContext)\s*\("
        ).unwrap();
        if hooks_after_return_pattern.is_match(content) {
            violated_rules.push("hooks-after-return".to_string());
            suggestions.push("Mover todos os hooks para o topo do componente, antes de qualquer return".to_string());
            severity = Severity::Error;
        }

        let use_state_in_conditional_pattern = Regex::new(
            r"if\s*\([^)]*\)\s*\{[^}]*\buseState\s*\(|else\s*\{[^}]*\buseState\s*\("
        ).unwrap();
        if use_state_in_conditional_pattern.is_match(content) {
            violated_rules.push("useState-in-conditional".to_string());
            suggestions.push("Mover useState para o topo do componente, fora de condicionais".to_string());
            severity = Severity::Error;
        }

        ValidationResult {
            allowed: severity != Severity::Error,
            reason: if severity == Severity::Error {
                "Violações avançadas de React Hooks detectadas".to_string()
            } else {
                "React Hooks válidos".to_string()
            },
            violated_rules,
            severity,
            suggestions,
        }
    }

    fn validate_bash_command(&self, command: &str) -> ValidationResult {
        let mut violated_rules: Vec<String> = Vec::new();
        let mut suggestions: Vec<String> = Vec::new();
        let mut severity = Severity::Info;

        let prohibited_commands = vec![
            "rm -rf",
            "sudo",
            "chmod 777",
            "curl | bash",
            "wget | bash",
            "eval",
            "exec",
        ];

        for prohibited in prohibited_commands {
            if command.contains(prohibited) {
                violated_rules.push(format!("prohibited-command-{}", prohibited.replace(" ", "-")));
                suggestions.push(format!("Comando \"{}\" é perigoso e não permitido", prohibited));
                severity = Severity::Error;
            }
        }

        if command.contains("npm install") || command.contains("yarn add") || command.contains("bun add") {
            violated_rules.push("unauthorized-package-installation".to_string());
            suggestions.push("Instalações de pacotes requerem autorização explícita".to_string());
            severity = Severity::Error;
        }

        ValidationResult {
            allowed: severity != Severity::Error,
            reason: if severity == Severity::Error {
                "Comando não permitido".to_string()
            } else {
                "Comando permitido".to_string()
            },
            violated_rules,
            severity,
            suggestions,
        }
    }

    fn validate_delete_action(&self, file_path: &str) -> ValidationResult {
        let mut violated_rules: Vec<String> = Vec::new();
        let mut suggestions: Vec<String> = Vec::new();
        let mut severity = Severity::Info;

        let critical_files = vec![
            ".devin/",
            "src/types/",
            "package.json",
            "tsconfig.json",
            "tailwind.config.ts",
            ".gitignore",
        ];

        for critical in &critical_files {
            if file_path.starts_with(critical) {
                violated_rules.push("critical-file-deletion".to_string());
                suggestions.push(format!("Arquivo crítico \"{}\" não pode ser deletado", critical));
                severity = Severity::Error;
                break;
            }
        }

        ValidationResult {
            allowed: severity != Severity::Error,
            reason: if severity == Severity::Error {
                "Deleção não permitida".to_string()
            } else {
                "Deleção permitida".to_string()
            },
            violated_rules,
            severity,
            suggestions,
        }
    }

    pub fn validate_actions(&self, actions: &[IAAction]) -> Vec<ValidationResult> {
        actions.iter().map(|action| self.validate_action(action)).collect()
    }

    pub fn reload_rule_patterns(&mut self) {
        self.rule_patterns = Self::initialize_rule_patterns();
    }
}
