use crate::types::{ValidationError, ValidationResult, ValidationWarning, WorkflowDefinition};
use regex::Regex;

pub struct WorkflowValidators;

lazy_static::lazy_static! {
    static ref MANDATORY_RULES: Vec<&'static str> = vec![
        ".devin/rules/rule-main-rules.md",
        ".devin/rules/origin-rules.md",
    ];

    static ref ALLOWED_LANGUAGES: Vec<&'static str> = vec![
        "bash", "sh", "shell", "powershell", "ps1", "javascript", "js",
        "typescript", "ts", "python", "py", "markdown", "md", "text",
        "json", "yaml", "yml", "xml", "sql", "dockerfile", "docker-compose",
    ];
}

impl WorkflowValidators {
    pub fn validate_mandatory_rules(workflow: &WorkflowDefinition) -> ValidationResult {
        let mut errors: Vec<ValidationError> = Vec::new();
        let mut warnings: Vec<ValidationWarning> = Vec::new();

        // Check if mandatory rules are referenced in the content
        for rule in MANDATORY_RULES.iter() {
            if !workflow.content.contains(*rule) {
                errors.push(ValidationError {
                    code: "MISSING_MANDATORY_RULE".to_string(),
                    message: format!("Mandatory rule reference missing: {}", rule),
                    severity: "error".to_string(),
                    line: None,
                });
            }
        }

        // Check if workflow has proper structure
        if !workflow.content.contains("##") {
            warnings.push(ValidationWarning {
                code: "MISSING_STRUCTURE".to_string(),
                message: "Workflow appears to lack proper markdown structure with ## headers".to_string(),
                line: None,
            });
        }

        ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
        }
    }

    pub fn validate_allowed_languages(workflow: &WorkflowDefinition) -> ValidationResult {
        let mut errors: Vec<ValidationError> = Vec::new();
        let mut warnings: Vec<ValidationWarning> = Vec::new();

        for block in &workflow.code_blocks {
            let language = block.language.to_lowercase();

            if !ALLOWED_LANGUAGES.contains(&language.as_str()) && language != "text" {
                errors.push(ValidationError {
                    code: "UNSUPPORTED_LANGUAGE".to_string(),
                    message: format!("Unsupported language '{}' at line {}", block.language, block.line_number),
                    severity: "error".to_string(),
                    line: Some(block.line_number),
                });
            }
        }

        ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
        }
    }

    pub fn validate_execution_sequence(workflow: &WorkflowDefinition) -> ValidationResult {
        let mut errors: Vec<ValidationError> = Vec::new();
        let mut warnings: Vec<ValidationWarning> = Vec::new();

        let content = workflow.content.to_lowercase();

        // Check for proper sequence indicators
        let sequence_indicators = [
            "1.", "2.", "3.", "4.", "5.",
            "primeiro", "segundo", "terceiro", "quarto", "quinto",
            "first", "second", "third", "fourth", "fifth",
            "passo", "step", "etapa",
        ];

        let has_sequence = sequence_indicators.iter().any(|indicator| content.contains(indicator));

        if !has_sequence && workflow.code_blocks.len() > 1 {
            warnings.push(ValidationWarning {
                code: "UNCLEAR_SEQUENCE".to_string(),
                message: "Multiple code blocks found but execution sequence is unclear".to_string(),
                line: None,
            });
        }

        // Check for dangerous patterns
        let dangerous_patterns: Vec<Regex> = vec![
            Regex::new(r"rm\s+-rf\s+/").unwrap(),     // rm -rf /
            Regex::new(r"sudo\s+rm").unwrap(),        // sudo rm
            Regex::new(r"format\s+c:").unwrap(),      // format c:
            Regex::new(r"dd\s+if=").unwrap(),          // dd if=
            Regex::new(r">\s*/dev/null").unwrap(),    // > /dev/null with important data
        ];

        for pattern in dangerous_patterns {
            if pattern.is_match(&workflow.content) {
                errors.push(ValidationError {
                    code: "DANGEROUS_COMMAND".to_string(),
                    message: "Potentially dangerous command pattern detected".to_string(),
                    severity: "error".to_string(),
                    line: None,
                });
            }
        }

        ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
        }
    }

    pub fn validate_workflow_completeness(workflow: &WorkflowDefinition) -> ValidationResult {
        let mut errors: Vec<ValidationError> = Vec::new();
        let mut warnings: Vec<ValidationWarning> = Vec::new();

        // Check if workflow has a title
        let title_pattern = Regex::new(r"^#\s+").unwrap();
        if !title_pattern.is_match(&workflow.content) {
            warnings.push(ValidationWarning {
                code: "MISSING_TITLE".to_string(),
                message: "Workflow should have a title (starting with #)".to_string(),
                line: None,
            });
        }

        // Check if workflow has sections
        let sections: Vec<_> = workflow.content.match_indices("##").collect();
        if sections.len() < 2 {
            warnings.push(ValidationWarning {
                code: "INSUFFICIENT_SECTIONS".to_string(),
                message: "Workflow should have multiple sections (starting with ##)".to_string(),
                line: None,
            });
        }

        // Check if workflow has executable content
        let executable_blocks: Vec<_> = workflow.code_blocks.iter().filter(|b| b.is_executable).collect();
        if executable_blocks.is_empty() {
            warnings.push(ValidationWarning {
                code: "NO_EXECUTABLE_CONTENT".to_string(),
                message: "Workflow has no executable code blocks".to_string(),
                line: None,
            });
        }

        ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
        }
    }

    pub fn validate_all(workflow: &WorkflowDefinition) -> ValidationResult {
        let mut all_errors: Vec<ValidationError> = Vec::new();
        let mut all_warnings: Vec<ValidationWarning> = Vec::new();

        // Run all validations
        let validations = [
            Self::validate_mandatory_rules(workflow),
            Self::validate_allowed_languages(workflow),
            Self::validate_execution_sequence(workflow),
            Self::validate_workflow_completeness(workflow),
        ];

        for validation in validations {
            all_errors.extend(validation.errors);
            all_warnings.extend(validation.warnings);
        }

        ValidationResult {
            is_valid: all_errors.is_empty(),
            errors: all_errors,
            warnings: all_warnings,
        }
    }
}
