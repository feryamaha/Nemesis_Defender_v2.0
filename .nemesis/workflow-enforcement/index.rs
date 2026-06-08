//! Core types and interfaces re-exports
//! Nemesis Workflow Enforcement Engine - Public API

// Re-export types
pub use crate::types::{
    ExecutionOptions,
    WorkflowDefinition,
    CodeBlock,
    ValidationResult,
    ValidationError,
    ValidationWarning,
    CommandResult,
    WorkflowRunnerResult,
    Violation,
    PermissionRequest,
    EnforcementConfig,
    PreToolValidationResult,
    PreToolValidationInput,
};

// Main classes and functions
pub use crate::workflow_parser::WorkflowParser;
pub use crate::workflow_catalog::WorkflowCatalog;
pub use crate::command_extractor::CommandExtractor;
pub use crate::workflow_validators::WorkflowValidators;
pub use crate::workflow_enforcer::WorkflowEnforcer;
pub use crate::bash_tool_adapter::BashToolAdapter;
pub use crate::permission_gate::PermissionGate;
pub use crate::violation_logger::ViolationLogger;
pub use crate::workflow_runner::WorkflowRunner;

// Nemesis v2 - Hook modules (automatic enforcement)
pub use crate::hook::code_validator::validate_code_content;
pub use crate::hook::scope_validator::{
    validate_file_scope,
    has_scope_active,
    read_scope,
};

// Environment Detection and Package Manager Adaptation
pub use crate::detectors::environment_detector::{
    detect_environment,
    validate_environment_compatibility,
    EnvironmentInfo,
};

// Re-export modules that will be created in next phases
pub use crate::validators::ia_action_validator::{
    IAActionValidator,
    IAAction,
    ValidationResult as IAValidationResult,
};
pub use crate::engine::rule_engine::{
    RuleEngine,
    Rule,
    ValidationContext as EngineValidationContext,
    RuleViolation,
    ValidationResult as EngineValidationResult,
};
pub use crate::behavioral::override_system::{
    BehavioralOverride,
    ComplianceResult,
    BehavioralPattern,
};
pub use crate::analysis::gap_detector::{
    GapDetector,
    GapAnalysis,
    RuleComprehension,
    ActionPlan,
};

// Terminal Reader Service - Leitura via terminal com fallbacks
pub use crate::services::terminal_reader_service::TerminalReaderService;
pub use crate::services::terminal_reader_logger::TerminalReaderLogger;
pub use crate::services::terminal_reader_types::{
    ReadOptions,
    ReadResult,
    SearchResult,
    PathValidation,
    LogEntry,
    TerminalCommand,
};

/// Run workflow with enforcement wrapper
pub async fn run_workflow_with_enforcement(
    workflow_path: &str,
    options: ExecutionOptions,
) -> Result<crate::types::WorkflowRunnerResult, Box<dyn std::error::Error>> {
    let runner = WorkflowRunner::new(options);
    runner.run_workflow(workflow_path).await
}

/// Validate and run workflow
pub async fn validate_and_run_workflow(
    workflow_path: &str,
    options: ExecutionOptions,
) -> Result<crate::types::WorkflowRunnerResult, Box<dyn std::error::Error>> {
    let runner = WorkflowRunner::new(options.clone());

    // First validate
    let validation = runner.validate_workflow(workflow_path).await;
    if !validation.is_valid {
        let errors = validation.errors.join(", ");
        return Err(format!("Workflow validation failed: {}", errors).into());
    }

    // Then run
    runner.run_workflow(workflow_path).await
}

/// Create enforcement config with defaults
pub fn create_enforcement_config(
    overrides: Option<crate::types::EnforcementConfig>,
) -> crate::types::EnforcementConfig {
    let mut config = crate::types::EnforcementConfig {
        block_unauthorized_commands: true,
        log_violations: true,
        require_permission_for_file_edits: true,
        allowed_languages: vec![
            "bash".to_string(),
            "javascript".to_string(),
            "typescript".to_string(),
            "python".to_string(),
            "markdown".to_string(),
        ],
        mandatory_rules: vec![".devin/rules/rule-main-rules.md".to_string()],
        mode: None,
    };

    if let Some(overrides) = overrides {
        config.block_unauthorized_commands = overrides.block_unauthorized_commands;
        config.log_violations = overrides.log_violations;
        config.require_permission_for_file_edits = overrides.require_permission_for_file_edits;
        if !overrides.allowed_languages.is_empty() {
            config.allowed_languages = overrides.allowed_languages;
        }
        if !overrides.mandatory_rules.is_empty() {
            config.mandatory_rules = overrides.mandatory_rules;
        }
        config.mode = overrides.mode.or(config.mode);
    }

    config
}

/// Setup enforcement engine
pub async fn setup_enforcement_engine() -> Result<SetupResult, Box<dyn std::error::Error>> {
    // Detectar ambiente
    let environment = detect_environment();

    // Validar compatibilidade
    let compatibility = validate_environment_compatibility(&environment);

    Ok(SetupResult {
        environment,
        is_compatible: compatibility.compatible,
        issues: compatibility.issues,
        recommendations: compatibility.recommendations,
    })
}

/// Result from setup enforcement engine
pub struct SetupResult {
    pub environment: crate::detectors::environment_detector::EnvironmentInfo,
    pub is_compatible: bool,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
}
