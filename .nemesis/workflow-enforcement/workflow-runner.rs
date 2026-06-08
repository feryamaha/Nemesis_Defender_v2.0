//! Workflow Runner for Nemesis Enforcement Engine
//! 
//! Orquestra a execução de workflows com enforcement de regras.

use std::collections::HashMap;
use std::path::Path;

use crate::types::{
    WorkflowDefinition,
    WorkflowRunnerResult,
    ExecutionOptions,
    EnforcementConfig,
    Violation,
    ViolationType,
};
use crate::workflow_parser::WorkflowParser;
use crate::workflow_catalog::WorkflowCatalog;
use crate::command_extractor::CommandExtractor;
use crate::workflow_enforcer::WorkflowEnforcer;
use crate::bash_tool_adapter::BashToolAdapter;
use crate::violation_logger::ViolationLogger;

/// Workflow Runner - Main execution engine
pub struct WorkflowRunner {
    enforcer: WorkflowEnforcer,
    bash_tool_adapter: BashToolAdapter,
    execution_options: ExecutionOptions,
}

impl WorkflowRunner {
    /// Create new runner with options
    pub fn new(options: ExecutionOptions) -> Self {
        let enforcer = WorkflowEnforcer::new(EnforcementConfig {
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
        });

        let bash_tool_adapter = BashToolAdapter::new(options.clone());

        Self {
            enforcer,
            bash_tool_adapter,
            execution_options: options,
        }
    }

    /// Create with default options
    pub fn with_defaults() -> Self {
        Self::new(ExecutionOptions::default())
    }

    /// Run a single workflow
    pub async fn run_workflow(&self, workflow_path: &str) -> Result<WorkflowRunnerResult, Box<dyn std::error::Error>> {
        let start_time = std::time::Instant::now();

        // Parse workflow
        let workflow = WorkflowParser::parse_workflow(workflow_path).await?;

        // Pre-execution checks
        let pre_check = self.enforcer.pre_execution_check(&workflow).await;
        if !pre_check.can_proceed {
            let violation = Violation {
                violation_type: ViolationType::RuleViolation,
                message: format!("Pre-execution check failed: {}", pre_check.reasons.join(", ")),
                rule: Some(".devin/rule-main-rules.md".to_string()),
                command: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
                llm_model: None,
                layer: Some("pretool".to_string()),
            };

            ViolationLogger::log_violation(&violation);

            return Ok(WorkflowRunnerResult {
                workflow: workflow.name,
                success: false,
                results: vec![],
                violations: vec![violation],
                execution_time: start_time.elapsed().as_millis() as f64,
            });
        }

        // Extract commands
        let commands = CommandExtractor::extract_executable_commands(&workflow.code_blocks);

        if commands.is_empty() {
            return Ok(WorkflowRunnerResult {
                workflow: workflow.name,
                success: true,
                results: vec![],
                violations: vec![],
                execution_time: start_time.elapsed().as_millis() as f64,
            });
        }

        // Enforce permissions
        let enforcement = self.enforcer.enforce_workflow_execution(
            &workflow,
            &commands,
        ).await;

        // Execute allowed commands
        let results = self.execute_with_bash_tool(
            &enforcement.allowed_commands,
            &self.execution_options,
        ).await;

        // Log blocked commands as violations
        let mut all_violations = enforcement.violations.clone();
        for blocked_command in &enforcement.blocked_commands {
            let violation = Violation {
                violation_type: ViolationType::PermissionDenied,
                message: "Command blocked by enforcement engine".to_string(),
                rule: Some(".devin/rule-main-rules.md".to_string()),
                command: Some(blocked_command.clone()),
                timestamp: chrono::Utc::now().to_rfc3339(),
                llm_model: None,
                layer: Some("pretool".to_string()),
            };

            ViolationLogger::log_violation(&violation);
            all_violations.push(violation);
        }

        let success = enforcement.blocked_commands.is_empty()
            && results.iter().all(|r| r.exit_code == 0);

        Ok(WorkflowRunnerResult {
            workflow: workflow.name,
            success,
            results,
            violations: all_violations,
            execution_time: start_time.elapsed().as_millis() as f64,
        })
    }

    /// Execute commands with bash tool
    async fn execute_with_bash_tool(
        &self,
        commands: &[String],
        _options: &ExecutionOptions,
    ) -> Vec<crate::types::CommandResult> {
        let mut results = vec![];

        for command in commands {
            let result = self.bash_tool_adapter.execute_command(command).await;
            let exit_code = result.exit_code;
            results.push(result);

            if exit_code != 0 {
                eprintln!("Command failed with exit code {}: {}", exit_code, command);
                break;
            }
        }

        results
    }

    /// Run all workflows in a directory
    pub async fn run_all_workflows(
        &self,
        base_path: &str,
    ) -> Vec<WorkflowRunnerResult> {
        let workflow_files = WorkflowCatalog::list_workflows(Some(base_path)).await;
        let mut results = vec![];

        for workflow_file in workflow_files {
            match self.run_workflow(&workflow_file).await {
                Ok(result) => results.push(result),
                Err(error) => {
                    eprintln!("Failed to run workflow {}: {}", workflow_file, error);
                }
            }
        }

        results
    }

    /// Run workflow by name
    pub async fn run_workflow_by_name(
        &self,
        name: &str,
        base_path: &str,
    ) -> Option<WorkflowRunnerResult> {
        match WorkflowCatalog::get_workflow_by_name(name, Some(base_path)).await {
            Some(workflow_path) => {
                match self.run_workflow(&workflow_path).await {
                    Ok(result) => Some(result),
                    Err(_) => None,
                }
            }
            None => {
                eprintln!("Workflow not found: {}", name);
                None
            }
        }
    }

    /// Validate a single workflow
    pub async fn validate_workflow(&self, workflow_path: &str) -> WorkflowValidationResult {
        match WorkflowParser::parse_workflow(workflow_path).await {
            Ok(workflow) => {
                let validation = self.enforcer.validate_workflow(&workflow).await;

                WorkflowValidationResult {
                    is_valid: validation.is_valid,
                    errors: validation.errors.iter().map(|e| e.message.clone()).collect(),
                    warnings: validation.warnings.iter().map(|w| w.message.clone()).collect(),
                }
            }
            Err(error) => WorkflowValidationResult {
                is_valid: false,
                errors: vec![error.to_string()],
                warnings: vec![],
            },
        }
    }

    /// Validate all workflows
    pub async fn validate_all_workflows(&self, base_path: &str) -> AllWorkflowsValidationResult {
        let workflow_files = WorkflowCatalog::list_workflows(Some(base_path)).await;
        let mut results = vec![];
        let mut valid = 0;
        let mut invalid = 0;

        for workflow_file in workflow_files {
            let validation = self.validate_workflow(&workflow_file).await;
            results.push(WorkflowValidationItem {
                workflow: workflow_file.clone(),
                is_valid: validation.is_valid,
                errors: validation.errors,
                warnings: validation.warnings,
            });

            if validation.is_valid {
                valid += 1;
            } else {
                invalid += 1;
            }
        }

        AllWorkflowsValidationResult {
            valid,
            invalid,
            total: results.len(),
            results,
        }
    }

    /// Get execution statistics
    pub fn get_execution_statistics(&self) -> ExecutionStatistics {
        let stats_value = ViolationLogger::get_statistics();
        let total = stats_value.get("total")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .unwrap_or(0);
        ExecutionStatistics {
            violations: ViolationStatistics { total },
        }
    }

    /// Generate report
    pub fn generate_report(&self) -> String {
        let stats = self.get_execution_statistics();
        let violations = ViolationLogger::generate_report();

        let mut report = String::new();
        report.push_str("# Workflow Runner Report\n\n");
        report.push_str("## Execution Statistics\n\n");
        report.push_str(&format!("- Total Violations: {}\n\n", stats.violations.total));
        report.push_str(&violations);

        report
    }

    /// Reset runner state
    pub fn reset(&self) {
        self.enforcer.reset();
        ViolationLogger::clear_violations();
    }

    /// Update execution options
    pub fn update_execution_options(&mut self, options: ExecutionOptions) {
        self.execution_options = options.clone();
        self.bash_tool_adapter = BashToolAdapter::new(options);
    }
}

/// Workflow validation result
pub struct WorkflowValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Workflow validation item for batch validation
pub struct WorkflowValidationItem {
    pub workflow: String,
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// All workflows validation result
pub struct AllWorkflowsValidationResult {
    pub valid: usize,
    pub invalid: usize,
    pub total: usize,
    pub results: Vec<WorkflowValidationItem>,
}

/// Execution statistics
pub struct ExecutionStatistics {
    pub violations: ViolationStatistics,
}

/// Violation statistics
pub struct ViolationStatistics {
    pub total: usize,
}

impl Default for crate::types::ExecutionOptions {
    fn default() -> Self {
        Self {
            max_call_depth: Some(10),
            max_command_count: Some(100),
            max_loop_iterations: Some(1000),
            network_access: Some(false),
            allowed_urls: None,
            cwd: None,
            env: None,
            files: None,
        }
    }
}
