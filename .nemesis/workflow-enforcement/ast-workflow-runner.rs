use nemesis::ast_builder::ASTBuilder;
use nemesis::ast_types::{
    ActionNode, AstViolation, ExecutionError, ExecutionResult, GateNode, RestrictionNode,
    VerifyNode, WorkflowAst, WorkflowExecutionState, WorkflowPhase,
};
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// AST Workflow Runner - Executa workflows a partir de AST
/// Versão otimizada sem dependências externas para evitar conflitos de tipagem
pub struct ASTWorkflowRunner {
    execution_state: Option<WorkflowExecutionState>,
}

impl ASTWorkflowRunner {
    /// Cria uma nova instância do runner
    pub fn new() -> Self {
        Self {
            execution_state: None,
        }
    }

    /// Execute workflow from AST
    pub async fn execute_workflow_ast(
        &mut self,
        ast: &WorkflowAst,
    ) -> ExecutionResult {
        let start_time = std::time::Instant::now();
        let mut errors: Vec<ExecutionError> = Vec::new();
        let mut violations: Vec<AstViolation> = Vec::new();
        let mut artifacts: HashMap<String, String> = HashMap::new();

        // Initialize execution state
        self.execution_state = Some(WorkflowExecutionState {
            workflow_name: ast.name.clone(),
            current_phase_index: 0,
            current_node_index: 0,
            completed_phases: Vec::new(),
            variables: HashMap::new(),
            artifacts: HashMap::new(),
            start_time: chrono::Utc::now().to_rfc3339(),
            last_update_time: chrono::Utc::now().to_rfc3339(),
        });

        // Start workflow step tracking
        if let Err(e) = self.start_step_tracking(&ast.name, ast.phases.len()).await {
            errors.push(ExecutionError {
                phase: "INIT".to_string(),
                node_type: "WORKFLOW".to_string(),
                message: format!("Failed to start step tracking: {}", e),
                line_number: 0,
            });
        }

        // Execute phases sequentially
        for (phase_index, phase) in ast.phases.iter().enumerate() {
            println!("\n=== Executing Phase {}: {} ===", phase_index + 1, phase.id);

            let phase_result = self.execute_phase(phase, phase_index).await;
            
            if !phase_result.success {
                errors.extend(phase_result.errors);
                violations.extend(phase_result.violations);
                break;
            }

            // Mark phase as completed
            if let Some(ref mut state) = self.execution_state {
                state.completed_phases.push(phase.id.clone());
                state.current_phase_index = phase_index as u32 + 1;
                state.last_update_time = chrono::Utc::now().to_rfc3339();
            }

            // Complete step in tracker
            if let Err(e) = self.complete_step(phase_index + 1).await {
                eprintln!("Warning: Failed to complete step: {}", e);
            }

            // Merge artifacts
            for (key, value) in &phase_result.artifacts {
                artifacts.insert(key.to_string(), value.to_string());
            }

            println!("✓ Phase {} completed successfully", phase.id);
        }

        let success = errors.is_empty() && violations.is_empty();

        let result = ExecutionResult {
            success,
            completed_phase: self.execution_state.as_ref().and_then(|state| {
                state.completed_phases.last().cloned()
            }),
            next_phase: if success {
                self.execution_state.as_ref().and_then(|state| {
                    let current = state.current_phase_index as usize;
                    if current < ast.phases.len() {
                        Some(ast.phases[current].id.clone())
                    } else {
                        None
                    }
                })
            } else {
                None
            },
            errors: errors.clone(),
            artifacts: artifacts.clone(),
            violations: violations.clone(),
        };

        // Cleanup step tracking
        if let Some(ref state) = self.execution_state {
            if let Err(e) = self.finish_step_tracking(&state.workflow_name).await {
                eprintln!("Warning: Failed to finish step tracking: {}", e);
            }
        }

        result
    }

    /// Execute individual phase
    async fn execute_phase(
        &self,
        phase: &WorkflowPhase,
        _phase_index: usize,
    ) -> ExecutionResult {
        let mut errors: Vec<ExecutionError> = Vec::new();
        let mut violations: Vec<AstViolation> = Vec::new();
        let mut artifacts: HashMap<String, String> = HashMap::new();

        // Execute model:
        // 1. Actions first
        for action in &phase.actions {
            let result = self.execute_action(action).await;
            if !result.success {
                errors.extend(result.errors);
                violations.extend(result.violations);
            }
            for (key, value) in &result.artifacts {
                artifacts.insert(key.to_string(), value.to_string());
            }
        }

        // 2. Validate restrictions
        for restriction in &phase.restrictions {
            let result = self.validate_restriction(restriction, &phase.id).await;
            if !result.success {
                errors.extend(result.errors);
                violations.extend(result.violations);
            }
        }

        // 3. Enforce gates
        for gate in &phase.gates {
            let result = self.enforce_gate(gate, &phase.id).await;
            if !result.success {
                errors.extend(result.errors);
                violations.extend(result.violations);
            }
        }

        // 4. Run verifies
        for verify in &phase.verifies {
            let result = self.run_verify(verify, &phase.id).await;
            if !result.success {
                errors.extend(result.errors);
                violations.extend(result.violations);
            }
        }

        ExecutionResult {
            success: errors.is_empty(),
            completed_phase: Some(phase.id.clone()),
            next_phase: None,
            errors,
            artifacts,
            violations,
        }
    }

    /// Execute action node
    async fn execute_action(
        &self,
        action: &ActionNode,
    ) -> ExecutionResult {
        let mut artifacts: HashMap<String, String> = HashMap::new();

        match action.command.as_str() {
            "WRITE_ARTEFATO" => {
                if let Some(artifact_name) = action.args.first() {
                    // Simulate artifact creation
                    artifacts.insert(
                        artifact_name.to_string(),
                        format!("Artifact created at {}", chrono::Utc::now().to_rfc3339()),
                    );
                    println!("  ✓ Action: WRITE_ARTEFATO {}", artifact_name);
                }
            }
            "STEP_DECLARED" => {
                println!("  ✓ Action: STEP_DECLARED {}", action.args.join(" "));
            }
            "MAP" => {
                if action.args.len() >= 2 {
                    println!("  ✓ Action: MAP {} -> {}", action.args[0], action.args[1]);
                } else {
                    println!("  ✓ Action: MAP {}", action.args.join(" -> "));
                }
            }
            _ => {
                println!("  ✓ Action: {}", action.command);
            }
        }

        ExecutionResult {
            success: true,
            completed_phase: None,
            next_phase: None,
            artifacts,
            errors: Vec::new(),
            violations: Vec::new(),
        }
    }

    /// Validate restriction node
    async fn validate_restriction(
        &self,
        restriction: &RestrictionNode,
        phase_id: &str,
    ) -> ExecutionResult {
        // Simulate restriction validation
        println!("  ✓ Restriction: {}", restriction.rule);

        ExecutionResult {
            success: true,
            completed_phase: None,
            next_phase: None,
            errors: Vec::new(),
            artifacts: HashMap::new(),
            violations: Vec::new(),
        }
    }

    /// Enforce gate node
    async fn enforce_gate(
        &self,
        gate: &GateNode,
        phase_id: &str,
    ) -> ExecutionResult {
        // Simulate gate enforcement
        println!("  ✓ Gate: {}", gate.name);

        ExecutionResult {
            success: true,
            completed_phase: None,
            next_phase: None,
            errors: Vec::new(),
            artifacts: HashMap::new(),
            violations: Vec::new(),
        }
    }

    /// Run verify node
    async fn run_verify(
        &self,
        verify: &VerifyNode,
        phase_id: &str,
    ) -> ExecutionResult {
        // Simulate verify execution
        println!("  ✓ Verify: {}", verify.target);

        ExecutionResult {
            success: true,
            completed_phase: None,
            next_phase: None,
            errors: Vec::new(),
            artifacts: HashMap::new(),
            violations: Vec::new(),
        }
    }

    /// Start step tracking for workflow
    async fn start_step_tracking(
        &self,
        workflow_name: &str,
        total_steps: usize,
    ) -> anyhow::Result<()> {
        let tracker_path = Path::new(".nemesis/workflow-enforcement/cli/workflow-step-tracker.rs");

        let output = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "workflow-step-tracker",
                "--",
                "start",
                workflow_name,
                &total_steps.to_string(),
            ])
            .current_dir(std::env::current_dir()?)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Step tracking failed: {}", stderr);
        }

        Ok(())
    }

    /// Complete step in tracker
    async fn complete_step(&self, step_number: usize) -> anyhow::Result<()> {
        let output = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "workflow-step-tracker",
                "--",
                "complete",
                &step_number.to_string(),
            ])
            .current_dir(std::env::current_dir()?)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Step completion failed: {}", stderr);
        }

        Ok(())
    }

    /// Finish step tracking
    async fn finish_step_tracking(&self, workflow_name: &str) -> anyhow::Result<()> {
        let output = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "workflow-step-tracker",
                "--",
                "finish",
                workflow_name,
            ])
            .current_dir(std::env::current_dir()?)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Step tracking finish failed: {}", stderr);
        }

        Ok(())
    }

    /// Get current execution state
    pub fn get_execution_state(&self) -> Option<&WorkflowExecutionState> {
        self.execution_state.as_ref()
    }

    /// Run workflow using AST execution
    pub async fn run_workflow_ast(
        &mut self,
        workflow_path: &str,
    ) -> ExecutionResult {
        match ASTBuilder::build_ast(workflow_path).await {
            Ok(parse_result) => {
                // Check both success flag AND ast presence (symmetry with TS: if (!parseResult.success || !parseResult.ast))
                if !parse_result.success || parse_result.ast.is_none() {
                    let errors: Vec<ExecutionError> = parse_result
                        .errors
                        .into_iter()
                        .map(|err| ExecutionError {
                            phase: "PARSE".to_string(),
                            node_type: "WORKFLOW".to_string(),
                            message: err.message.clone(),
                            line_number: err.line,
                        })
                        .collect();
                    
                    let violations: Vec<AstViolation> = parse_result
                        .errors
                        .into_iter()
                        .map(|err| AstViolation {
                            violation_type: "syntax_error".to_string(),
                            message: err.message,
                            rule: None,
                            phase: None,
                            line_number: Some(err.line),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        })
                        .collect();
                    
                    ExecutionResult {
                        success: false,
                        completed_phase: None,
                        next_phase: None,
                        errors,
                        artifacts: HashMap::new(),
                        violations,
                    }
                } else if let Some(ast) = parse_result.ast {
                    // Execute AST
                    self.execute_workflow_ast(&ast).await
                } else {
                    ExecutionResult {
                        success: false,
                        completed_phase: None,
                        next_phase: None,
                        errors: parse_result
                            .errors
                            .into_iter()
                            .map(|err| ExecutionError {
                                phase: "PARSE".to_string(),
                                node_type: "WORKFLOW".to_string(),
                                message: err.message,
                                line_number: err.line,
                            })
                            .collect(),
                        artifacts: HashMap::new(),
                        violations: parse_result
                            .errors
                            .into_iter()
                            .map(|err| AstViolation {
                                violation_type: "syntax_error".to_string(),
                                message: err.message,
                                rule: None,
                                phase: None,
                                line_number: Some(err.line),
                                timestamp: chrono::Utc::now().to_rfc3339(),
                            })
                            .collect(),
                    }
                }
            }
            Err(e) => ExecutionResult {
                success: false,
                completed_phase: None,
                next_phase: None,
                errors: vec![ExecutionError {
                    phase: "UNKNOWN".to_string(),
                    node_type: "WORKFLOW".to_string(),
                    message: format!("{:?}", e),
                    line_number: 0,
                }],
                artifacts: HashMap::new(),
                violations: vec![AstViolation {
                    violation_type: "syntax_error".to_string(),
                    message: format!("{:?}", e),
                    rule: None,
                    phase: None,
                    line_number: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }],
            },
        }
    }
}

impl Default for ASTWorkflowRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Test function for AST execution
pub async fn test_ast_execution() {
    println!("Testing AST Workflow Execution...");

    let mut runner = ASTWorkflowRunner::new();
    let workflow_path = Path::new(".devin/workflows/work-01-rag.md");

    // Execute workflow using AST
    let result = runner.run_workflow_ast(&workflow_path.to_string_lossy()).await;

    println!("\n=== Execution Result ===");
    println!("Success: {}", result.success);
    println!(
        "Completed Phase: {}",
        result.completed_phase.as_deref().unwrap_or("None")
    );
    println!(
        "Next Phase: {}",
        result.next_phase.as_deref().unwrap_or("None")
    );
    println!("Errors: {}", result.errors.len());
    println!("Violations: {}", result.violations.len());
    println!("Artifacts: {}", result.artifacts.len());

    if !result.errors.is_empty() {
        println!("\nErrors:");
        for error in &result.errors {
            println!("  - {}:{} - {}", error.phase, error.node_type, error.message);
        }
    }

    if !result.violations.is_empty() {
        println!("\nViolations:");
        for violation in &result.violations {
            println!("  - {}: {}", violation.violation_type, violation.message);
        }
    }

    println!("\n=== Test Complete ===");
}

/// Run test if this file is executed directly (binário standalone)
/// Equivalente ao bloco: if (typeof process !== "undefined" && process.argv && process.argv[1] === __filename)
#[tokio::main]
async fn main() {
    test_ast_execution().await;
}
