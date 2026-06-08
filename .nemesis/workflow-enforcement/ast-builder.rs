use crate::ast_types::{DSLParseResult, WorkflowAST, WorkflowPhase};
use std::collections::HashMap;
use std::path::Path;

pub struct ASTBuilder;

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    pub phases: Vec<String>,
    pub total_actions: usize,
    pub total_gates: usize,
    pub total_restrictions: usize,
    pub critical_path: Vec<String>,
}

impl ASTBuilder {
    /// Build AST from workflow file
    pub async fn build_ast(workflow_path: &str) -> anyhow::Result<DSLParseResult> {
        crate::workflow_parser::WorkflowParser::parse_workflow_to_ast(workflow_path).await
    }

    /// Build ASTs from multiple workflow files
    pub async fn build_multiple_asts(workflow_paths: &[String]) -> Vec<DSLParseResult> {
        let mut results = Vec::new();
        
        for path in workflow_paths {
            match Self::build_ast(path).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    eprintln!("Failed to build AST for {}: {}", path, e);
                    results.push(crate::ast_types::DSLParseResult {
                        success: false,
                        ast: None,
                        errors: vec![crate::ast_types::ParseError {
                            line: 1,
                            message: e.to_string(),
                            error_type: "parse".to_string(),
                        }],
                        warnings: vec![],
                    });
                }
            }
        }
        
        results
    }

    /// Build AST from workflow directory
    pub async fn build_ast_from_directory(dir_path: &str) -> Vec<DSLParseResult> {
        match tokio::fs::read_dir(dir_path).await {
            Ok(mut entries) => {
                let mut workflow_files = Vec::new();
                
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if let Some(name) = path.file_name() {
                        let name_str = name.to_string_lossy();
                        if name_str.ends_with(".md") {
                            workflow_files.push(path.to_string_lossy().to_string());
                        }
                    }
                }
                
                Self::build_multiple_asts(&workflow_files).await
            }
            Err(e) => {
                eprintln!("Failed to read directory {}: {}", dir_path, e);
                Vec::new()
            }
        }
    }

    /// Generate example AST from work-01-rag.md
    pub async fn generate_example_ast() -> Option<WorkflowAST> {
        let workflow_path = Path::new(".devin/workflows/work-01-rag.md");
        
        match Self::build_ast(&workflow_path.to_string_lossy()).await {
            Ok(result) => result.ast,
            Err(e) => {
                eprintln!("Failed to generate example AST: {}", e);
                None
            }
        }
    }

    /// Validate AST structure
    pub fn validate_ast(ast: &WorkflowAST) -> ValidationResult {
        let mut errors: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        // Basic structure validation
        if ast.name.is_empty() {
            errors.push("Workflow name is required".to_string());
        }

        if ast.phases.is_empty() {
            errors.push("At least one phase is required".to_string());
        }

        // Phase validation
        for (index, phase) in ast.phases.iter().enumerate() {
            if phase.id.is_empty() {
                errors.push(format!("Phase {} missing ID", index + 1));
            }

            // Check for required nodes in critical phases
            if phase.id.contains("MODEL") && phase.actions.is_empty() {
                warnings.push(format!("Phase {} has no actions - may be incomplete", phase.id));
            }

            // Validate gate dependencies
            for gate in &phase.gates {
                if gate.name.is_empty() {
                    errors.push(format!("Gate in phase {} missing name", phase.id));
                }
            }

            // Verify restriction syntax
            for restriction in &phase.restrictions {
                if restriction.rule.is_empty() {
                    errors.push(format!("Restriction in phase {} missing rule", phase.id));
                }
            }
        }

        ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
        }
    }

    /// Extract execution plan from AST
    pub fn extract_execution_plan(ast: &WorkflowAST) -> ExecutionPlan {
        let mut phases: Vec<String> = Vec::new();
        let mut total_actions = 0;
        let mut total_gates = 0;
        let mut total_restrictions = 0;
        let mut critical_path: Vec<String> = Vec::new();

        for phase in &ast.phases {
            phases.push(phase.id.clone());
            total_actions += phase.actions.len();
            total_gates += phase.gates.len();
            total_restrictions += phase.restrictions.len();

            // Add critical nodes to critical path
            for gate in &phase.gates {
                critical_path.push(format!("{}:GATE:{}", phase.id, gate.name));
            }

            for action in &phase.actions {
                if action.command.contains("WRITE") || action.command.contains("STEP_DECLARED") {
                    critical_path.push(format!("{}:ACTION:{}", phase.id, action.command));
                }
            }
        }

        ExecutionPlan {
            phases,
            total_actions,
            total_gates,
            total_restrictions,
            critical_path,
        }
    }

    /// Export AST to JSON for inspection
    pub fn export_ast(ast: &WorkflowAST, output_path: Option<&str>) -> anyhow::Result<String> {
        let json = serde_json::to_string_pretty(ast)?;

        if let Some(path) = output_path {
            std::fs::write(path, &json)?;
        }

        Ok(json)
    }

    /// Print AST summary to console
    pub fn print_ast_summary(ast: &WorkflowAST) {
        println!("\n=== Workflow AST Summary: {} ===", ast.name);
        println!("Path: {}", ast.path);
        println!("Phases: {}", ast.phases.len());

        for (index, phase) in ast.phases.iter().enumerate() {
            println!("\n  Phase {}: {}", index + 1, phase.id);
            println!("    Actions: {}", phase.actions.len());
            println!("    Gates: {}", phase.gates.len());
            println!("    Verifies: {}", phase.verifies.len());
            println!("    Restrictions: {}", phase.restrictions.len());
            println!("    Constants: {}", phase.constants.len());
            println!("    Dictionaries: {}", phase.dictionaries.len());
            println!("    Schemas: {}", phase.schemas.len());
            println!("    Maps: {}", phase.maps.len());

            // Show critical nodes
            if !phase.gates.is_empty() {
                let gate_names: Vec<&str> = phase.gates.iter().map(|g| g.name.as_str()).collect();
                println!("    Gates: {}", gate_names.join(", "));
            }

            if !phase.actions.is_empty() {
                let action_commands: Vec<&str> = phase.actions.iter().take(3).map(|a| a.command.as_str()).collect();
                let suffix = if phase.actions.len() > 3 { "..." } else { "" };
                println!("    Key Actions: {}{}", action_commands.join(", "), suffix);
            }
        }

        println!("\n=== End Summary ===\n");
    }
}
