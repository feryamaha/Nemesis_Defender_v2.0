use crate::types::WorkflowDefinition;
use std::path::{Path, PathBuf};
use tokio::fs;

pub struct WorkflowCatalog;

const WORKFLOWS_DIR: &str = ".devin/workflows";

impl WorkflowCatalog {
    pub async fn list_workflows(base_path: Option<&str>) -> Vec<String> {
        let base_path = base_path.unwrap_or(".");
        let normalized_base = Self::normalize_base_path(base_path);
        let workflows_dir = Path::new(&normalized_base).join(WORKFLOWS_DIR);

        match fs::read_dir(&workflows_dir).await {
            Ok(mut entries) => {
                let mut workflow_files = Vec::new();
                
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if let Some(name) = path.file_name() {
                        let name_str = name.to_string_lossy();
                        if name_str.ends_with(".md") || name_str.ends_with(".markdown") {
                            workflow_files.push(path.to_string_lossy().to_string());
                        }
                    }
                }
                
                workflow_files
            }
            Err(e) => {
                eprintln!("Failed to read workflows directory: {:?} - {}", workflows_dir, e);
                Vec::new()
            }
        }
    }

    pub async fn list_all_workflow_files(base_path: Option<&str>) -> Vec<WorkflowDefinition> {
        let workflow_files = Self::list_workflows(base_path).await;
        let mut workflows = Vec::new();

        for file_path in workflow_files {
            match fs::metadata(&file_path).await {
                Ok(metadata) if metadata.is_file() => {
                    workflows.push(WorkflowDefinition {
                        name: Self::extract_workflow_name(&file_path),
                        path: file_path,
                        content: String::new(),
                        code_blocks: Vec::new(),
                        metadata: std::collections::HashMap::new(),
                    });
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Failed to stat file {}: {}", file_path, e);
                }
            }
        }

        workflows
    }

    pub async fn get_workflow_by_name(name: &str, base_path: Option<&str>) -> Option<String> {
        let workflows = Self::list_workflows(base_path).await;

        for workflow_path in workflows {
            let workflow_name = Self::extract_workflow_name(&workflow_path);
            if workflow_name == name || workflow_name == format!("{}.md", name) {
                return Some(workflow_path);
            }
        }

        None
    }

    fn extract_workflow_name(file_path: &str) -> String {
        Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| {
                n.trim_end_matches(".md")
                    .trim_end_matches(".markdown")
                    .to_string()
            })
            .unwrap_or_else(|| file_path.to_string())
    }

    fn normalize_base_path(base_path: &str) -> String {
        let re = regex::Regex::new(r"[/\\]\.devin[/\\]workflows[/\\]?$").unwrap();
        re.replace(base_path, "").to_string()
    }

    pub async fn validate_workflows_directory(base_path: Option<&str>) -> bool {
        let base_path = base_path.unwrap_or(".");
        let normalized_base = Self::normalize_base_path(base_path);
        let workflows_dir = Path::new(&normalized_base).join(WORKFLOWS_DIR);

        match fs::metadata(&workflows_dir).await {
            Ok(metadata) => metadata.is_dir(),
            Err(_) => false,
        }
    }
}
