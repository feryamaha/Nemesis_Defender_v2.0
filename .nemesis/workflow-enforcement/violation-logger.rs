use crate::types::Violation;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref VIOLATIONS: Mutex<Vec<Violation>> = Mutex::new(Vec::new());
    static ref CURRENT_LLM_MODEL: Mutex<Option<String>> = Mutex::new(None);
}

const LOG_DIR: &str = "logs";
const LOG_FILE: &str = "logs/violations.log";

pub struct ViolationLogger;

impl ViolationLogger {
    fn ensure_log_directory() {
        if !Path::new(LOG_DIR).exists() {
            if let Err(e) = fs::create_dir_all(LOG_DIR) {
                eprintln!("Failed to create log directory: {}", e);
            }
        }
    }

    pub fn set_llm_model(model: &str) {
        let mut current = CURRENT_LLM_MODEL.lock().unwrap();
        *current = Some(model.to_string());
    }

    pub fn get_llm_model() -> Option<String> {
        let current = CURRENT_LLM_MODEL.lock().unwrap();
        current.clone()
    }

    pub fn log_violation(violation: &Violation) {
        let mut violation = violation.clone();
        if violation.llm_model.is_none() {
            violation.llm_model = Self::get_llm_model().or_else(|| Some(Self::detect_llm_model()));
        }

        {
            let mut violations = VIOLATIONS.lock().unwrap();
            violations.push(violation.clone());
        }

        Self::write_to_file(&violation);

        eprintln!("[VIOLATION] {:?}: {}", violation.violation_type, violation.message);
        if let Some(ref rule) = violation.rule {
            eprintln!("  Rule: {}", rule);
        }
        if let Some(ref command) = violation.command {
            eprintln!("  Command: {}", command);
        }
        if let Some(ref llm_model) = violation.llm_model {
            eprintln!("  LLM Model: {}", llm_model);
        }
        if let Some(ref layer) = violation.layer {
            eprintln!("  Layer: {}", layer);
        }
        eprintln!("  Timestamp: {}", violation.timestamp);
        eprintln!();
    }

    fn detect_llm_model() -> String {
        for env_var in ["CASCADE_LLM_MODEL", "LLM_MODEL", "WINDSURF_LLM_MODEL", "AGENT_MODEL", "AI_MODEL", "MODEL_NAME"] {
            if let Ok(model) = std::env::var(env_var) {
                return model;
            }
        }

        if std::env::var("WINDSURF_HOOK_EVENT").is_ok() {
            for env_var in ["WINDSURF_MODEL", "CASCADE_MODEL"] {
                if let Ok(model) = std::env::var(env_var) {
                    return model;
                }
            }
            return "Cascade (Devin) - Unknown Model".to_string();
        }

        if std::env::var("WINDSURF_CONTEXT").map(|v| v == "true").unwrap_or(false)
            || std::env::var("WINDSURF_IDE").map(|v| v == "true").unwrap_or(false)
        {
            return "Cascade (Devin) - Unknown Model".to_string();
        }

        if std::env::var("TRAJECTORY_ID").is_ok() || std::env::var("EXECUTION_ID").is_ok() {
            return "Cascade (Devin) - Unknown Model".to_string();
        }

        for env_var in ["CASCADE_MODEL", "WINDSURF_MODEL", "AI_AGENT_MODEL", "LLM_PROVIDER_MODEL"] {
            if let Ok(model) = std::env::var(env_var) {
                return model;
            }
        }

        let args = std::env::args().collect::<Vec<String>>().join(" ");
        let patterns: Vec<(&str, usize)> = vec![
            ("--model=", 8),
            ("--llm=", 6),
            ("model:", 6),
            ("llm:", 4),
        ];
        for (pattern, offset) in patterns {
            if let Some(pos) = args.find(pattern) {
                let start = pos + offset;
                let end = args[start..].find(' ').unwrap_or(args.len() - start);
                return args[start..start + end].to_string();
            }
        }

        let args_lower = args.to_lowercase();
        if args_lower.contains("swe") { return "SWE (Cascade)".to_string(); }
        if args_lower.contains("claude") { return "Claude (Cascade)".to_string(); }
        if args_lower.contains("gpt-4") || args_lower.contains("gpt4") { return "GPT-4 (Cascade)".to_string(); }
        if args_lower.contains("gpt-3.5") || args_lower.contains("gpt35") { return "GPT-3.5 (Cascade)".to_string(); }
        if args_lower.contains("grok") { return "Grok (Cascade)".to_string(); }
        if args_lower.contains("copilot") { return "GitHub Copilot".to_string(); }

        if args_lower.contains("cascade") || args_lower.contains("devin") {
            return "Cascade (Unknown Model)".to_string();
        }

        "unknown-llm-model".to_string()
    }

    fn write_to_file(violation: &Violation) {
        Self::ensure_log_directory();
        let log_entry = Self::format_log_entry(violation);

        let mut file = match OpenOptions::new().append(true).create(true).open(LOG_FILE) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Failed to write violation to log file: {}", e);
                return;
            }
        };

        if let Err(e) = writeln!(file, "{}", log_entry) {
            eprintln!("Failed to write violation to log file: {}", e);
        }
    }

    fn format_log_entry(violation: &Violation) -> String {
        let entry = serde_json::json!({
            "timestamp": violation.timestamp,
            "type": violation.violation_type,
            "message": violation.message,
            "rule": violation.rule.as_ref().unwrap_or(&"".to_string()),
            "command": violation.command.as_ref().unwrap_or(&"".to_string()),
            "llmModel": violation.llm_model.as_ref().unwrap_or(&"unknown".to_string()),
            "layer": violation.layer.as_ref().unwrap_or(&"unknown".to_string()),
        });
        entry.to_string()
    }

    pub fn get_violations() -> Vec<Violation> {
        let violations = VIOLATIONS.lock().unwrap();
        violations.clone()
    }

    pub fn get_violations_by_type(violation_type: &str) -> Vec<Violation> {
        let violations = VIOLATIONS.lock().unwrap();
        violations.iter().filter(|v| format!("{:?}", v.violation_type).to_lowercase() == violation_type.to_lowercase()).cloned().collect()
    }

    pub fn get_violations_by_workflow(workflow_name: &str) -> Vec<Violation> {
        let violations = VIOLATIONS.lock().unwrap();
        violations.iter().filter(|v| v.rule.as_ref().map(|r| r.contains(workflow_name)).unwrap_or(false)).cloned().collect()
    }

    pub fn clear_violations() {
        let mut violations = VIOLATIONS.lock().unwrap();
        violations.clear();
    }

    pub fn generate_report() -> String {
        let violations = VIOLATIONS.lock().unwrap();
        let total = violations.len();
        let by_type = Self::group_violations_by_type(&violations);
        let by_workflow = Self::group_violations_by_workflow(&violations);

        let mut report = "# Violation Report\n\n".to_string();
        report.push_str(&format!("**Total Violations:** {}\n\n", total));

        report.push_str("## Violations by Type\n\n");
        for (vtype, vlist) in by_type {
            report.push_str(&format!("### {}\n", vtype.to_uppercase()));
            report.push_str(&format!("- Count: {}\n", vlist.len()));
            let latest = vlist.last().map(|v| v.timestamp.as_str()).unwrap_or("N/A");
            report.push_str(&format!("- Latest: {}\n\n", latest));
        }

        report.push_str("## Violations by Workflow\n\n");
        for (workflow, vlist) in by_workflow {
            report.push_str(&format!("### {}\n", workflow));
            report.push_str(&format!("- Count: {}\n", vlist.len()));
            let latest = vlist.last().map(|v| v.timestamp.as_str()).unwrap_or("N/A");
            report.push_str(&format!("- Latest: {}\n\n", latest));
        }

        if total > 0 {
            report.push_str("## Recent Violations\n\n");
            let mut recent: Vec<&Violation> = violations.iter().collect();
            recent.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            for violation in recent.into_iter().take(10) {
                report.push_str(&format!("### {:?} - {}\n", violation.violation_type, violation.timestamp));
                report.push_str(&format!("- **Message:** {}\n", violation.message));
                if let Some(ref rule) = violation.rule {
                    report.push_str(&format!("- **Rule:** {}\n", rule));
                }
                if let Some(ref command) = violation.command {
                    report.push_str(&format!("- **Command:** {}\n", command));
                }
                if let Some(ref llm_model) = violation.llm_model {
                    report.push_str(&format!("- **LLM Model:** {}\n", llm_model));
                }
                report.push('\n');
            }
        }

        report
    }

    fn group_violations_by_type(violations: &[Violation]) -> HashMap<String, Vec<Violation>> {
        let mut grouped: HashMap<String, Vec<Violation>> = HashMap::new();
        for v in violations {
            let key = format!("{:?}", v.violation_type).to_lowercase();
            grouped.entry(key).or_default().push(v.clone());
        }
        grouped
    }

    fn group_violations_by_workflow(violations: &[Violation]) -> HashMap<String, Vec<Violation>> {
        let mut grouped: HashMap<String, Vec<Violation>> = HashMap::new();
        for v in violations {
            let workflow = v.rule.as_ref().and_then(|r| {
                r.split('@').nth(1).map(|s| s.split(']').next().unwrap_or(s).to_string())
            }).unwrap_or_else(|| "Unknown".to_string());
            grouped.entry(workflow).or_default().push(v.clone());
        }
        grouped
    }

    pub fn export_to_file(file_path: Option<&str>) {
        let report = Self::generate_report();
        let output_path = file_path.unwrap_or("violation-report.md");

        match fs::write(output_path, report) {
            Ok(_) => println!("Violation report exported to: {}", output_path),
            Err(e) => eprintln!("Failed to export violation report: {}", e),
        }
    }

    pub fn get_statistics() -> serde_json::Value {
        let violations = VIOLATIONS.lock().unwrap();
        let now = chrono::Utc::now();
        let one_hour_ago = now - chrono::Duration::hours(1);

        let recent_count = violations.iter().filter(|v| {
            chrono::DateTime::parse_from_rfc3339(&v.timestamp)
                .map(|t| t.with_timezone(&chrono::Utc) >= one_hour_ago)
                .unwrap_or(false)
        }).count();

        serde_json::json!({
            "total": violations.len(),
            "byType": Self::get_counts_by_type(&violations),
            "byWorkflow": Self::get_counts_by_workflow(&violations),
            "recentTrend": recent_count,
        })
    }

    fn get_counts_by_type(violations: &[Violation]) -> HashMap<String, u32> {
        let mut counts: HashMap<String, u32> = HashMap::new();
        for v in violations {
            let key = format!("{:?}", v.violation_type).to_lowercase();
            *counts.entry(key).or_insert(0) += 1;
        }
        counts
    }

    fn get_counts_by_workflow(violations: &[Violation]) -> HashMap<String, u32> {
        let mut counts: HashMap<String, u32> = HashMap::new();
        for v in violations {
            let workflow = v.rule.as_ref().and_then(|r| {
                r.split('@').nth(1).map(|s| s.split(']').next().unwrap_or(s).to_string())
            }).unwrap_or_else(|| "Unknown".to_string());
            *counts.entry(workflow).or_insert(0) += 1;
        }
        counts
    }
}
