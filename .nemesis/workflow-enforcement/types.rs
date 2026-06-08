use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOptions {
    #[serde(rename = "maxCallDepth", skip_serializing_if = "Option::is_none")]
    pub max_call_depth: Option<u32>,
    #[serde(rename = "maxCommandCount", skip_serializing_if = "Option::is_none")]
    pub max_command_count: Option<u32>,
    #[serde(rename = "maxLoopIterations", skip_serializing_if = "Option::is_none")]
    pub max_loop_iterations: Option<u32>,
    #[serde(rename = "networkAccess", skip_serializing_if = "Option::is_none")]
    pub network_access: Option<bool>,
    #[serde(rename = "allowedUrls", skip_serializing_if = "Option::is_none")]
    pub allowed_urls: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    pub name: String,
    pub path: String,
    pub content: String,
    #[serde(rename = "codeBlocks")]
    pub code_blocks: Vec<CodeBlock>,
    pub metadata: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeBlock {
    pub language: String,
    pub content: String,
    #[serde(rename = "lineNumber")]
    pub line_number: u32,
    #[serde(rename = "isExecutable")]
    pub is_executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    #[serde(rename = "isValid")]
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationWarning {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    #[serde(rename = "exitCode")]
    pub exit_code: i32,
    #[serde(rename = "executionTime")]
    pub execution_time: f64,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRunnerResult {
    pub workflow: String,
    pub success: bool,
    pub results: Vec<CommandResult>,
    pub violations: Vec<Violation>,
    #[serde(rename = "executionTime")]
    pub execution_time: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    #[serde(rename = "type")]
    pub violation_type: ViolationType,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub timestamp: String,
    #[serde(rename = "llmModel", skip_serializing_if = "Option::is_none")]
    pub llm_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationType {
    PermissionDenied,
    RuleViolation,
    SyntaxError,
    SecurityViolation,
    GateViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub command: String,
    pub reason: String,
    pub workflow: String,
    #[serde(rename = "requiresConfirmation")]
    pub requires_confirmation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementConfig {
    #[serde(rename = "blockUnauthorizedCommands")]
    pub block_unauthorized_commands: bool,
    #[serde(rename = "logViolations")]
    pub log_violations: bool,
    #[serde(rename = "requirePermissionForFileEdits")]
    pub require_permission_for_file_edits: bool,
    #[serde(rename = "allowedLanguages")]
    pub allowed_languages: Vec<String>,
    #[serde(rename = "mandatoryRules")]
    pub mandatory_rules: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreToolValidationResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevinHookInput {
    #[serde(rename = "agent_action_name")]
    pub agent_action_name: String,
    #[serde(rename = "trajectory_id")]
    pub trajectory_id: String,
    #[serde(rename = "execution_id")]
    pub execution_id: String,
    pub timestamp: String,
    #[serde(rename = "tool_info")]
    pub tool_info: DevinToolInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevinToolInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edits: Option<Vec<DevinEdit>>,
    #[serde(rename = "command_line", skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(rename = "user_prompt", skip_serializing_if = "Option::is_none")]
    pub user_prompt: Option<String>,
    #[serde(rename = "mcp_server_name", skip_serializing_if = "Option::is_none")]
    pub mcp_server_name: Option<String>,
    #[serde(rename = "mcp_tool_name", skip_serializing_if = "Option::is_none")]
    pub mcp_tool_name: Option<String>,
    #[serde(rename = "mcp_tool_arguments", skip_serializing_if = "Option::is_none")]
    pub mcp_tool_arguments: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "mcp_result", skip_serializing_if = "Option::is_none")]
    pub mcp_result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(rename = "worktree_path", skip_serializing_if = "Option::is_none")]
    pub worktree_path: Option<String>,
    #[serde(rename = "root_workspace_path", skip_serializing_if = "Option::is_none")]
    pub root_workspace_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevinEdit {
    #[serde(rename = "old_string")]
    pub old_string: String,
    #[serde(rename = "new_string")]
    pub new_string: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreToolValidationInput {
    #[serde(rename = "toolName")]
    pub tool_name: String,
    #[serde(rename = "toolInput")]
    pub tool_input: serde_json::Map<String, serde_json::Value>,
}
