//! Nemesis CLI - PreToolUse Hook
// diretorio: .nemesis/hooks/pretool-hook.rs 
//!
//! FIX: validateFileOperation bloqueia escrita direta em
//! permission-gate.state.json e workflow-state.json.
//!
//! FIX SEQUENCE ENFORCEMENT (write_to_file + bash):
//! Lê todos os .devin/workflows/work-*.md e extrai gate artifacts
//! em ordem de aparição. Constrói cadeia sequencial completa.
//! Mantido para compatibilidade com work-03, work-04, work-05.
//!
//! FIX SRC/ ALWAYS LOCKED:
//! Escrita em src/, app/, Feature-Documentation/ é SEMPRE bloqueada
//! a menos que exista um artifact de aprovação válido em .nemesis/runtime/.
//!
//! FIX LLM MODEL DETECTION:
//! Lê .nemesis/runtime/current-model.json como prioridade 1.
//!
//! FIX MASS EXECUTION GUARD (checkBashSequence):
//! Bloqueia 2+ gate artifacts em um único comando encadeado.
//! Bloqueia bash redirects para artefato-*.txt — obriga uso da write tool.
//!
//! FIX ARTEFATO PROGRESSIVO (checkArtifactWrite):
//! Valida que cada escrita no artefato progressivo:
//! - Mantém todas as fases anteriores com AUDIT e convergencia: SIM
//! - Não permite avançar se alguma fase anterior declarou convergencia: NÃO
//! Este é o mecanismo central do novo modelo de execução.

#![allow(dead_code)]

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;

use ast_linters::validator::validate_semantic;
use nemesis_defender;

// =============================================================================
// TIPOS
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DenylistFolderFiles {
    absolute_block: AbsoluteBlock,
    write_block: WriteBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AbsoluteBlock {
    paths: Vec<String>,
    allowed_exceptions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WriteBlock {
    files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PreToolInput {
    agent_action_name: AgentActionName,
    tool_info: ToolInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AgentActionName {
    PreReadCode,
    PostReadCode,
    PreWriteCode,
    PostWriteCode,
    PreRunCommand,
    PostRunCommand,
    PreMcpToolUse,
    PostMcpToolUse,
    PreUserPrompt,
    PostCascadeResponse,
    PostSetupWorktree,
}

impl AgentActionName {
    fn as_str(&self) -> &'static str {
        match self {
            AgentActionName::PreReadCode => "pre_read_code",
            AgentActionName::PostReadCode => "post_read_code",
            AgentActionName::PreWriteCode => "pre_write_code",
            AgentActionName::PostWriteCode => "post_write_code",
            AgentActionName::PreRunCommand => "pre_run_command",
            AgentActionName::PostRunCommand => "post_run_command",
            AgentActionName::PreMcpToolUse => "pre_mcp_tool_use",
            AgentActionName::PostMcpToolUse => "post_mcp_tool_use",
            AgentActionName::PreUserPrompt => "pre_user_prompt",
            AgentActionName::PostCascadeResponse => "post_cascade_response",
            AgentActionName::PostSetupWorktree => "post_setup_worktree",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ToolInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    edits: Option<Vec<Edit>>,
    #[serde(rename = "CodeContent", skip_serializing_if = "Option::is_none")]
    code_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    search_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    includes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_tool_arguments: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Edit {
    old_string: String,
    new_string: String,
}

#[derive(Debug, Clone)]
struct ValidationResult {
    valid: bool,
    reason: Option<String>,
    rule: Option<String>,
    suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkflowState {
    active_workflow: String,
    started_at: String,
    total_steps: i32,
    completed_steps: Vec<i32>,
    #[serde(default)]
    current_step: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    unlocked_fragment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_plan: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_phases: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan_loaded_at: Option<String>,
    required_before_write: HashMap<String, Vec<i32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PermissionGateState {
    state: String,
    #[serde(rename = "workflowName")]
    workflow_name: String,
    #[serde(rename = "planSummary")]
    plan_summary: String,
    #[serde(rename = "requestedAt")]
    requested_at: i64,
    #[serde(rename = "resolvedAt", skip_serializing_if = "Option::is_none")]
    resolved_at: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
struct DenyListHit {
    message: String,
    rule: String,
    suggestion: String,
}

#[derive(Debug, Clone)]
struct SafetyCheck {
    risk_level: String,
    reasons: Vec<String>,
}

// =============================================================================
// CONSTANTES
// =============================================================================

const ABSOLUTE_PROTECTED_RUNTIME_FILES: &[&str] = &[
    "permission-gate.state.json",
    "workflow-state.json",
];

const WORKFLOW_PROTECTED_PATHS: &[&str] = &[
    "src/",
    "/src/",
    "app/",
    "/app/",
    "Feature-Documentation/",
    "/Feature-Documentation/",
];

// =============================================================================
// FUNÇÕES UTILITÁRIAS DE PATH
// =============================================================================

fn get_cwd() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn get_nemesis_dir() -> PathBuf {
    get_cwd().join(".nemesis")
}

fn get_runtime_dir() -> PathBuf {
    get_nemesis_dir().join("runtime")
}

fn get_workflow_enforcement_dir() -> PathBuf {
    get_nemesis_dir().join("denylist")
}

fn get_workflows_dir() -> PathBuf {
    get_cwd().join(".devin").join("workflows")
}

fn get_config_path() -> PathBuf {
    get_workflow_enforcement_dir().join("workflow-gate-artifacts.json")
}

fn get_scope_path() -> PathBuf {
    get_nemesis_dir().join("scope.json")
}

fn get_permission_gate_state_path() -> PathBuf {
    get_runtime_dir().join("permission-gate.state.json")
}

fn get_deny_list_path() -> PathBuf {
    get_workflow_enforcement_dir().join("deny-list.json")
}

// =============================================================================
// PERMISSION GATE
// =============================================================================

fn load_permission_gate_state() -> Option<PermissionGateState> {
    let state_path = get_permission_gate_state_path();
    if !state_path.exists() {
        return None;
    }
    match fs::read_to_string(&state_path) {
        Ok(content) => match serde_json::from_str::<PermissionGateState>(&content) {
            Ok(state) => {
                if state.state == "idle" || state.workflow_name == "none" {
                    return None;
                }
                Some(state)
            }
            Err(_) => None,
        },
        Err(_) => None,
    }
}

fn can_modify_file(_command_context: &str) -> (bool, String) {
    let state = load_permission_gate_state();

    match state {
        None => (
            false,
            "No active workflow permission context. File modifications require workflow-main Step 7 authorization.".to_string(),
        ),
        Some(ref s) if s.state == "awaiting" => (
            false,
            format!(
                "Permission gate is AWAITING explicit user authorization. Workflow: {}. Do not proceed until user sends explicit YES.",
                s.workflow_name
            ),
        ),
        Some(ref s) if s.state == "denied" => (
            false,
            format!("Permission was DENIED for workflow: {}.", s.workflow_name),
        ),
        Some(ref s) if s.state == "granted" => (
            true,
            format!("Permission GRANTED for workflow: {}.", s.workflow_name),
        ),
        _ => (false, "Unknown permission state. Defaulting to blocked.".to_string()),
    }
}

// =============================================================================
// SCOPE VALIDATOR
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScopeConfig {
    task: Option<String>,
    #[serde(rename = "rag_reference")]
    rag_reference: Option<String>,
    #[serde(rename = "allowed_files")]
    allowed_files: Option<Vec<String>>,
    #[serde(rename = "allowed_patterns")]
    allowed_patterns: Option<Vec<String>>,
    #[serde(rename = "blocked_files")]
    blocked_files: Option<Vec<String>>,
    #[serde(rename = "created_at")]
    created_at: Option<String>,
}

fn has_scope_active() -> bool {
    get_scope_path().exists()
}

fn read_scope() -> Option<ScopeConfig> {
    let scope_path = get_scope_path();
    if !scope_path.exists() {
        return None;
    }
    match fs::read_to_string(&scope_path) {
        Ok(content) => serde_json::from_str::<ScopeConfig>(&content).ok(),
        Err(_) => None,
    }
}

fn match_glob(file_path: &str, pattern: &str) -> bool {
    let normalized_pattern = pattern.replace('\\', "/");
    let normalized_path = file_path.replace('\\', "/");

    let regex_str = normalized_pattern
        .replace('.', "\\.")
        .replace('+', "\\+")
        .replace('^', "\\^")
        .replace('$', "\\$")
        .replace('{', "\\{")
        .replace('}', "\\}")
        .replace('(', "\\(")
        .replace(')', "\\)")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace("**", "___DOUBLESTAR___")
        .replace('*', "[^/]*")
        .replace('?', "[^/]")
        .replace("___DOUBLESTAR___", ".*");

    let regex_str = format!("^{}$", regex_str);

    match Regex::new(&regex_str) {
        Ok(re) => re.is_match(&normalized_path),
        Err(_) => false,
    }
}

/// Resolve `.`/`..` LEXICAMENTE (sem `canonicalize`, sem exigir que o arquivo exista), a partir
/// de `base`. Paths absolutos ficam como estão. É o que faltava: `canonicalize()` falha para
/// arquivos NOVOS e deixava `../../etc/passwd` cru escapar da contenção.
fn resolve_lexical(file_path: &str, base: &std::path::Path) -> PathBuf {
    let raw = PathBuf::from(file_path);
    let start = if raw.is_absolute() { raw } else { base.join(&raw) };
    let mut root = PathBuf::new();
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    for comp in start.components() {
        match comp {
            std::path::Component::Prefix(p) => root.push(p.as_os_str()),
            std::path::Component::RootDir => root.push(std::path::Component::RootDir.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(c) => out.push(c.to_os_string()),
        }
    }
    let mut result = root;
    for c in out {
        result.push(c);
    }
    result
}

/// CONTENÇÃO POSITIVA ao scaffold: a escrita resolvida deve ficar DENTRO da raiz do projeto (cwd).
/// Bloqueia path traversal (`../../`) e symlink que escape. Vale SEMPRE, mesmo sem scope.json.
fn is_write_within_project(file_path: &str) -> bool {
    let cwd = get_cwd();
    let root = cwd.canonicalize().unwrap_or(cwd);
    let resolved = resolve_lexical(file_path, &root);
    if !resolved.starts_with(&root) {
        return false;
    }
    // Anti-symlink: se o diretório-pai existe, seu caminho REAL também deve estar na raiz.
    if let Some(parent) = resolved.parent() {
        if let Ok(real_parent) = parent.canonicalize() {
            if !real_parent.starts_with(&root) {
                return false;
            }
        }
    }
    true
}

fn validate_file_scope(file_path: &str) -> ValidationResult {
    // Contenção ao scaffold (independente de scope.json): escrita fora da raiz do projeto é
    // bloqueada. Fecha o vetor de path traversal (`../../etc/passwd`) achado no pentest do Mac.
    if !is_write_within_project(file_path) {
        return ValidationResult {
            valid: false,
            reason: Some(format!("NEMESIS SEC - ESCRITA FORA DO PROJETO · {}", file_path)),
            rule: Some(".devin/rules/README.md".to_string()),
            suggestion: Some(
                "Escrita permitida apenas dentro da raiz do projeto (sem path traversal).".to_string(),
            ),
        };
    }

    let scope = read_scope();

    // Sem scope = modo aberto (permite tudo)
    if scope.is_none() {
        return ValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    let scope = scope.unwrap();
    let absolute_path = PathBuf::from(file_path).canonicalize().unwrap_or_else(|_| PathBuf::from(file_path));
    let cwd = get_cwd();
    let relative_path = absolute_path.strip_prefix(&cwd).map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| file_path.to_string());
    let normalized_relative = relative_path.replace('\\', "/");

    // Verificar blocked_files primeiro (prioridade maxima)
    if let Some(blocked_files) = scope.blocked_files {
        for blocked in blocked_files {
            let normalized_blocked = blocked.replace('\\', "/");
            if normalized_relative == normalized_blocked || normalized_relative.ends_with(&normalized_blocked) {
                return ValidationResult {
                    valid: false,
                    reason: Some(format!("NEMESIS SEC - ESCRITA FORA DO ESCOPO PERMITIDO · {}", normalized_relative)),
                    rule: Some(".devin/rules/README.md".to_string()),
                    suggestion: Some(".devin/rules/README.md".to_string()),
                };
            }
        }
    }

    // Se nao ha allowed_files nem allowed_patterns, modo aberto
    let has_allowed_files = scope.allowed_files.as_ref().map(|v| !v.is_empty()).unwrap_or(false);
    let has_allowed_patterns = scope.allowed_patterns.as_ref().map(|v| !v.is_empty()).unwrap_or(false);

    if !has_allowed_files && !has_allowed_patterns {
        return ValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    // Verificar allowed_files (match exato ou por sufixo)
    if let Some(ref allowed_files) = scope.allowed_files {
        for allowed in allowed_files {
            let normalized_allowed = allowed.replace('\\', "/");
            if normalized_relative == normalized_allowed || normalized_relative.ends_with(&normalized_allowed) {
                return ValidationResult {
                    valid: true,
                    reason: None,
                    rule: None,
                    suggestion: None,
                };
            }
        }
    }

    // Verificar allowed_patterns (glob simples)
    if let Some(ref allowed_patterns) = scope.allowed_patterns {
        for pattern in allowed_patterns {
            if match_glob(&normalized_relative, pattern) {
                return ValidationResult {
                    valid: true,
                    reason: None,
                    rule: None,
                    suggestion: None,
                };
            }
        }
    }

    // Arquivo nao esta no escopo
    let allowed_list = scope.allowed_files.iter().flatten().cloned().collect::<Vec<_>>().join(", ");
    let allowed_list = if allowed_list.is_empty() { "nenhum especificado".to_string() } else { allowed_list };
    ValidationResult {
        valid: false,
        reason: Some(format!("NEMESIS SEC - ESCRITA FORA DO ESCOPO PERMITIDO · {}", normalized_relative)),
        rule: Some(".devin/rules/README.md".to_string()),
        suggestion: Some(format!(".devin/rules/README.md: {}", allowed_list)),
    }
}

// =============================================================================
// DENY LIST LOADER
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DenyPattern {
    id: String,
    pattern: String,
    #[serde(rename = "type")]
    pattern_type: String,
    severity: String,
    message: String,
    suggestion: String,
    rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "contextType")]
    context_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DenyListLayer {
    description: String,
    patterns: Vec<DenyPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DenyList {
    version: String,
    #[serde(rename = "lastUpdated")]
    last_updated: String,
    #[serde(rename = "projectStack")]
    project_stack: Vec<String>,
    layers: HashMap<String, DenyListLayer>,
}

fn load_deny_list() -> Option<DenyList> {
    let deny_list_path = get_deny_list_path();
    if !deny_list_path.exists() {
        return None;
    }
    match fs::read_to_string(&deny_list_path) {
        Ok(content) => serde_json::from_str::<DenyList>(&content).ok(),
        Err(_) => None,
    }
}

/// Carrega TODOS os arquivos .json da pasta config como deny-lists.
fn load_all_deny_lists() -> Vec<DenyList> {
    let mut all = Vec::new();
    let denylist_dir = get_workflow_enforcement_dir();
    if let Ok(entries) = fs::read_dir(&denylist_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(deny_list) = serde_json::from_str::<DenyList>(&content) {
                        all.push(deny_list);
                    }
                }
            }
        }
    }
    all
}

fn get_command_patterns() -> Vec<DenyPattern> {
    let mut all_patterns: Vec<DenyPattern> = Vec::new();

    // Consultar TODAS as 3 deny-lists de comandos
    let denylist_dir = get_workflow_enforcement_dir();
    let deny_list_paths = [
        denylist_dir.join("deny-list.json"),
        denylist_dir.join("deny-list-base.json"),
        denylist_dir.join("deny-list-generic.json"),
    ];

    for path in &deny_list_paths {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(deny_list) = serde_json::from_str::<DenyList>(&content) {
                if let Some(commands) = deny_list.layers.get("commands") {
                    for p in &commands.patterns {
                        if p.pattern_type == "regex" {
                            all_patterns.push(p.clone());
                        }
                    }
                }
            }
        }
    }

    all_patterns
}

fn check_command(command: &str) -> Option<DenyPattern> {
    let patterns = get_command_patterns();
    for pattern in patterns {
        if let Ok(re) = Regex::new(&pattern.pattern) {
            if re.is_match(command) {
                return Some(pattern);
            }
        }
    }
    None
}

/// Carrega a lista canônica de comandos bloqueados do eBPF.
/// Extrai do commands.toml usando regex simples (sem dep toml).
fn load_ebpf_blocked_commands() -> Vec<String> {
    let path = get_nemesis_dir()
        .join("ebpf-kernel")
        .join("denylist-ebpf")
        .join("commands.toml");
    if !path.exists() {
        return Vec::new();
    }
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let array_re = match Regex::new(r#"blocked_commands\s*=\s*\[([^\]]*)\]"#) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    if let Some(caps) = array_re.captures(&content) {
        let list_str = &caps[1];
        let item_re = match Regex::new(r#""([^"]*)""#) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        item_re.captures_iter(list_str)
            .map(|c| c[1].to_string())
            .collect()
    } else {
        Vec::new()
    }
}

// =============================================================================
// CODE VALIDATOR
// =============================================================================

fn validate_code_content(file_path: &str, new_string: &str) -> ValidationResult {
    if new_string.is_empty() || file_path.is_empty() {
        return ValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    let path_buf = PathBuf::from(file_path);
    let ext = path_buf.extension().and_then(|e| e.to_str()).unwrap_or("").to_string();

    if ext != "ts" && ext != "tsx" && ext != "js" && ext != "jsx" && ext != "py"
       && ext != "md" && ext != "json" && ext != "sh" && ext != "bash"
       && ext != "yml" && ext != "yaml" && ext != "toml" {
        return ValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    let _file_name = path_buf.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
    let _normalized_path = file_path.replace('\\', "/");

    // === DENY-LIST DINÂMICA ===
    if let Some(deny_hit) = check_content_deny_list(file_path, new_string) {
        return ValidationResult {
            valid: false,
            reason: Some(deny_hit.message),
            rule: Some(deny_hit.rule),
            suggestion: Some(deny_hit.suggestion),
        };
    }

    // REGRA 6: AST semantic validation (NÃO-BLOQUEANTE por padrão — só avisa)
    // Config: .nemesis/ast-linters-config.json define se bloqueia ou apenas avisa
    let ast_violations = validate_semantic(new_string, file_path);

    // Carregar config de ast-linters
    let ast_config_path = get_nemesis_dir().join("ast-linters-config.json");
    let should_block_ast = if ast_config_path.exists() {
        fs::read_to_string(&ast_config_path)
            .ok()
            .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
            .and_then(|v| v.get("blocking_mode").and_then(|b| b.as_bool()))
            .unwrap_or(false)
    } else {
        false // Padrão: não bloqueia
    };

    // Filtrar violações por severity se em modo não-bloqueante
    let critical_violations: Vec<_> = if !should_block_ast {
        ast_violations.iter()
            .filter(|v| v.severity.as_str() == "critical")
            .collect()
    } else {
        ast_violations.iter().collect()
    };

    if !critical_violations.is_empty() && should_block_ast {
        let _first = critical_violations[0];
        return ValidationResult {
            valid: false,
            reason: Some("NEMESIS QUALITY - PADRAO DE CODIGO NAO PERMITIDO ANALISAR REGRAS!".to_string()),
            rule: Some(".devin/rules/README.md".to_string()),
            suggestion: Some("Violação semântica crítica detectada por análise de AST.".to_string()),
        };
    }

    // Avisos não-críticos (não bloqueiam, apenas registram no log)
    if !ast_violations.is_empty() && !should_block_ast {
        for violation in &ast_violations {
            if violation.severity.as_str() == "warn" {
                log_violation("ast-warning", &violation.message, Some(&format!(".devin/rules/README.md (line {})", violation.line)), None);
            }
        }
    }

    ValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

fn get_all_code_patterns() -> Vec<DenyPattern> {
    let deny_lists = load_all_deny_lists();
    let code_layers = vec!["typescript", "react", "css", "nextjs", "api", "security", "bypass"];

    let mut patterns = Vec::new();
    for deny_list in deny_lists {
        for layer_name in &code_layers {
            if let Some(layer) = deny_list.layers.get(*layer_name) {
                for pattern in &layer.patterns {
                    if pattern.pattern_type == "regex" {
                        patterns.push(pattern.clone());
                    }
                }
            }
        }
    }
    patterns
}

fn get_patterns_for_file(file_path: &str) -> Vec<DenyPattern> {
    let all_patterns = get_all_code_patterns();
    all_patterns
        .into_iter()
        .filter(|p| {
            if let Some(ref context) = p.context {
                if let Some(ref context_type) = p.context_type {
                    match context_type.as_str() {
                        "path_contains" => file_path.contains(context),
                        "path_ends_with" => file_path.ends_with(context),
                        _ => true,
                    }
                } else {
                    true
                }
            } else {
                true
            }
        })
        .collect()
}

fn check_content_deny_list(file_path: &str, content: &str) -> Option<DenyPattern> {
    let patterns = get_patterns_for_file(file_path);
    for pattern in patterns {
        if let Ok(re) = Regex::new(&pattern.pattern) {
            if re.is_match(content) {
                return Some(pattern);
            }
        }
    }
    None
}

// =============================================================================
// VIOLATION LOGGER
// =============================================================================

static CURRENT_LLM_MODEL: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn set_llm_model(model: &str) {
    let _ = CURRENT_LLM_MODEL.set(model.to_string());
}

fn get_current_llm_model() -> String {
    CURRENT_LLM_MODEL
        .get()
        .cloned()
        .unwrap_or_else(|| detect_devin_llm_model())
}

fn log_violation(violation_type: &str, message: &str, rule: Option<&str>, command: Option<&str>) {
    // Ledger unificado ÚNICO: `.nemesis/logs/nemesis-violations.log` (via nemesis_defender).
    // O arquivo legado `.nemesis/logs/violations.log` foi REMOVIDO da arquitetura.
    // Bloqueios já são registrados no ledger pelo nemesis-pretool-check-unix (que lê o
    // exit-code/stderr deste hook); aqui só registramos eventos NÃO-bloqueantes (ex.:
    // ast-warning) que não passam por aquele caminho — evitando entradas duplicadas.
    let llm_model = get_current_llm_model();
    let mut composed = format!("NEMESIS · {} · {}", violation_type, message);
    if let Some(c) = command.filter(|c| !c.is_empty()) {
        composed.push_str(&format!(" · {}", c));
    }
    if let Some(r) = rule.filter(|r| !r.is_empty()) {
        composed.push_str(&format!(" [{}]", r));
    }
    if !llm_model.is_empty() && llm_model != "unknown" {
        composed.push_str(&format!(" ({})", llm_model));
    }
    nemesis_defender::violations_log::append("pretool", &composed);
}

// =============================================================================
// DETECÇÃO DE MODELO LLM
// =============================================================================

fn detect_devin_llm_model() -> String {
    // Tenta ler current-model.json
    let current_model_path = get_runtime_dir().join("current-model.json");
    if current_model_path.exists() {
        if let Ok(content) = fs::read_to_string(&current_model_path) {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(model) = data.get("model").and_then(|v| v.as_str()) {
                    if !model.trim().is_empty() {
                        return model.trim().to_string();
                    }
                }
            }
        }
    }

    // Fallback para variáveis de ambiente
    env::var("CASCADE_LLM_MODEL")
        .or_else(|_| env::var("WINDSURF_LLM_MODEL"))
        .or_else(|_| env::var("LLM_MODEL"))
        .unwrap_or_else(|_| "unknown — execute work-00-training to register model identity".to_string())
}

fn build_workflow_dependency_map() -> HashMap<String, String> {
    let mut dep_map = HashMap::new();
    let static_config_path = get_workflow_enforcement_dir()
        .join("config")
        .join("workflow-gate-artifacts.json");

    if static_config_path.exists() {
        if let Ok(content) = fs::read_to_string(&static_config_path) {
            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(workflows) = config.get("workflows").and_then(|v| v.as_object()) {
                    for (_, workflow_def) in workflows {
                        if let Some(gate_sequence) = workflow_def.get("gateSequence").and_then(|v| v.as_object()) {
                            for (artifact, required) in gate_sequence {
                                if !required.is_null() {
                                    if let Some(req_str) = required.as_str() {
                                        dep_map.insert(artifact.clone(), req_str.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if dep_map.is_empty() {
        return build_workflow_dependency_map_legacy();
    }
    dep_map
}

// =============================================================================
// LEGACY: dynamic parser — kept for work-03, work-04, work-05
// =============================================================================
fn build_workflow_dependency_map_legacy() -> HashMap<String, String> {
    let mut dep_map = HashMap::new();
    let workflows_dir = get_workflows_dir();

    if !workflows_dir.exists() {
        return dep_map;
    }

    if let Ok(entries) = fs::read_dir(&workflows_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            if entry.path().extension().map(|e| e == "md").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    let lines: Vec<_> = content.lines().collect();
                    let mut ordered: Vec<String> = Vec::new();
                    let mut seen = std::collections::HashSet::new();

                    let re = Regex::new(r"[>]{1,2}\s*\.nemesis/runtime/(work-[\w.\-]+\.txt)").unwrap();
                    for line in &lines {
                        if let Some(cap) = re.captures(line) {
                            let artifact = cap[1].to_string();
                            if !artifact.starts_with("artefato-") && !seen.contains(&artifact) {
                                seen.insert(artifact.clone());
                                ordered.push(artifact);
                            }
                        }
                    }

                    for i in 1..ordered.len() {
                        dep_map.insert(ordered[i].clone(), ordered[i - 1].clone());
                    }
                }
            }
        }
    }

    dep_map
}

fn build_approval_artifacts() -> Vec<String> {
    let static_config_path = get_workflow_enforcement_dir()
        .join("config")
        .join("workflow-gate-artifacts.json");

    if static_config_path.exists() {
        if let Ok(content) = fs::read_to_string(&static_config_path) {
            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(artifacts) = config.get("approvalArtifacts").and_then(|v| v.as_array()) {
                    return artifacts.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                }
            }
        }
    }

    // Fallback legacy
    let mut artifacts = Vec::new();
    let workflows_dir = env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".devin")
        .join("workflows");

    if workflows_dir.exists() {
        if let Ok(entries) = fs::read_dir(&workflows_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                if entry.path().extension().map(|e| e == "md").unwrap_or(false) {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        let re = Regex::new(r"LOCKED until (work-[\w.\-]+\.txt) exists").unwrap();
                        for cap in re.captures_iter(&content) {
                            let artifact = cap[1].to_string();
                            if !artifacts.contains(&artifact) {
                                artifacts.push(artifact);
                            }
                        }
                    }
                }
            }
        }
    }

    artifacts
}

fn check_src_lock(file_path: &str) -> Option<ValidationResult> {
    let is_protected = WORKFLOW_PROTECTED_PATHS.iter()
        .any(|p| file_path.starts_with(p) || file_path.contains(p));

    if !is_protected {
        return None;
    }

    // SURGERY 3: Existence guard — workflow-state.json absent on protected path = BLOCK
    let workflow_state_path = get_runtime_dir().join("workflow-state.json");
    if !workflow_state_path.exists() {
        return Some(ValidationResult {
            valid: false,
            reason: Some(format!(
                "NEMESIS SEC - ESCRITA FORA DO ESCOPO PERMITIDO · {}",
                file_path
            )),
            rule: Some(".devin/workflows — tracker start obrigatório antes de escrever em src/, app/, Feature-Documentation/".to_string()),
            suggestion: Some(
                "Execute: work-00-training para iniciar o workflow de treinamento e liberar a escrita no diretório.".to_string()
            ),
        });
    }

    let runtime_dir = get_runtime_dir();

    if !runtime_dir.exists() {
        return Some(ValidationResult {
            valid: false,
            reason: Some(format!(
                "NEMESIS SEC - ESCRITA FORA DO ESCOPO PERMITIDO · {}",
                file_path
            )),
            rule: Some(".devin/workflows — src/ requer workflow aprovado".to_string()),
            suggestion: Some("Execute o workflow work-02-main e complete todas as fases até a aprovação do MegaPlan.".to_string()),
        });
    }

    let runtime_files: Vec<String> = if let Ok(entries) = fs::read_dir(&runtime_dir) {
        entries.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string()).collect()
    } else {
        Vec::new()
    };

    let approval_artifacts = build_approval_artifacts();
    for artifact in &approval_artifacts {
        if runtime_files.contains(artifact) {
            return None;
        }
    }

    // PATH-SPECIFIC APPROVAL — each protected path requires its OWN artifact
    let path_approval_map = build_path_approval_map();

    let mut required_artifacts: Vec<String> = Vec::new();
    for (pattern, arts) in &path_approval_map {
        if file_path.starts_with(pattern) || file_path.contains(pattern) {
            required_artifacts = arts.clone();
            break;
        }
    }

    // FIX: Permitir qualquer artifact de complete válido para o path
    if !required_artifacts.is_empty() {
        let any_complete_artifact: Vec<_> = runtime_files.iter()
            .filter(|f| f.contains("complete.txt") || f.contains("approved.txt"))
            .cloned()
            .collect();

        if !any_complete_artifact.is_empty() {
            return None;
        }

        let has_specific_approval = required_artifacts.iter()
            .any(|a| runtime_files.contains(&PathBuf::from(a).file_name().and_then(|n| n.to_str()).unwrap_or("").to_string()));

        if has_specific_approval {
            return None;
        }

        let _approval_needed = required_artifacts.join(" ou ");
        return Some(ValidationResult {
            valid: false,
            reason: Some(format!(
                "NEMESIS SEC - ESCRITA FORA DO ESCOPO PERMITIDO · {}",
                file_path
            )),
            rule: Some(".devin/workflows — aprovação específica por path protegido".to_string()),
            suggestion: Some(format!("Execute o workflow correspondente. Artifact necessário: {}", required_artifacts.get(0).cloned().unwrap_or_else(|| "work-*-approved.txt".to_string()))),
        });
    }

    let approval_needed = if approval_artifacts.is_empty() {
        "work-*-approved.txt".to_string()
    } else {
        approval_artifacts.join(" ou ")
    };

    Some(ValidationResult {
        valid: false,
        reason: Some(format!(
            "NEMESIS SEC - ESCRITA FORA DO ESCOPO PERMITIDO · {}",
            file_path
        )),
        rule: Some(".devin/workflows — src/ e app/ requerem workflow aprovado".to_string()),
        suggestion: Some(format!(
            "Execute o workflow correspondente (ex: work-02-main), complete todas as fases de planejamento, aguarde aprovação explícita do usuário. Artifact necessário: {}.",
            approval_needed
        )),
    })
}

fn build_path_approval_map() -> HashMap<String, Vec<String>> {
    let static_config_path = get_config_path();
    
    if static_config_path.exists() {
        if let Ok(content) = fs::read_to_string(&static_config_path) {
            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&content) {
                let mut map: HashMap<String, Vec<String>> = HashMap::new();

                if let Some(workflows) = config.get("workflows").and_then(|v| v.as_object()) {
                    // work-01-rag -> Feature-Documentation/PROMPTS/
                    if let Some(work_01) = workflows.get("work-01-rag") {
                        if let Some(complete) = work_01.get("completeArtifact").and_then(|v| v.as_str()) {
                            let basename = PathBuf::from(complete).file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                            if !basename.is_empty() {
                                map.insert("Feature-Documentation/PROMPTS/".to_string(), vec![basename]);
                            }
                        }
                    }

                    // work-02-main -> src/, app/, Feature-Documentation/MEGAPLANS/
                    if let Some(work_02) = workflows.get("work-02-main") {
                        if let Some(gate_artifacts) = work_02.get("gateArtifacts").and_then(|v| v.as_array()) {
                            let approved_artifact = gate_artifacts.iter()
                                .filter_map(|v| v.as_str())
                                .find(|a| a.contains("approved.txt"));
                            if let Some(approved) = approved_artifact {
                                map.insert("src/".to_string(), vec![approved.to_string()]);
                                map.insert("/src/".to_string(), vec![approved.to_string()]);
                                map.insert("app/".to_string(), vec![approved.to_string()]);
                                map.insert("/app/".to_string(), vec![approved.to_string()]);
                                map.insert("Feature-Documentation/MEGAPLANS/".to_string(), vec![approved.to_string()]);
                            }
                        }
                    }

                    // work-06-pr -> Feature-Documentation/PR/
                    if let Some(work_06) = workflows.get("work-06-pr") {
                        if let Some(complete) = work_06.get("completeArtifact").and_then(|v| v.as_str()) {
                            let basename = PathBuf::from(complete).file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                            if !basename.is_empty() {
                                map.insert("Feature-Documentation/PR/".to_string(), vec![basename]);
                            }
                        }
                    }
                }

                if !map.is_empty() {
                    return map;
                }
            }
        }
    }

    // Fallback hardcoded
    let mut map = HashMap::new();
    map.insert("Feature-Documentation/PROMPTS/".to_string(), vec!["work-01-rag-complete.txt".to_string()]);
    map.insert("Feature-Documentation/MEGAPLANS/".to_string(), vec!["work-02-phaseA6-approved.txt".to_string()]);
    map.insert("Feature-Documentation/PR/".to_string(), vec!["work-06-pr-complete.txt".to_string()]);
    map.insert("src/".to_string(), vec!["work-02-phaseA6-approved.txt".to_string()]);
    map.insert("/src/".to_string(), vec!["work-02-phaseA6-approved.txt".to_string()]);
    map.insert("app/".to_string(), vec!["work-02-phaseA6-approved.txt".to_string()]);
    map.insert("/app/".to_string(), vec!["work-02-phaseA6-approved.txt".to_string()]);
    map
}

// =============================================================================
// SISTEMA 4 — INSTRUCTIVE BLOCKING MESSAGE
// Constrói mensagem de bloqueio com instrução exata do que o modelo deve fazer.
// Elimina o comportamento de improvisação após bloqueio.
// =============================================================================
fn build_block_message(
    block_type: &str,
    workflow_name: &str,
    attempted_phase: Option<&str>,
    config: &serde_json::Value,
) -> String {
    let workflow_config = config.get(workflow_name);

    let mut phase_instruction = String::new();
    let mut expected_phase = String::new();

    let state_path = get_runtime_dir().join("workflow-state.json");
    if state_path.exists() {
        if let Ok(content) = fs::read_to_string(&state_path) {
            if let Ok(state) = serde_json::from_str::<WorkflowState>(&content) {
                expected_phase = state.current_phase.unwrap_or_default();
            }
        }
    }

    if let Some(wf_config) = workflow_config {
        if let Some(instructions) = wf_config.get("phaseInstructions").and_then(|v| v.as_object()) {
            if !expected_phase.is_empty() {
                if let Some(instr) = instructions.get(&expected_phase).and_then(|v| v.as_str()) {
                    phase_instruction = instr.to_string();
                }
            } else if let Some(phase) = attempted_phase {
                if let Some(instr) = instructions.get(phase).and_then(|v| v.as_str()) {
                    phase_instruction = instr.to_string();
                }
            }
        }
    }

    let separator = "═".repeat(60);
    let mut message = format!("\n{}\n", separator);
    message.push_str(&format!("[NEMESIS BLOCKED] {}\n", block_type));
    message.push_str(&format!("{}\n", separator));

    if !expected_phase.is_empty() {
        message.push_str(&format!("\nFASE ESPERADA AGORA: {}\n", expected_phase));
    }

    if !phase_instruction.is_empty() {
        message.push_str(&format!("\nINSTRUÇÃO OBRIGATÓRIA:\n{}\n", phase_instruction));
    }

    message.push_str("\nREGRAS DE RECUPERAÇÃO:\n");
    message.push_str(&format!("  1. Releia a instrução da fase atual no workflow {}\n", workflow_name));
    message.push_str("  2. Execute EXATAMENTE o que a fase instrui — sem improvisar\n");
    message.push_str("  3. NÃO tente contornar o bloqueio\n");
    message.push_str("  4. NÃO delete artefatos\n");
    message.push_str("  5. NÃO invente comandos do tracker\n");
    message.push_str("  6. NÃO busque no filesystem como solução\n");
    message.push_str("  7. O bloqueio só cessa quando a fase for executada corretamente\n");
    message.push_str(&format!("\n{}\n", separator));

    message
}

// =============================================================================
// LEGACY: SEQUENCE ENFORCEMENT
// Mantido para work-03, work-04, work-05.
// =============================================================================
fn check_workflow_sequence(file_path: &str) -> Option<ValidationResult> {
    let normalized = file_path.replace('\\', "/");
    let re = Regex::new(r"\.nemesis/runtime/(work-[\w.\-]+\.txt)$").unwrap();
    
    let artifact_match = re.captures(&normalized)?;
    let artifact_name = artifact_match.get(1)?.as_str();

    // Não aplica o sistema legado em artefatos progressivos
    if artifact_name.starts_with("artefato-") {
        return None;
    }

    let dep_map = build_workflow_dependency_map();
    let required = dep_map.get(artifact_name)?;

    let required_path = get_runtime_dir().join(required);
    if !required_path.exists() {
        return Some(ValidationResult {
            valid: false,
            reason: Some(format!(
                "NEMESIS SEC - ESCRITA FORA DO ESCOPO PERMITIDO · {}",
                artifact_name
            )),
            rule: Some(".devin/workflows — sequência obrigatória de gates".to_string()),
            suggestion: Some(format!("Crie primeiro: {}. A sequência é definida pelo workflow e não pode ser alterada.", required)),
        });
    }

    None
}

// =============================================================================
// SISTEMA 5 — PROACTIVE EXECUTION PLAN REGISTRATION
// Quando um workflow inicia, o Nemesis carrega e registra o plano completo.
// O hook passa a conhecer todas as fases e pode antecipar e controlar a execução.
// =============================================================================
fn load_workflow_plan(workflow_name: &str, config: &serde_json::Value) {
    let Some(workflow_config) = config.get(workflow_name) else { return };
    let Some(phase_sequence) = workflow_config.get("phaseSequence").and_then(|v| v.as_array()) else { return };
    if phase_sequence.is_empty() { return; }

    let state_path = get_runtime_dir().join("workflow-state.json");
    
    let mut state: WorkflowState = if state_path.exists() {
        fs::read_to_string(&state_path)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_else(|| WorkflowState {
                active_workflow: workflow_name.to_string(),
                started_at: chrono::Utc::now().to_rfc3339(),
                total_steps: 0,
                completed_steps: Vec::new(),
                current_step: 0,
                unlocked_fragment: None,
                current_phase: None,
                execution_plan: None,
                completed_phases: None,
                plan_loaded_at: None,
                required_before_write: HashMap::new(),
            })
    } else {
        WorkflowState {
            active_workflow: workflow_name.to_string(),
            started_at: chrono::Utc::now().to_rfc3339(),
            total_steps: 0,
            completed_steps: Vec::new(),
            current_step: 0,
            unlocked_fragment: None,
            current_phase: None,
            execution_plan: None,
            completed_phases: None,
            plan_loaded_at: None,
            required_before_write: HashMap::new(),
        }
    };

    // FIX: Recarregar o plano se a phaseSequence mudou
    let saved_plan = state.execution_plan.clone();
    let phase_seq_strings: Vec<String> = phase_sequence.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
    
    let plan_outdated = saved_plan.as_ref().map_or(true, |sp| {
        sp.first() != phase_seq_strings.first() || sp.len() != phase_seq_strings.len()
    });

    if state.active_workflow == workflow_name && state.execution_plan.is_some() && !plan_outdated {
        return;
    }

    state.active_workflow = workflow_name.to_string();
    state.execution_plan = Some(phase_seq_strings.clone());
    state.current_phase = phase_seq_strings.first().cloned();
    state.completed_phases = Some(Vec::new());
    state.plan_loaded_at = Some(chrono::Utc::now().to_rfc3339());

    let _ = fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap_or_default());
}

/// Avança o plano de execução para a próxima fase após uma fase ser completada.
fn advance_workflow_phase(workflow_name: &str, completed_phase: &str, config: &serde_json::Value) {
    let Some(workflow_config) = config.get(workflow_name) else { return };
    let Some(phase_sequence) = workflow_config.get("phaseSequence").and_then(|v| v.as_array()) else { return };

    let state_path = get_runtime_dir().join("workflow-state.json");
    if !state_path.exists() { return }

    let Ok(content) = fs::read_to_string(&state_path) else { return };
    let Ok(mut state) = serde_json::from_str::<WorkflowState>(&content) else { return };

    if state.active_workflow != workflow_name { return }

    let phase_seq_strings: Vec<String> = phase_sequence.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
    
    let Some(completed_index) = phase_seq_strings.iter().position(|p| p == completed_phase) else { return };

    // Registrar fase como completa
    if state.completed_phases.is_none() {
        state.completed_phases = Some(Vec::new());
    }
    if let Some(ref mut phases) = state.completed_phases {
        if !phases.contains(&completed_phase.to_string()) {
            phases.push(completed_phase.to_string());
        }
    }

    // Avançar para próxima fase
    let next_index = completed_index + 1;
    if next_index < phase_seq_strings.len() {
        state.current_phase = Some(phase_seq_strings[next_index].clone());
    } else {
        state.current_phase = Some("COMPLETE".to_string());
    }

    let _ = fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap_or_default());
}

// =============================================================================
// INTRA-WORKFLOW PHASE SEQUENCE ENFORCEMENT — Sistema 3
// Verifica se as fases anteriores existem com convergencia: SIM
// antes de permitir escrita da fase atual no artefato progressivo.
// =============================================================================
struct PhaseSequenceCheck {
    allowed: bool,
    reason: Option<String>,
}

fn check_phase_sequence(
    artefato_path: &str,
    new_content: &str,
    workflow_name: &str,
    config: &serde_json::Value,
) -> PhaseSequenceCheck {
    let Some(workflow_config) = config.get(workflow_name) else {
        return PhaseSequenceCheck { allowed: true, reason: None };
    };
    
    let Some(phase_sequence) = workflow_config.get("phaseSequence").and_then(|v| v.as_array()) else {
        return PhaseSequenceCheck { allowed: true, reason: None };
    };
    
    if phase_sequence.is_empty() {
        return PhaseSequenceCheck { allowed: true, reason: None };
    }

    let convergence_marker = workflow_config
        .get("convergenceMarker")
        .and_then(|v| v.as_str())
        .unwrap_or("convergencia: SIM");

    let phase_seq_strings: Vec<String> = phase_sequence.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();

    // Detectar qual fase está sendo escrita no novo conteúdo
    let phase_being_written = phase_seq_strings.iter().find(|phase| new_content.contains(*phase));
    
    let Some(phase_being_written) = phase_being_written else {
        return PhaseSequenceCheck { allowed: true, reason: None };
    };

    let current_index = phase_seq_strings.iter().position(|p| p == phase_being_written).unwrap_or(0);

    // Artefato não existe no disco — apenas primeira fase pode iniciar
    if !PathBuf::from(artefato_path).exists() {
        if current_index == 0 {
            return PhaseSequenceCheck { allowed: true, reason: None };
        }
        return PhaseSequenceCheck {
            allowed: false,
            reason: Some(format!(
                concat!(
                    "[NEMESIS INTRA-SKIP BLOCKED] Tentativa de escrever {} mas o artefato NÃO EXISTE em disco.\n",
                    "AÇÃO OBRIGATÓRIA: Use a ferramenta nativa de escrita para CRIAR o arquivo {} com {} como PRIMEIRA SEÇÃO.\n",
                    "current-model.json não é suficiente. O artefato progressivo precisa existir com {} antes de qualquer outra fase.\n",
                    "NÃO execute bash. NÃO use redirect. Use Write File / Edit File no artefato diretamente."
                ),
                phase_being_written,
                PathBuf::from(artefato_path).file_name().and_then(|n| n.to_str()).unwrap_or(artefato_path),
                phase_seq_strings[0],
                phase_seq_strings[0]
            )),
        };
    }

    let Ok(existing_content) = fs::read_to_string(artefato_path) else {
        return PhaseSequenceCheck { allowed: true, reason: None };
    };

    // Verificar TODAS as fases anteriores na sequência
    for i in 0..current_index {
        let required_phase = &phase_seq_strings[i];

        if !existing_content.contains(required_phase) {
            return PhaseSequenceCheck {
                allowed: false,
                reason: Some(format!(
                    "[NEMESIS INTRA-SKIP BLOCKED] Tentativa de escrever {} (índice {}) sem {} (índice {}) existir no artefato. Skip de fase bloqueado.",
                    phase_being_written, current_index, required_phase, i
                )),
            };
        }

        // Verificar convergencia: SIM para a fase anterior
        let phase_start = existing_content.find(required_phase).unwrap_or(0);
        let next_phase_start = if i + 1 < phase_seq_strings.len() {
            existing_content.find(&phase_seq_strings[i + 1]).unwrap_or(existing_content.len())
        } else {
            existing_content.len()
        };

        let phase_segment = if next_phase_start > phase_start {
            &existing_content[phase_start..next_phase_start]
        } else {
            &existing_content[phase_start..]
        };

        if !phase_segment.contains(convergence_marker) {
            return PhaseSequenceCheck {
                allowed: false,
                reason: Some(format!(
                    "[NEMESIS CONVERGENCIA BLOCKED] {} existe no artefato mas SEM \"{}\". Fase incompleta. Corrija {} antes de escrever {}.",
                    required_phase, convergence_marker, required_phase, phase_being_written
                )),
            };
        }
    }

    PhaseSequenceCheck { allowed: true, reason: None }
}

// =============================================================================
// ARTEFATO PROGRESSIVO — VALIDAÇÃO DE CONTEÚDO
// Valida escritas no artefato progressivo (artefato-*.txt).
// Regras:
//   1. Cada fase (## FASE-XX) deve ter um bloco ## AUDIT-FASE-XX correspondente
//      antes que uma nova fase possa ser adicionada.
//   2. Qualquer AUDIT com convergencia: NÃO bloqueia imediatamente.
//   3. AUDIT com convergencia ausente é tratado como inválido.
// Esta função é chamada com o NOVO conteúdo que o modelo está tentando escrever.
// =============================================================================
fn check_artifact_write(file_path: &str, content: &str) -> Option<ValidationResult> {
    let normalized = file_path.replace('\\', "/");
    let re = Regex::new(r"\.nemesis/runtime/artefato-[\w-]+\.txt$").unwrap();
    
    if !re.is_match(&normalized) {
        return None;
    }

    if content.trim().is_empty() {
        return None;
    }

    // WORKFLOW ACTIVE GUARD
    let early_config_path = get_config_path();
    let mut early_workflow_config: serde_json::Value = serde_json::json!({});
    
    if early_config_path.exists() {
        if let Ok(content) = fs::read_to_string(&early_config_path) {
            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&content) {
                early_workflow_config = config.get("workflows").cloned().unwrap_or(serde_json::json!({}));
            }
        }
    }

    // Detectar workflow name do artefato
    let workflow_re = Regex::new(r"artefato-(work-[\w-]+)\.txt$").unwrap();
    let workflow_match = workflow_re.captures(&normalized)?;
    let expected_workflow = workflow_match.get(1)?.as_str();

    let workflow_state_path = get_runtime_dir().join("workflow-state.json");
    
    if !workflow_state_path.exists() {
        let block_msg = build_block_message(
            &format!("workflow-state.json ausente — artefato \"{}\" não pode ser escrito", PathBuf::from(file_path).file_name()?.to_str()?),
            expected_workflow,
            None,
            &early_workflow_config,
        );
        return Some(ValidationResult {
            valid: false,
            reason: Some(block_msg),
            rule: Some(".devin/workflows — tracker start obrigatório antes de escrever artefato".to_string()),
            suggestion: Some(format!("Execute: workflow-step-tracker start {} [total-steps]", expected_workflow)),
        });
    }

    let Ok(state_content) = fs::read_to_string(&workflow_state_path) else {
        return Some(ValidationResult {
            valid: false,
            reason: Some(format!(
                "Artefato \"{}\" bloqueado: workflow-state.json corrompido. Execute tracker start para reiniciar o estado.",
                PathBuf::from(file_path).file_name()?.to_str()?
            )),
            rule: Some(".devin/workflows — workflow-state.json deve ser legível".to_string()),
            suggestion: Some(format!("Execute: workflow-step-tracker start {} [total-steps]", expected_workflow)),
        });
    };

    let Ok(state) = serde_json::from_str::<WorkflowState>(&state_content) else {
        return Some(ValidationResult {
            valid: false,
            reason: Some(format!(
                "Artefato \"{}\" bloqueado: workflow-state.json corrompido. Execute tracker start para reiniciar o estado.",
                PathBuf::from(file_path).file_name()?.to_str()?
            )),
            rule: Some(".devin/workflows — workflow-state.json deve ser legível".to_string()),
            suggestion: Some(format!("Execute: workflow-step-tracker start {} [total-steps]", expected_workflow)),
        });
    };

    if state.active_workflow != expected_workflow {
        let block_msg = build_block_message(
            &format!("workflow ativo é \"{}\" — artefato de \"{}\" está bloqueado", state.active_workflow, expected_workflow),
            &state.active_workflow,
            None,
            &early_workflow_config,
        );
        return Some(ValidationResult {
            valid: false,
            reason: Some(block_msg),
            rule: Some(".devin/workflows — artefato deve corresponder ao workflow ativo em workflow-state.json".to_string()),
            suggestion: Some(format!("Execute: workflow-step-tracker start {} [total-steps]", expected_workflow)),
        });
    }

    // SISTEMA 5 — Registrar plano de execução ao detectar início de workflow
    load_workflow_plan(expected_workflow, &early_workflow_config);

    // SISTEMA 3 — INTRA-WORKFLOW PHASE SEQUENCE ENFORCEMENT
    // PATCH: TRACKER STEP VALIDATION
    if early_config_path.exists() {
        if let Ok(config_content) = fs::read_to_string(&early_config_path) {
            if let Ok(workflow_config) = serde_json::from_str::<serde_json::Value>(&config_content) {
                if let Some(phase_sequence) = workflow_config.get("phaseSequence").and_then(|v| v.as_array()) {
                    let phase_seq_strings: Vec<String> = phase_sequence.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                    
                    if !phase_seq_strings.is_empty() {
                        // Verifica se o step correspondente foi marcado como concluído
                        if let Ok(tracker_content) = fs::read_to_string(&workflow_state_path) {
                            if let Ok(tracker_state) = serde_json::from_str::<WorkflowState>(&tracker_content) {
                                let phase_being_written = phase_seq_strings.iter().find(|phase| content.contains(*phase));
                                
                                if let Some(phase) = phase_being_written {
                                    if let Some(phase_index) = phase_seq_strings.iter().position(|p| p == phase) {
                                        if phase_index > 0 {
                                            let required_step = phase_index as i32;
                                            if !tracker_state.completed_steps.contains(&required_step) {
                                                return Some(ValidationResult {
                                                    valid: false,
                                                    reason: Some(format!(
                                                        concat!(
                                                            "[NEMESIS TRACKER GATE] Tentativa de escrever {} bloqueada: Step {} não foi marcado como concluído.\n",
                                                            "Execute obrigatoriamente ANTES de avançar:\n",
                                                            "workflow-step-tracker complete {}\n",
                                                            "Workflow ativo: {} | Steps concluídos: {:?}"
                                                        ),
                                                        phase, required_step, required_step, tracker_state.active_workflow, tracker_state.completed_steps
                                                    )),
                                                    rule: Some(".devin/workflows — tracker complete obrigatório antes de avançar fase".to_string()),
                                                    suggestion: None,
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                let phase_check = check_phase_sequence(file_path, content, expected_workflow, &early_workflow_config);
                if !phase_check.allowed {
                    return Some(ValidationResult {
                        valid: false,
                        reason: phase_check.reason.or_else(|| Some("Skip de fase bloqueado pelo Nemesis".to_string())),
                        rule: Some(".devin/workflows — intra-workflow phase sequence enforcement".to_string()),
                        suggestion: Some("Execute as fases em ordem sequencial conforme definido no workflow.".to_string()),
                    });
                }
            }
        }
    }

    // Extrai todos os cabeçalhos de fase (exclui AUDIT)
    let fase_re = Regex::new(r"^## (FASE-[\w-]+)").unwrap();
    let fases: Vec<String> = content.lines()
        .filter_map(|line| fase_re.captures(line))
        .map(|cap| cap[1].to_string())
        .filter(|fase| !fase.contains("AUDIT"))
        .collect();

    if fases.is_empty() {
        return None;
    }

    // Extrai todos os blocos AUDIT e seus valores de convergencia
    let mut audit_map: HashMap<String, String> = HashMap::new();
    let audit_re = Regex::new(r"(?m)^## AUDIT-(FASE-[\w-]+)\b\n([\s\S]*?)^---$").unwrap();
    
    for cap in audit_re.captures_iter(content) {
        let fase_name = cap[1].to_string();
        let audit_body = &cap[2];
        let converg_re = Regex::new(r"convergencia:\s*(SIM|NÃO|NAO)").unwrap();
        let converg_value = if let Some(converg_cap) = converg_re.captures(audit_body) {
            converg_cap[1].to_uppercase().replace("NAO", "NÃO")
        } else {
            "MISSING".to_string()
        };
        audit_map.insert(fase_name, converg_value);
    }

    // Regra 1: qualquer convergencia: NÃO → bloqueio imediato
    for (fase, convergencia) in &audit_map {
        if convergencia == "NÃO" {
            let block_msg = build_block_message(
                &format!("{} declarou convergencia: NÃO — fase não convergiu com o solicitado", fase),
                expected_workflow,
                Some(&format!("## {}", fase)),
                &early_workflow_config,
            );
            return Some(ValidationResult {
                valid: false,
                reason: Some(block_msg),
                rule: Some(".devin/workflows — auto-auditoria: convergencia: NÃO bloqueia execução".to_string()),
                suggestion: Some(format!("Revise o conteúdo de {}, corrija o que divergiu, reescreva AUDIT-{} com convergencia: SIM.", fase, fase)),
            });
        }
    }

    // VALIDAÇÃO EM 3 CAMADAS COM FLEXIBILIZAÇÃO INICIAL
    // Camada 1: Estrutura (## FASE-N existe) — sempre permitido
    // Camada 2: Conteúdo (dados preenchidos) — permitido na primeira escrita
    // Camada 3: Audit (## AUDIT-FASE-N com convergencia: SIM) — exigido antes de avançar para próxima fase

    // Regra 2: Todas as fases EXCETO a última devem ter AUDIT com convergencia: SIM
    let fases_para_validar = &fases[..fases.len().saturating_sub(1)];
    for fase in fases_para_validar {
        let convergencia = audit_map.get(fase);

        if convergencia.is_none() || convergencia.unwrap() == "MISSING" {
            let block_msg = build_block_message(
                &format!("{} não tem bloco AUDIT obrigatório com convergencia declarada", fase),
                expected_workflow,
                Some(&format!("## {}", fase)),
                &early_workflow_config,
            );
            return Some(ValidationResult {
                valid: false,
                reason: Some(block_msg),
                rule: Some(".devin/workflows — AUDIT obrigatório antes de avançar para próxima fase".to_string()),
                suggestion: Some(format!("Adicione:\n## AUDIT-{}\nsolicitado: [pedido]\nproduzido: [gerado]\nconvergencia: SIM\n---", fase)),
            });
        }
    }

    // Regra 3: Última fase pode estar em qualquer camada de validação
    let ultima_fase = fases.last()?;
    let ultima_fase_tem_audit = audit_map.contains_key(ultima_fase);

    // Se a última fase já tem AUDIT, então está tudo completo
    // Permitir adição de nova fase quando todas as anteriores têm AUDIT
    if ultima_fase_tem_audit && !fases_para_validar.is_empty() {
        let proxima_fase_esperada = format!("FASE-{}", fases.len());
        if content.contains(&proxima_fase_esperada) {
            // Nova fase está sendo adicionada — permitir (Camada 1)
            // SISTEMA 5 — Avançar fase após escrita aprovada com convergencia: SIM
            if early_config_path.exists() {
                if let Ok(config_content) = fs::read_to_string(&early_config_path) {
                    if let Ok(workflow_config) = serde_json::from_str::<serde_json::Value>(&config_content) {
                        let workflow_config_data = workflow_config.get("workflows").cloned().unwrap_or(serde_json::json!({}));
                        advance_workflow_phase(expected_workflow, ultima_fase, &workflow_config_data);
                    }
                }
            }
            return None;
        }
    }

    // Permitir escrita na última fase em qualquer estágio (Camada 1, 2 ou 3)
    // SISTEMA 5 — Avançar fase após escrita aprovada com convergencia: SIM
    if ultima_fase_tem_audit && content.contains("convergencia: SIM") {
        if early_config_path.exists() {
            if let Ok(config_content) = fs::read_to_string(&early_config_path) {
                if let Ok(workflow_config) = serde_json::from_str::<serde_json::Value>(&config_content) {
                    let workflow_config_data = workflow_config.get("workflows").cloned().unwrap_or(serde_json::json!({}));
                    advance_workflow_phase(expected_workflow, ultima_fase, &workflow_config_data);
                }
            }
        }
    }

    None
}

// =============================================================================
// BASH SEQUENCE + MASS EXECUTION GUARD
// =============================================================================
fn check_bash_sequence(command: &str) -> Option<ValidationResult> {
    // Guard 1: Bash redirect para artefato progressivo é proibido.
    // O artefato DEVE ser escrito via Devin native write tool.
    let artefato_redirect = Regex::new(r"[>]{1,2}\s*[\w./\-]*\.nemesis/runtime/artefato-[\w-]+\.txt").unwrap();
    if artefato_redirect.is_match(command) {
        return Some(ValidationResult {
            valid: false,
            reason: Some(
                "Bash redirect para artefato progressivo bloqueado. O artefato deve ser escrito exclusivamente via Devin native write tool (não via terminal).".to_string()
            ),
            rule: Some(".devin/workflows — artefato progressivo requer escrita via ferramenta nativa".to_string()),
            suggestion: Some(
                "Use a ferramenta nativa de escrita do Devin para escrever/atualizar o artefato. O terminal não pode criar ou modificar artefato-*.txt.".to_string()
            ),
        });
    }

    // Guard 2: Coleta todos os gate artifacts únicos no comando (sistema legado)
    let mut collected: HashMap<String, String> = HashMap::new();

    let redirect_full = Regex::new(r"[>]{1,2}\s*([\w./\-]*\.nemesis/runtime/work-[\w.\-]+\.txt)").unwrap();
    for cap in redirect_full.captures_iter(command) {
        let target_path = cap[1].trim().to_string();
        let normalized = if target_path.starts_with('/') {
            target_path.replacen(&format!("{}/", get_cwd().to_string_lossy()), "", 1)
        } else {
            target_path.clone()
        };
        let basename = PathBuf::from(&normalized).file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        if !basename.starts_with("artefato-") && !collected.contains_key(&basename) {
            collected.insert(basename, normalized);
        }
    }

    let redirect_relative = Regex::new(r"[>]{1,2}\s*(work-[\w.\-]+\.txt)").unwrap();
    for cap in redirect_relative.captures_iter(command) {
        let artifact = cap[1].trim().to_string();
        if artifact.starts_with("artefato-") {
            continue;
        }
        let normalized = format!(".nemesis/runtime/{}", artifact);
        let basename = PathBuf::from(&normalized).file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        if !collected.contains_key(&basename) {
            collected.insert(basename, normalized);
        }
    }

    if collected.is_empty() {
        return None;
    }

    // Guard 3: Mais de 1 gate em um único comando = execução em massa
    if collected.len() > 1 {
        let names: Vec<_> = collected.keys().cloned().collect();
        let first = names.first().unwrap();
        let names_joined = names.join(", ");
        return Some(ValidationResult {
            valid: false,
            reason: Some(format!(
                "Execução em massa bloqueada: o comando tenta criar {} gate artifacts em uma única execução ({}). O workflow exige UM gate por vez, com confirmação do usuário entre cada execução.",
                collected.len(), names_joined
            )),
            rule: Some(".devin/workflows — execução sequencial obrigatória, um gate por vez".to_string()),
            suggestion: Some(format!(
                "Execute apenas o próximo gate pendente: {}. Aguarde confirmação do usuário antes de executar o gate seguinte.",
                first
            )),
        });
    }

    // Guard 4: Sequência intra-workflow (sistema legado)
    for normalized in collected.values() {
        if let Some(result) = check_workflow_sequence(normalized) {
            return Some(result);
        }
    }

    None
}

// =============================================================================
// READ STDIN
// =============================================================================
fn read_stdin() -> io::Result<String> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    Ok(buffer)
}

// =============================================================================
// NEMESIS INFRASTRUCTURE PROTECTION
// Bloqueia leitura e escrita em paths protegidos pelo denylist-folder-files.json
// Fonte unica de verdade: .nemesis/denylist/denylist-folder-files.json
// =============================================================================

fn path_matches_allowed_exception(rel_path: &str, exception: &str) -> bool {
    let exc = exception.trim().trim_matches('/').to_lowercase();
    if exc.is_empty() {
        return false;
    }
    let rel = rel_path.trim_start_matches("./").to_lowercase();
    rel == exc || rel.starts_with(&format!("{}/", exc))
}

fn check_nemesis_protected_path(file_path: &str, is_write: bool) -> Option<ValidationResult> {
    if file_path.is_empty() {
        return None;
    }

    let rel_path = normalize_to_relative(file_path);

    // Leitura pontual em subpastas liberadas de .nemesis/
    if rel_path.starts_with(".nemesis/") || rel_path == ".nemesis" {
        let allowed_prefixes = [
            ".nemesis/runtime/",
            ".nemesis/logs/",
            ".nemesis/denylist/",
            ".nemesis/nemesis-defender/config/",
            ".nemesis/defender-exclude.txt",
        ];
        if allowed_prefixes.iter().any(|prefix| rel_path.starts_with(prefix)) {
            return None;
        }
    }

    let project_root = get_cwd().to_string_lossy().to_string();
    if let Some(denylist) = load_denylist_folder_files(&project_root) {
        if let Some(blocked) = check_folder_file_access(&denylist, file_path, is_write) {
            return Some(blocked);
        }
    }

    if rel_path.starts_with(".nemesis/") || rel_path == ".nemesis" {
        return Some(ValidationResult {
            valid: false,
            reason: Some(format!(
                "NEMESIS SEC - {} - ARQUIVO PROTEGIDO · {}",
                if is_write { "ACESSO NEGADO" } else { "LEITURA NEGADA" },
                rel_path
            )),
            rule: Some(".nemesis/NemesisFrameworkDocumentation — infrastructure protection".to_string()),
            suggestion: Some(
                "Arquivos de infraestrutura do Nemesis sao gerenciados exclusivamente pelo usuario."
                    .to_string(),
            ),
        });
    }

    None
}

// =============================================================================
// DENYLIST FOLDER FILES — Carregamento e verificacao
// =============================================================================

fn load_denylist_folder_files(project_root: &str) -> Option<DenylistFolderFiles> {
    let path = format!(
        "{}/.nemesis/denylist/denylist-folder-files.json",
        project_root
    );
    match fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(denylist) => Some(denylist),
            Err(e) => {
                eprintln!("[NEMESIS WARNING] Failed to parse denylist-folder-files.json: {}", e);
                None
            }
        },
        Err(_) => None, // File not found is not an error
    }
}

fn normalize_to_relative(file_path: &str) -> String {
    let path = file_path.replace('\\', "/");

    let mut components: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                components.pop();
            }
            _ => components.push(part),
        }
    }

    if let Ok(cwd) = env::current_dir() {
        let cwd_str = cwd.to_string_lossy().replace('\\', "/");
        let cwd_parts: Vec<&str> = cwd_str
            .split('/')
            .filter(|p| !p.is_empty())
            .collect();
        if components.len() >= cwd_parts.len() && components[..cwd_parts.len()] == cwd_parts[..] {
            let rel = components[cwd_parts.len()..].join("/");
            return trim_leading_dot_slash(&rel);
        }
    }

    let joined = components.join("/");
    extract_dotdir_suffix(&joined)
}

fn trim_leading_dot_slash(path: &str) -> String {
    if path.starts_with("./") {
        path[2..].to_string()
    } else {
        path.to_string()
    }
}

/// Fallback: extrai sufixo .cursor/, .devin/, etc. de paths absolutos residuais.
fn extract_dotdir_suffix(path: &str) -> String {
    let trimmed = trim_leading_dot_slash(path);
    for marker in [
        "/.nemesis/",
        "/.github/",
        "/.vscode/",
        "/.claude/",
        "/.devin/",
        "/.cursor/",
        "/.codex/",
        "/.openclaude/",
    ] {
        if let Some(idx) = trimmed.rfind(marker) {
            return trimmed[idx + 1..].to_string();
        }
    }
    if trimmed.starts_with(".env") || trimmed.starts_with(".gitignore") {
        trimmed
    } else {
        trimmed
    }
}

fn check_folder_file_access(
    denylist: &DenylistFolderFiles,
    file_path: &str,
    is_write: bool,
) -> Option<ValidationResult> {
    let rel_path = normalize_to_relative(file_path);

    // 1. Verificar write_block (somente se e operacao de escrita — leitura permitida)
    // Vem ANTES do absolute_block para permitir leitura em paths com ambos
    for blocked in &denylist.write_block.files {
        if rel_path.ends_with(blocked) || rel_path == *blocked {
            if is_write {
                return Some(ValidationResult {
                    valid: false,
                    reason: Some(format!(
                        "NEMESIS SEC - ACESSO NEGADO - ARQUIVO PROTEGIDO · {}",
                        rel_path
                    )),
                    rule: Some("denylist-folder-files.json".to_string()),
                    suggestion: Some("Arquivos de configuracao do projeto sao gerenciados exclusivamente pelo usuario.".to_string()),
                });
            }
            // Leitura em write_block: PERMITIDA (sobrescreve absolute_block)
            return None;
        }
    }

    // 2. Verificar absolute_block — bloqueio total (só aplica se NÃO está em write_block)
    for blocked in &denylist.absolute_block.paths {
        let blocked_trimmed = blocked.trim_end_matches('/');
        if rel_path.starts_with(blocked)
            || rel_path.starts_with(blocked_trimmed)
            || rel_path == blocked_trimmed {
            let is_exception = denylist.absolute_block.allowed_exceptions
                .iter()
                .any(|exc| path_matches_allowed_exception(&rel_path, exc));

            if !is_exception {
                return Some(ValidationResult {
                    valid: false,
                    reason: Some(format!(
                        "NEMESIS SEC - {} - ARQUIVO PROTEGIDO · {}",
                        if is_write { "ACESSO NEGADO" } else { "LEITURA NEGADA" },
                        rel_path
                    )),
                    rule: Some("denylist-folder-files.json".to_string()),
                    suggestion: Some("Arquivos protegidos sao gerenciados exclusivamente pelo usuario.".to_string()),
                });
            }
        }
    }

    None // Permitido
}

fn validate_file_operation(file_path: &str, action: &str, _content: Option<&str>) -> ValidationResult {
    if file_path.is_empty() {
        return ValidationResult {
            valid: false,
            reason: Some("Caminho do arquivo não fornecido".to_string()),
            rule: Some(".devin/rules/README.md".to_string()),
            suggestion: Some("Especifique o caminho completo do arquivo".to_string()),
        };
    }

    // NEMESIS INFRASTRUCTURE PROTECTION — verificar antes de qualquer outra validacao
    let is_write = action == "pre_write_code" || action == "post_write_code";
    if let Some(blocked) = check_nemesis_protected_path(file_path, is_write) {
        return blocked;
    }

    // Arquivos de configuracao criticos do projeto — BLOQUEIO de escrita/edicao (leitura permitida)
    let critical_config_files = [
        "package.json",
        "next.config.js",
        "next.config.mjs",
        "next.config.ts",
        "eslint.config.mjs",
        "eslint.config.js",
        ".eslintrc",
        ".eslintrc.json",
        ".env",
        ".env.local",
        ".env.production",
        ".gitignore",
        "proxy.ts",
    ];
    let cfg_file_name = file_path.replace('\\', "/");
    let cfg_file_name = cfg_file_name.split('/').last().unwrap_or("");
    if critical_config_files.iter().any(|f| cfg_file_name == *f) {
        return ValidationResult {
            valid: false,
            reason: Some(format!(
                "NEMESIS SEC - ACESSO NEGADO - ARQUIVO PROTEGIDO · {}",
                cfg_file_name
            )),
            rule: Some(".devin/rules/README.md".to_string()),
            suggestion: Some("Arquivos de configuracao do projeto sao gerenciados exclusivamente pelo usuario.".to_string()),
        };
    }

    let path_buf = PathBuf::from(file_path);
    let file_name = path_buf.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if ABSOLUTE_PROTECTED_RUNTIME_FILES.contains(&file_name) {
        return ValidationResult {
            valid: false,
            reason: Some(format!(
                "NEMESIS SEC - ACESSO NEGADO - ARQUIVO PROTEGIDO · {}",
                file_name
            )),
            rule: Some(".devin/rules/README.md".to_string()),
            suggestion: Some(format!("LEITURA & EDIÇÃO PROIBIDA: {}", file_name)),
        };
    }

    // Workflow sequence enforcement removido — SDD pipeline migrou para skills

    let absolute_path = if file_path.starts_with('/') {
        PathBuf::from(file_path)
    } else {
        get_cwd().join(file_path)
    };

    let is_in_project = absolute_path.to_string_lossy().starts_with(&get_cwd().to_string_lossy().to_string());
    if !is_in_project {
        let allowed_paths = ["/tmp", "/var/tmp", "/dev/null"];
        let path_str = absolute_path.to_string_lossy();
        if !allowed_paths.iter().any(|p| path_str.starts_with(p)) {
            return ValidationResult {
                valid: false,
                reason: Some(format!("NEMESIS SEC - ESCRITA FORA DO ESCOPO PERMITIDO · {}", file_path)),
                rule: Some(".devin/rules/README.md".to_string()),
                suggestion: Some("IDENTIFIQUE QUAL REGRA VOCE ESTA VIOLANDO .devin/rules/README.md".to_string()),
            };
        }
    }

    // Arquivos críticos
    let critical_patterns = [
        r"\.git/",
        r"\.gitignore$",
        r"package\.json$",
        r"yarn\.lock$",
        r"\.env$",
        r"\.env\.local$",
        r"\.env\..*$",
        r"tsconfig\.json$",
        r"tailwind\.config",
        r"next\.config",
    ];

    let path_str = absolute_path.to_string_lossy();
    let is_critical = critical_patterns.iter().any(|pattern| {
        Regex::new(pattern).map(|re| re.is_match(&path_str)).unwrap_or(false)
    });

    // CONTENCAO DE PATH TRAVERSAL (incondicional, SPEC_005): resolve `.`/`..` lexicamente
    // (sem exigir que o arquivo exista) e bloqueia toda escrita cujo path resolvido caia FORA
    // da raiz do projeto. Roda SEMPRE — independente de scope.json ou de o arquivo ser critico —
    // fechando o vetor em que `canonicalize()` falha para arquivos novos e o `..` cru escapa.
    if !is_write_within_project(file_path) {
        return ValidationResult {
            valid: false,
            reason: Some(format!("NEMESIS SEC - ESCRITA FORA DO PROJETO · {}", file_path)),
            rule: Some(".devin/rules/README.md".to_string()),
            suggestion: Some(
                "Escrita permitida apenas dentro da raiz do projeto (sem path traversal `../`)."
                    .to_string(),
            ),
        };
    }

    if is_critical {
        // Check scope validator first
        if has_scope_active() {
            let scope_result = validate_file_scope(file_path);
            if !scope_result.valid {
                return scope_result;
            }
        }

        // Check permission gate
        let (allowed, _reason) = can_modify_file(file_path);
        if !allowed {
            return ValidationResult {
                valid: false,
                reason: Some("NEMESIS SEC - ACESSO NEGADO - ARQUIVO PROTEGIDO".to_string()),
                rule: Some(".devin/rules/Conformidade.md - Secao 3 (Protecao de Dados)".to_string()),
                suggestion: Some("Arquivos de configuracao requerem autorizacao explicita do Step 7.".to_string()),
            };
        }
    }

    ValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// COMMAND DECOMPOSITION — PONTO ÚNICO DE VALIDAÇÃO
// =============================================================================

/// Extrai TODOS os segmentos de um comando composto.
/// Inclui: comando original, normalizado por basename, decomposição por pipes,
/// shell wrappers, subshells, backticks. Dedup.
fn extract_all_segments(command: &str) -> Vec<String> {
    let mut segments = Vec::new();

    // Comando original
    segments.push(command.to_string());

    // Normalizar path absoluto
    let first = command.split_whitespace().next().unwrap_or("");
    if first.contains('/') {
        if let Some(base) = first.rsplit('/').next() {
            let rest = command.splitn(2, ' ').nth(1).unwrap_or("");
            let normalized = if rest.is_empty() {
                base.to_string()
            } else {
                format!("{} {}", base, rest)
            };
            if !segments.contains(&normalized) {
                segments.push(normalized);
            }
        }
    }

    // Extrair shell wrapper (bash -c, sh -c, zsh -c)
    let shell_prefixes = [
        "bash -c ", "sh -c ", "zsh -c ",
        "/bin/bash -c ", "/bin/sh -c ", "/bin/zsh -c ",
        "/usr/bin/bash -c ", "/usr/bin/sh -c ",
        "/usr/bin/env bash -c ", "/usr/bin/env sh -c ",
    ];
    for prefix in &shell_prefixes {
        if command.starts_with(prefix) {
            let inner = command[prefix.len()..].trim();
            let inner = if (inner.starts_with('"') && inner.ends_with('"'))
                || (inner.starts_with('\'') && inner.ends_with('\''))
            {
                &inner[1..inner.len()-1]
            } else {
                inner
            };
            if !segments.contains(&inner.to_string()) {
                segments.push(inner.to_string());
            }
            // Decompor o inner também recursivamente
            for sub in inner.split(|c: char| c == '|' || c == ';') {
                let s = sub.trim();
                if !s.is_empty() && !segments.contains(&s.to_string()) {
                    segments.push(s.to_string());
                }
                for sub2 in s.split("&&") {
                    let s2 = sub2.trim();
                    if !s2.is_empty() && !segments.contains(&s2.to_string()) {
                        segments.push(s2.to_string());
                    }
                }
            }
        }
    }

    // Decompor por |, ;, &&, ||
    for part in command.split(|c: char| c == '|' || c == ';') {
        let part = part.trim();
        if part.is_empty() { continue; }
        if !segments.contains(&part.to_string()) {
            segments.push(part.to_string());
        }
        for sub in part.split("&&") {
            let sub = sub.trim();
            if sub.is_empty() { continue; }
            if !segments.contains(&sub.to_string()) {
                segments.push(sub.to_string());
            }
            for subsub in sub.split("||") {
                let s = subsub.trim();
                if s.is_empty() { continue; }
                if !segments.contains(&s.to_string()) {
                    segments.push(s.to_string());
                }
            }
        }
    }

    // Extrair $(...) subshells
    let bytes = command.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$' && bytes[i+1] == b'(' {
            if let Some(end) = command[i+2..].find(')') {
                let inner = &command[i+2..i+2+end];
                if !segments.contains(&inner.to_string()) {
                    segments.push(inner.to_string());
                }
            }
        }
        i += 1;
    }

    // Extrair `...` backticks
    if let Some(start) = command.find('`') {
        if let Some(end) = command[start+1..].find('`') {
            let inner = &command[start+1..start+1+end];
            if !segments.contains(&inner.to_string()) {
                segments.push(inner.to_string());
            }
        }
    }

    // Extrair <(...) process substitution
    let bytes = command.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'<' && bytes[i+1] == b'(' {
            if let Some(end) = command[i+2..].find(')') {
                let inner = &command[i+2..i+2+end];
                if !segments.contains(&inner.to_string()) {
                    segments.push(inner.to_string());
                }
            }
        }
        i += 1;
    }

    segments
}

/// Valida comando contra TODOS os patterns de TODAS as fontes.
/// Ponto ÚNICO de validação de comando.
fn validate_full_command(
    command: &str,
    deny_patterns: &[DenyPattern],
    ebpf_commands: &[String],
) -> Option<(String, String)> {
    let segments = extract_all_segments(command);

    for segment in &segments {
        // 1. Verificar deny-list patterns (regex)
        for pattern in deny_patterns {
            if let Ok(re) = Regex::new(&pattern.pattern) {
                if re.is_match(segment) {
                    let suggestion = if pattern.suggestion.is_empty() {
                        String::new()
                    } else {
                        pattern.suggestion.clone()
                    };
                    return Some((pattern.message.clone(), suggestion));
                }
            }
        }

        // 2. Verificar commands.toml (match por nome com word boundary)
        let first_word = segment.split_whitespace().next().unwrap_or("");
        let basename = if first_word.contains('/') {
            first_word.rsplit('/').next().unwrap_or(first_word)
        } else {
            first_word
        };
        for blocked in ebpf_commands {
            if basename == blocked || basename == blocked {
                return Some((
                    format!("Comando '{}' bloqueado pela lista canônica do eBPF.", blocked),
                    "Este comando está na denylist do Nemesis eBPF.".to_string(),
                ));
            }
            // Também verificar se o segmento contém o comando como palavra (word boundary)
            // Ex: "bash -c rm" contém "rm" como palavra separada
            if segment.contains(blocked) {
                let re_str = format!(r"(?:^|\s){}[\s$]|{}$", regex::escape(blocked), regex::escape(blocked));
                if let Ok(re) = Regex::new(&re_str) {
                    if re.is_match(segment) {
                        return Some((
                            format!("Comando '{}' bloqueado pela lista canônica do eBPF.", blocked),
                            "Este comando está na denylist do Nemesis eBPF.".to_string(),
                        ));
                    }
                }
            }
        }
    }

    None
}

// =============================================================================
// VALIDAÇÃO DE COMANDO (REFATORADA)
// =============================================================================

fn validate_command(command: &str) -> ValidationResult {
    if command.trim().is_empty() {
        return ValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    // Carregar ebpf_commands para validate_full_command
    let ebpf_cmds = load_ebpf_blocked_commands();

    // DENY-LIST: validate_full_command (ponto único — decomposição total)
    let patterns = get_command_patterns();
    if let Some((_message, suggestion)) = validate_full_command(command, &patterns, &ebpf_cmds) {
        return ValidationResult {
            valid: false,
            reason: Some("NEMESIS SEC - COMANDO NAO PERMITIDO".to_string()),
            rule: Some(".nemesis/ebpf-kernel/denylist-ebpf/commands.toml".to_string()),
            suggestion: Some(suggestion),
        };
    }

    // 3. Defender scan_command (defesa em profundidade — decoders, entropy)
    {
        let defender_result = nemesis_defender::scan_command(command);
        match defender_result.severity {
            nemesis_defender::Severity::Malicious => {
                let _msgs: Vec<String> = defender_result.violations.iter()
                    .map(|v| format!("[{}] {}", v.visitor, v.message))
                    .collect();
                return ValidationResult {
                    valid: false,
                    reason: Some("NEMESIS SEC - COMANDO NAO PERMITIDO".to_string()),
                    rule: Some(".nemesis/nemesis-defender — deep command scan".to_string()),
                    suggestion: Some("Payloads ofuscados ou maliciosos sao bloqueados.".to_string()),
                };
            }
            nemesis_defender::Severity::Suspicious => {
                eprintln!("[NEMESIS WARNING] Comando suspeito: {}", command);
            }
            _ => {}
        }
    }

    // NOTA: dangerous_patterns e install_pattern foram movidos para as deny-lists JSON
    // (deny-list.json + deny-list-base.json) como fonte unica de verdade.
    // Nenhum padrao hardcoded no hook — consulta dinamica via get_command_patterns().

    ValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

async fn async_main() -> anyhow::Result<i32> {
    let input = read_stdin()?;
    if input.trim().is_empty() {
        eprintln!("NEMESIS ERROR: Nenhum input recebido via stdin");
        return Ok(1);
    }

    let data: PreToolInput = match serde_json::from_str(&input) {
        Ok(d) => d,
        Err(_e) => {
            eprintln!("NEMESIS ERROR: JSON invalido recebido");
            eprintln!("Input recebido: {}", &input[..input.len().min(200)]);
            return Ok(1);
        }
    };

    let llm_model = detect_devin_llm_model();

    let result: ValidationResult = match data.agent_action_name {
        AgentActionName::PreReadCode | AgentActionName::PostReadCode => {
            // NEMESIS INFRASTRUCTURE PROTECTION — bloquear leitura de .nemesis/ e .devin/hooks.json
            let read_path = data.tool_info.file_path.as_deref().unwrap_or("");
            if let Some(blocked) = check_nemesis_protected_path(read_path, false) {
                blocked
            } else {
                ValidationResult { valid: true, reason: None, rule: None, suggestion: None }
            }
        }
        AgentActionName::PreWriteCode | AgentActionName::PostWriteCode => {
            let write_content = data.tool_info.edits.as_ref()
                .map(|edits| edits.iter().map(|e| e.new_string.clone()).collect::<Vec<_>>().join("\n"))
                .or_else(|| data.tool_info.code_content.clone());

            let file_op_result = validate_file_operation(
                data.tool_info.file_path.as_deref().unwrap_or(""),
                data.agent_action_name.as_str(),
                write_content.as_deref(),
            );

            if file_op_result.valid {
                if let (Some(content), Some(file_path)) = (write_content, data.tool_info.file_path.clone()) {
                    // Validate code content (AST linters + deny-list do pretool)
                    let ast_result = validate_code_content(&file_path, &content);

                    if !ast_result.valid {
                        ast_result
                    } else {
                        // Defesa em profundidade: Nemesis Defender escaneia o conteudo
                        // com regex_layer, entropy, decoder recursivo e byte scanner.
                        // Isso detecta prompt injection em .md/.json/.toml/qualquer extensao.
                        let path_buf = std::path::PathBuf::from(&file_path);
                        let defender_result = nemesis_defender::scan_content(&path_buf, content.as_bytes());

                        if defender_result.severity == nemesis_defender::Severity::Malicious {
                            let _evidence: Vec<String> = defender_result.violations.iter()
                                .map(|v| format!("[{}] {} (linha {})", v.visitor, v.message, v.line))
                                .collect();

                            ValidationResult {
                                valid: false,
                                reason: Some("NEMESIS SEC - CONTEUDO MALICIOSO DETECTADO".to_string()),
                                rule: Some("nemesis-defender::scan_content".to_string()),
                                suggestion: Some(
                                    "O conteudo do arquivo contem padroes maliciosos detectados pelo Nemesis Defender. Revise o conteudo e tente novamente.".to_string()
                                ),
                            }
                        } else {
                            ValidationResult { valid: true, reason: None, rule: None, suggestion: None }
                        }
                    }
                } else {
                    ValidationResult { valid: true, reason: None, rule: None, suggestion: None }
                }
            } else {
                file_op_result
            }
        }
        AgentActionName::PreRunCommand | AgentActionName::PostRunCommand => {
            if let Some(ref command) = data.tool_info.command_line {
                validate_command(command)
            } else {
                ValidationResult { valid: true, reason: None, rule: None, suggestion: None }
            }
        }
        AgentActionName::PreMcpToolUse | AgentActionName::PostMcpToolUse => {
            if data.tool_info.mcp_server_name.is_none() {
                ValidationResult {
                    valid: false,
                    reason: Some("MCP server name nao fornecido".to_string()),
                    rule: Some(".devin/rules/rule-main-rules.md".to_string()),
                    suggestion: Some("Especifique o nome do servidor MCP".to_string()),
                }
            } else {
                ValidationResult { valid: true, reason: None, rule: None, suggestion: None }
            }
        }
        AgentActionName::PreUserPrompt | AgentActionName::PostCascadeResponse | AgentActionName::PostSetupWorktree => {
            ValidationResult { valid: true, reason: None, rule: None, suggestion: None }
        }
    };

    if !result.valid {
        let reason_text = result.reason.clone().unwrap_or_else(|| "Violação detectada pelo PreToolUse hook".to_string());
        let suggestion_text = result.suggestion.clone();

        eprintln!("{}", reason_text);
        if let Some(suggestion) = suggestion_text {
            eprintln!("→ {}", suggestion);
        }

        // Bloqueio: o nemesis-pretool-check-unix (entrypoint que executa este hook) já grava
        // este evento no ledger unificado a partir do exit-code/stderr. Não registramos aqui
        // para não duplicar a entrada. set_llm_model mantém o modelo disponível p/ o ledger.
        set_llm_model(&llm_model);

        return Ok(2);
    }

    Ok(0)
}

fn main() {
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    let exit_code = runtime.block_on(async_main()).unwrap_or(1);
    process::exit(exit_code);
}
