// =============================================================================
// Nemesis PreToolUse Hook - Unix/Bash Version
// =============================================================================
//
// BLOQUEIOS IMPLEMENTADOS (conforme violations.log):
// 1. Permission gate (idle/awaiting/granted/denied)
// 2. Redirect TS com validacao de conteudo (any, hooks condicionais, require, etc.)
// 3. Arquivos criticos via heredoc/echo redirect/printf/tee
// 4. require() em TypeScript
// 5. _document + next/head
// 6. module.exports
// 7. import type ausente para Props/Type/Config
// 8. [RESTAURADO] eslint-disable bypass
// 9. [RESTAURADO] Comandos de atualizacao em massa de dependencias
// 10. [RESTAURADO] SMART COMPONENT insercao manual
// 11. [RESTAURADO] Operacoes system-level de alto risco (npx tsx -e)
// 12. TypeScript engine (pretool-hook.ts) para validacoes avancadas
//
// RESTAURADO: 4 blocos ausentes adicionados + path do engine corrigido
// =============================================================================

use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ── Session tracking: tool context para multi-turn detection ──
thread_local! {
    static CURRENT_TOOL: RefCell<(String, String)> = RefCell::new((String::new(), String::new()));
}

// ── Antigravity IDE detection flag ──
thread_local! {
    static IS_ANTIGRAVITY: RefCell<bool> = RefCell::new(false);
}

fn map_tool_type(raw: &str) -> &'static str {
    match raw {
        "Bash" | "bash" | "RunCommand" | "run_command" | "terminal" | "Shell" | "shell"
        | "send_command_input" | "browser_subagent" => "Bash",
        "Read" | "read" | "ReadFile" | "read_file" | "View" | "view" | "Grep" | "grep" | "Glob" | "glob" | "SemanticSearch" | "semantic_search" | "WebFetch" | "web_fetch" | "TabRead" | "tab_read"
        | "view_file" | "grep_search" | "search_web" | "read_url_content" | "command_status" | "find_by_name" => "Read",
        "ListDir" | "list_dir" | "ListDirectory" | "list_directory" | "LS" | "ls" => "ListDir",
        _ => "Write",
    }
}

/// Normaliza payload Antigravity para formato DevinInput.
/// Antigravity envia: {"toolCall": {"name": "X", "args": {...}}, "stepIdx": N, ...}
/// Nemesis espera: {"toolName": "X", "toolInput": {...}}
fn normalize_antigravity_input(raw: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(raw).ok()?;
    let tool_call = val.get("toolCall")?;
    let name = tool_call.get("name")?.as_str()?;
    let args = tool_call.get("args").cloned().unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    let mut tool_input = serde_json::Map::new();
    if let Some(obj) = args.as_object() {
        for (key, value) in obj {
            match key.as_str() {
                // Antigravity arg keys → Nemesis internal keys
                "CommandLine" => { tool_input.insert("command".to_string(), value.clone()); }
                "Cwd" => { tool_input.insert("cwd".to_string(), value.clone()); }
                "TargetFile" | "AbsolutePath" => { tool_input.insert("file_path".to_string(), value.clone()); }
                "DirectoryPath" => { tool_input.insert("file_path".to_string(), value.clone()); }
                "SearchPath" => { tool_input.insert("search_path".to_string(), value.clone()); }
                "Query" => { tool_input.insert("query".to_string(), value.clone()); }
                "CodeContent" => { tool_input.insert("content".to_string(), value.clone()); }
                "TargetContent" => { tool_input.insert("old_string".to_string(), value.clone()); }
                "ReplacementContent" => { tool_input.insert("new_string".to_string(), value.clone()); }
                "Url" => { tool_input.insert("url".to_string(), value.clone()); }
                "Includes" => { tool_input.insert("includes".to_string(), value.clone()); }
                "ReplacementChunks" => {
                    // multi_replace_file_content: extrair edits e conteudo combinado
                    if let Some(chunks) = value.as_array() {
                        let mut combined = String::new();
                        let mut edits_arr: Vec<serde_json::Value> = Vec::new();
                        for chunk in chunks {
                            if let Some(co) = chunk.as_object() {
                                let old = co.get("TargetContent").cloned().unwrap_or(serde_json::Value::String(String::new()));
                                let new = co.get("ReplacementContent").cloned().unwrap_or(serde_json::Value::String(String::new()));
                                if let Some(s) = new.as_str() {
                                    if !combined.is_empty() { combined.push('\n'); }
                                    combined.push_str(s);
                                }
                                let mut eo = serde_json::Map::new();
                                eo.insert("old_string".to_string(), old);
                                eo.insert("new_string".to_string(), new);
                                edits_arr.push(serde_json::Value::Object(eo));
                            }
                        }
                        if !combined.is_empty() {
                            tool_input.insert("content".to_string(), serde_json::Value::String(combined));
                        }
                        if !edits_arr.is_empty() {
                            tool_input.insert("edits".to_string(), serde_json::Value::Array(edits_arr));
                        }
                    }
                }
                _ => { tool_input.insert(key.clone(), value.clone()); }
            }
        }
    }

    let mut result = serde_json::Map::new();
    result.insert("toolName".to_string(), serde_json::Value::String(name.to_string()));
    result.insert("toolInput".to_string(), serde_json::Value::Object(tool_input));

    IS_ANTIGRAVITY.with(|f| *f.borrow_mut() = true);

    serde_json::to_string(&serde_json::Value::Object(result)).ok()
}

fn write_session_event(tool_type: &str, target: &str, blocked: bool, risk_level: u8) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let line = format!(
        "{{\"ts\":{},\"tool\":\"{}\",\"target\":\"{}\",\"blocked\":{},\"risk\":{}}}",
        ts, tool_type,
        target.replace('\\', "\\\\").replace('"', "\\\""),
        blocked, risk_level,
    );
    // Derive reliable path from current_exe: .nemesis/target/release/bin → .nemesis/logs/
    let exe_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf())) // release/
        .and_then(|p| p.parent().map(|d| d.to_path_buf())) // target/
        .and_then(|p| p.parent().map(|d| d.to_path_buf())) // .nemesis/
        .map(|nemesis| nemesis.join("logs/session-events.jsonl"));

    let fallback_paths: &[std::path::PathBuf] = &[
        std::path::PathBuf::from(".nemesis/logs/session-events.jsonl"),
        std::env::current_dir()
            .unwrap_or_default()
            .join(".nemesis/logs/session-events.jsonl"),
    ];

    let all_paths: Vec<&std::path::PathBuf> = exe_path.iter()
        .chain(fallback_paths.iter())
        .collect();

    for p in all_paths {
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
            let _ = writeln!(file, "{}", line);
            return;
        }
    }
}

// ============================================================
// FUNCOES DE LOG E BLOQUEIO
// ============================================================

fn nemesis_log(level: &str, message: &str) {
    eprintln!("[NEMESIS ENFORCEMENT | {}] {}", level, message);
}

fn nemesis_block(reason: &str, instruction: Option<&str>) -> ! {
    // Antigravity: emitir JSON de decisao no stdout antes de sair
    IS_ANTIGRAVITY.with(|f| {
        if *f.borrow() {
            let deny_json = format!(
                "{{\"decision\":\"deny\",\"reason\":\"{}\"}}",
                reason.replace('\\', "\\\\").replace('"', "\\\"")
            );
            let _ = io::stdout().write_all(deny_json.as_bytes());
            let _ = io::stdout().write_all(b"\n");
            let _ = io::stdout().flush();
        }
    });
    eprintln!("{}", reason);
    if let Some(instr) = instruction {
        eprintln!("→ {}", instr);
    }
    CURRENT_TOOL.with(|c| {
        let (tool_type, target) = &*c.borrow();
        if !tool_type.is_empty() {
            write_session_event(tool_type, target, true, 2);
        }
    });
    std::process::exit(2);
}

// ============================================================
// ESTRUTURAS DE DADOS
// ============================================================

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct PermissionState {
    state: String,
    #[serde(rename = "workflowName")]
    workflow_name: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct DenyList {
    layers: Option<HashMap<String, DenyLayer>>,
}

#[derive(Debug, serde::Deserialize)]
struct DenyLayer {
    patterns: Vec<DenyPattern>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct DenyPattern {
    enabled: Option<bool>,
    #[serde(rename = "type")]
    pattern_type: String,
    pattern: String,
    message: String,
    suggestion: Option<String>,
    rule: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct DevinInput {
    #[serde(rename = "toolName")]
    tool_name: Option<String>,
    #[serde(rename = "tool_name")]
    tool_name_alt: Option<String>,
    #[serde(rename = "toolInput")]
    tool_input: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "tool_input")]
    tool_input_alt: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct NemesisInput {
    #[serde(rename = "agent_action_name")]
    agent_action_name: String,
    #[serde(rename = "tool_info")]
    tool_info: HashMap<String, serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
struct DenylistFolderFiles {
    absolute_block: AbsoluteBlock,
    write_block: WriteBlock,
}

#[derive(Debug, serde::Deserialize)]
struct AbsoluteBlock {
    paths: Vec<String>,
    allowed_exceptions: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct WriteBlock {
    files: Vec<String>,
}

// ============================================================
// FUNCOES UTILITARIAS
// ============================================================

fn read_state_field(state_path: &Path, field: &str) -> String {
    if !state_path.exists() {
        return "unknown".to_string();
    }

    match fs::read_to_string(state_path) {
        Ok(content) => {
            match serde_json::from_str::<PermissionState>(&content) {
                Ok(state) => match field {
                    "state" => state.state,
                    "workflowName" => state.workflow_name.unwrap_or_else(|| "unknown".to_string()),
                    _ => "unknown".to_string(),
                },
                Err(_) => "unknown".to_string(),
            }
        }
        Err(_) => "unknown".to_string(),
    }
}

fn translate_devin_to_nemesis(input_json: &str) -> Result<String, String> {
    if input_json.contains("\"agent_action_name\"") {
        return Ok(input_json.to_string());
    }

    if !input_json.contains("\"toolName\"") && !input_json.contains("\"tool_name\"") {
        nemesis_log("WARNING", "Formato JSON nao reconhecido");
        return Ok(input_json.to_string());
    }

    let parsed: DevinInput = match serde_json::from_str(input_json) {
        Ok(p) => p,
        Err(e) => {
            nemesis_log("WARNING", &format!("Erro ao parsear JSON: {}", e));
            return Ok(input_json.to_string());
        }
    };

    let tool_name = parsed.tool_name.as_ref()
        .or(parsed.tool_name_alt.as_ref())
        .map(|s| s.as_str())
        .unwrap_or("");

    let agent_action = match tool_name {
        // Devin
        "Edit" | "Write" | "MultiEdit" | "EditNotebook" => "pre_write_code",
        "Bash" => "pre_run_command",
        "Read" | "Grep" => "pre_read_code",
        // Claude Code
        "bash" => "pre_run_command",
        "str_replace_based_edit_tool" | "edit_file" | "str_replace" => "pre_write_code",
        "create_file" | "write_file" => "pre_write_code",
        "read_file" | "view" => "pre_read_code",
        // Codex
        "apply_patch" => "pre_write_code",
        "read" | "file_read" => "pre_read_code",
        "edit" | "file_edit" => "pre_write_code",
        "write" | "file_write" => "pre_write_code",
        "bash_command" | "shell" => "pre_run_command",
        // Cursor
        "Shell" => "pre_run_command",
        "StrReplace" => "pre_write_code",
        "Glob" => "pre_read_code",
        "Grep" => "pre_read_code",
        "Delete" => "pre_write_code",
        "EditNotebook" => "pre_write_code",
        "SemanticSearch" => "pre_read_code",
        "Task" => "pre_run_command",
        "TabRead" => "pre_read_code",
        "TabWrite" => "pre_write_code",
        "WebFetch" => "pre_read_code",
        "WebSearch" => "pre_read_code",
        // Antigravity
        "run_command" | "send_command_input" | "browser_subagent" => "pre_run_command",
        "write_to_file" | "replace_file_content" | "multi_replace_file_content" | "generate_image" => "pre_write_code",
        "view_file" | "list_dir" | "grep_search" | "search_web" | "read_url_content"
        | "command_status" | "find_by_name" => "pre_read_code",
        // Claude Code MCP tools
        s if s.starts_with("mcp__") => "pre_mcp_tool_use",
        _ => "pre_write_code",
    };

    let tool_input = parsed.tool_input.or(parsed.tool_input_alt).unwrap_or_default();
    let mut nemesis_data = NemesisInput {
        agent_action_name: agent_action.to_string(),
        tool_info: HashMap::new(),
    };

    if let Some(cmd) = tool_input.get("command")
        .or_else(|| tool_input.get("commandLine"))
        .or_else(|| tool_input.get("command_line"))
    {
        nemesis_data.tool_info.insert("command_line".to_string(), cmd.clone());
    }
    if let Some(path) = tool_input.get("file_path")
        .or_else(|| tool_input.get("filePath"))
    {
        nemesis_data.tool_info.insert("file_path".to_string(), path.clone());
    }
    if let Some(path) = tool_input.get("path") {
        nemesis_data.tool_info.insert("file_path".to_string(), path.clone());
    }
    if let Some(content) = tool_input.get("content")
        .or_else(|| tool_input.get("fileContent"))
        .or_else(|| tool_input.get("newContent"))
        .or_else(|| tool_input.get("text"))
        .or_else(|| tool_input.get("fileText"))
    {
        nemesis_data.tool_info.insert("CodeContent".to_string(), content.clone());
    }
    if let Some(edits) = tool_input.get("edits") {
        nemesis_data.tool_info.insert("edits".to_string(), edits.clone());
    }
    if tool_input.contains_key("old_string") || tool_input.contains_key("new_string")
        || tool_input.contains_key("oldString") || tool_input.contains_key("newString")
        || tool_input.contains_key("old_str") || tool_input.contains_key("new_str")
    {
        let mut edit_obj = serde_json::Map::new();
        if let Some(old) = tool_input.get("old_string")
            .or_else(|| tool_input.get("oldString"))
            .or_else(|| tool_input.get("old_str"))
        {
            edit_obj.insert("old_string".to_string(), old.clone());
        }
        if let Some(new) = tool_input.get("new_string")
            .or_else(|| tool_input.get("newString"))
            .or_else(|| tool_input.get("new_str"))
        {
            edit_obj.insert("new_string".to_string(), new.clone());
        }
        let edits_array = serde_json::Value::Array(vec![serde_json::Value::Object(edit_obj)]);
        nemesis_data.tool_info.insert("edits".to_string(), edits_array);
    }

    for (key, value) in tool_input {
        if !nemesis_data.tool_info.contains_key(&key) {
            nemesis_data.tool_info.insert(key, value);
        }
    }

    serde_json::to_string(&nemesis_data).map_err(|e| e.to_string())
}

fn check_deny_list(deny_list_path: &Path, command: &str) -> Option<(String, String)> {
    if !deny_list_path.exists() {
        return None;
    }

    let content = match fs::read_to_string(deny_list_path) {
        Ok(c) => c,
        Err(_) => return None,
    };

    let deny_list: DenyList = match serde_json::from_str(&content) {
        Ok(d) => d,
        Err(_) => return None,
    };

    if let Some(layers) = deny_list.layers {
        if let Some(commands_layer) = layers.get("commands") {
            for pattern in &commands_layer.patterns {
                if pattern.enabled == Some(false) {
                    continue;
                }
                if pattern.pattern_type != "regex" {
                    continue;
                }

                if let Ok(regex) = Regex::new(&pattern.pattern) {
                    if regex.is_match(command) {
                        return Some((pattern.message.clone(), pattern.suggestion.clone().unwrap_or_default()));
                    }
                }
            }
        }
    }

    None
}

/// Retorna todos os arquivos .json em um diretório (ordenados por nome para determinismo).
fn get_all_json_files(dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths
}

/// Valida o conteúdo de código contra TODAS as deny-lists da pasta config.
/// Itera TODAS as layers (exceto "commands" que é para bash) e todos os patterns regex.
/// Retorna o primeiro hit encontrado.
fn check_content_all_deny_lists(file_path: &str, content: &str, config_dir: &Path) -> Option<DenyPattern> {
    let deny_list_paths = get_all_json_files(config_dir);

    for path in deny_list_paths {
        let file_content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let deny_list: DenyList = match serde_json::from_str(&file_content) {
            Ok(d) => d,
            Err(_) => continue,
        };

        if let Some(layers) = deny_list.layers {
            for (layer_name, layer) in layers {
                // Layer "commands" é exclusiva para validação de comandos bash
                if layer_name == "commands" {
                    continue;
                }
                for pattern in &layer.patterns {
                    if pattern.enabled == Some(false) {
                        continue;
                    }
                    if pattern.pattern_type != "regex" {
                        continue;
                    }
                    if let Ok(re) = Regex::new(&pattern.pattern) {
                        if re.is_match(content) {
                            return Some(pattern.clone());
                        }
                    }
                }
            }
        }
    }

    None
}

/// Carrega a lista canônica de comandos bloqueados do eBPF (commands.toml).
/// Usa regex simples para evitar dependência extra de crate toml.
/// Isto garante auto-sync: qualquer comando adicionado ao commands.toml
/// é automaticamente bloqueado no pretool hook sem ação manual.
fn load_ebpf_blocked_commands(commands_toml_path: &Path) -> Vec<String> {
    let content = match fs::read_to_string(commands_toml_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // Extrai o array blocked_commands = ["rm", "shred", ...]
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

/// Extrai TODOS os segmentos de um comando composto.
/// Decompõe pipes, semicolons, &&, ||, bash -c, sh -c, $(...), `...`,
/// e normaliza path absoluto para basename.
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

fn extract_redirect_content(command: &str) -> Option<(String, String)> {
    let heredoc_regex = Regex::new(
        r"[>]{1,2}\s*([^\s<&;|\n]+\.(?:ts|tsx))"
    ).unwrap();

    let heredoc_content_regex = Regex::new(
        r#"<<\s*['"]?(\w+)['"]?\s*\n(.*?)\n\1\s*$"#
    ).unwrap();

    let target_file = heredoc_regex.captures(command)?[1].trim().to_string();

    let content = if let Some(caps) = heredoc_content_regex.captures(command) {
        caps[2].to_string()
    } else {
        let echo_sq = Regex::new(r"echo\s+'(.*?)'\s*[>]{1,2}").unwrap();
        let echo_dq = Regex::new(r#"echo\s+"(.*?)"\s*[>]{1,2}"#).unwrap();

        if let Some(caps) = echo_sq.captures(command) {
            caps[1].to_string()
        } else if let Some(caps) = echo_dq.captures(command) {
            caps[1].to_string()
        } else {
            let printf_sq = Regex::new(r"printf\s+'(.*?)'\s*[>]{1,2}").unwrap();
            let printf_dq = Regex::new(r#"printf\s+"(.*?)"\s*[>]{1,2}"#).unwrap();

            if let Some(caps) = printf_sq.captures(command) {
                caps[1].to_string()
            } else if let Some(caps) = printf_dq.captures(command) {
                caps[1].to_string()
            } else {
                return None;
            }
        }
    };

    Some((target_file, content))
}

fn validate_redirect_content(command: &str) -> Option<String> {
    let redirect_regex = Regex::new(r"(?:cat|tee|echo|printf)[^|]*[>]{1,2}\s*[^\s]+\.(ts|tsx)").unwrap();
    if !redirect_regex.is_match(command) {
        return None;
    }

    let (target_file, content) = match extract_redirect_content(command) {
        Some(t) => t,
        None => return None,
    };

    let module_exports_regex = Regex::new(r"module\.(exports|[a-zA-Z_][a-zA-Z0-9_]*)\s*=").unwrap();
    if module_exports_regex.is_match(&content) {
        return Some("module-exports".to_string());
    }

    None
}

fn validate_critical_files(command: &str) -> Option<String> {
    let critical_file_patterns = [
        (r"(?:cat|tee)\s*>\s*(tsconfig\.json|package\.json|\.eslintrc|next\.config|tailwind\.config|postcss\.config|\.env)", "Arquivo de configuracao critico protegido"),
        (r"echo\s+.+>\s*(tsconfig\.json|package\.json)", "Arquivo de configuracao critico protegido"),
    ];

    for (pattern, message) in &critical_file_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(command) {
                return Some(message.to_string());
            }
        }
    }

    let strict_disable_regex = Regex::new(r#""strict"\s*:\s*false|"noImplicitAny"\s*:\s*false"#).unwrap();
    if strict_disable_regex.is_match(command) {
        return Some("Desabilitacao de TypeScript strict mode bloqueada".to_string());
    }

    None
}

fn load_denylist_folder_files(project_root: &Path) -> Option<DenylistFolderFiles> {
    let path = project_root
        .join(".nemesis/workflow-enforcement/config/denylist-folder-files.json");
    let content = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Exceção allowlist: path relativo canônico deve estar DENTRO da zona (ex: src/),
/// nunca substring no path bruto (fecha bypass src/../.cursor/...).
fn path_matches_allowed_exception(rel_path: &str, exception: &str) -> bool {
    let exc = exception.trim().trim_matches('/').to_lowercase();
    if exc.is_empty() {
        return false;
    }
    let rel = rel_path.trim_start_matches("./").to_lowercase();
    rel == exc || rel.starts_with(&format!("{}/", exc))
}

fn normalize_to_relative(file_path: &str) -> String {
    let path = file_path.replace('\\', "/");

    // Resolve ".." e "." ANTES de qualquer validação (fecha path traversal).
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

    // Paths absolutos perdem a barra inicial após split/join — remover prefixo do cwd.
    if let Ok(cwd) = std::env::current_dir() {
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

    trim_leading_dot_slash(&components.join("/"))
}

fn trim_leading_dot_slash(path: &str) -> String {
    if path.starts_with("./") {
        path[2..].to_string()
    } else {
        path.to_string()
    }
}

fn check_folder_file_access(
    denylist: &DenylistFolderFiles,
    path: &str,
    is_write: bool,
) -> Option<(String, String)> {
    let rel_path = normalize_to_relative(path);

    // 1. Verificar absolute_block
    for blocked in &denylist.absolute_block.paths {
        if rel_path.starts_with(blocked) || rel_path == blocked.trim_end_matches('/') {
            // Verificar exceptions
            let is_exception = denylist.absolute_block.allowed_exceptions
                .iter()
                .any(|exc| path_matches_allowed_exception(&rel_path, exc));

            if !is_exception {
                return Some((
                    format!("NEMESIS SEC - {} - ARQUIVO PROTEGIDO · {}", if is_write { "ACESSO NEGADO" } else { "LEITURA NEGADA" }, rel_path),
                    "Arquivos protegidos sao gerenciados exclusivamente pelo usuario.".into(),
                ));
            }
        }
    }

    // 2. Verificar write_block (somente se e operacao de escrita)
    if is_write {
        for blocked in &denylist.write_block.files {
            if rel_path.ends_with(blocked) || rel_path == *blocked {
                return Some((
                    format!("NEMESIS SEC - ACESSO NEGADO - ARQUIVO PROTEGIDO · {}", rel_path),
                    "Arquivos de configuracao do projeto sao gerenciados exclusivamente pelo usuario.".into(),
                ));
            }
        }
    }

    None
}

// ============================================================
// MAIN
// ============================================================

fn main() {
    // Wrapper fail-closed: qualquer panic ou erro → exit(2)
    match std::panic::catch_unwind(|| {
        run_pretool()
    }) {
        Ok(()) => {} // exited normally via process::exit
        Err(panic) => {
            let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            eprintln!("[NEMESIS ERROR] Hook panic: {}", msg);
            std::process::exit(2);
        }
    }
}

fn run_pretool() {
    // ── Nemesis Defender: garantir daemon ativo (fire-and-forget) ──
    {
        let defender = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| std::path::PathBuf::from(".nemesis/target/release"))
            .join("nemesis-defender");

        if defender.exists() {
            let _ = std::process::Command::new(&defender)
                .arg("--ensure-daemon")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            // Fire-and-forget: pretool não espera, continua imediatamente
        }
    }

    let path_export = "/Users/fernandomoreira/.nvm/versions/node/v25.6.1/bin:/Users/fernandomoreira/.bun/bin";
    let current_path = env::var("PATH").unwrap_or_default();
    env::set_var("PATH", format!("{}:{}", path_export, current_path));

    let exe_path = env::current_exe().expect("Falha ao obter path do executavel");
    let script_dir = exe_path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
    let project_dir = script_dir.parent().and_then(|p| p.parent()).and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| script_dir.clone());

    // ── Nemesis eBPF: garantir daemon BPF LSM ativo (fire-and-forget, apenas Linux) ──
    #[cfg(target_os = "linux")]
    {
        // Verificar se kernel suporta BPF LSM
        let lsm_ok = std::fs::read_to_string("/sys/kernel/security/lsm")
            .map(|s| s.contains("bpf"))
            .unwrap_or(false);

        if lsm_ok {
            let ebpf_daemon = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()))
                .unwrap_or_else(|| std::path::PathBuf::from(".nemesis/target/release"))
                .join("nemesis-ebpf-daemon");

            // Fallback: procurar em .nemesis/target/release/ se o path derivado do current_exe nao existir
            let ebpf_daemon = if ebpf_daemon.exists() {
                ebpf_daemon
            } else {
                project_dir
                    .join(".nemesis")
                    .join("target")
                    .join("release")
                    .join("nemesis-ebpf-daemon")
            };

            if ebpf_daemon.exists() {
                let _ = std::process::Command::new(&ebpf_daemon)
                    .arg("--ensure-daemon")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
                // Fire-and-forget: pretool não espera, continua imediatamente
            }
        }
    }

    let permission_state_file = project_dir.join(".nemesis").join("runtime").join("permission-gate.state.json");

    let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string();

    let deny_list_path = project_dir.join(".nemesis").join("workflow-enforcement").join("config").join("deny-list.json");

    // ============================================================
    // DETECAO DE IDE
    // ============================================================
    let mut ide_type = "devin".to_string();

    if env::var("CLAUDE_PROJECT_DIR").is_ok() || env::var("CLAUDE_CODE").is_ok() {
        ide_type = "claude_code".to_string();
    } else if env::var("VSCODE_AGENT_HOST").is_ok() || env::var("GITHUB_COPILOT_HOOK").is_ok() {
        ide_type = "vscode_copilot".to_string();
    } else if env::var("CURSOR_USER_DATA_DIR").is_ok() || env::var("CURSOR_TRACE").is_ok() {
        ide_type = "cursor".to_string();
    }


    // ============================================================
    // VERIFICACAO 1: Permission gate
    // ============================================================
    if permission_state_file.exists() {
        let metadata = fs::metadata(&permission_state_file).ok();
        let file_size = metadata.map(|m| m.len()).unwrap_or(0);

        let (gate_state, gate_workflow) = if file_size > 4096 {
            nemesis_log("WARNING", "State file suspeito. Ignorando — gate assume IDLE.");
            ("idle".to_string(), "unknown".to_string())
        } else {
            (
                read_state_field(&permission_state_file, "state"),
                read_state_field(&permission_state_file, "workflowName")
            )
        };


        if gate_state == "awaiting" {
            nemesis_block(
                &format!("Permission gate AWAITING — workflow '{}' aguarda confirmacao explicita", gate_workflow),
                Some("Responda com: sim | yes | pode | prossiga | confirmo | autorizo")
            );
        }

        if gate_state == "denied" {
            nemesis_block(
                &format!("Permission DENIED — workflow '{}' foi negado", gate_workflow),
                Some("Execute um novo workflow e aguarde aprovacao explicita do usuario")
            );
        }

        if gate_state == "granted" {
            // Permission granted
        }

        if gate_state == "idle" || gate_state == "unknown" {
            // Permission idle
        }
    } else {
        // Permission gate state file not found
    }

    // ============================================================
    // Capturar stdin e aplicar traducao
    // ============================================================
    let mut stdin_peek = String::new();

    let mut buffer = vec![0u8; 131072];
    if let Ok(n) = io::stdin().read(&mut buffer) {
        stdin_peek = String::from_utf8_lossy(&buffer[..n]).to_string();
    }

    // ── Antigravity: normalizar payload toolCall → toolName/toolInput ──
    if stdin_peek.contains("\"toolCall\"") {
        if let Some(normalized) = normalize_antigravity_input(&stdin_peek) {
            stdin_peek = normalized;
        }
    }

    // ── Extrair tool context ANTES da tradução — JSON original tem tool_name/tool_input ──
    // Também captura conteúdo de Write antes da tradução para scan inline.
    let mut write_scan_data: Option<(String, String)> = None;

    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdin_peek) {
        let raw_tool = val.get("tool_name")
            .or_else(|| val.get("toolName"))
            .or_else(|| val.get("tool"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let tool_input_val = val.get("tool_input")
            .or_else(|| val.get("toolInput"));
        let target = tool_input_val
            .and_then(|ti| ti.get("file_path").or_else(|| ti.get("filePath")))
            .or_else(|| tool_input_val.and_then(|ti| ti.get("path")))
            .or_else(|| tool_input_val.and_then(|ti| ti.get("command").or_else(|| ti.get("commandLine"))))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let tool_type = map_tool_type(raw_tool).to_string();
        CURRENT_TOOL.with(|c| *c.borrow_mut() = (tool_type, target));

        // Capturar conteúdo de Write/Edit ANTES da tradução
        let is_write_op = matches!(raw_tool,
            "Write" | "write" | "write_file" | "create_file" |
            "Edit" | "edit" | "edit_file" | "str_replace" |
            "MultiEdit" | "str_replace_based_edit_tool" | "apply_patch" |
            "str_replace_editor" | "StrReplace" | "TabWrite" |
            // Antigravity
            "write_to_file" | "replace_file_content" | "multi_replace_file_content"
        );
        if is_write_op {
            if let Some(input) = val.get("tool_input")
                .or_else(|| val.get("toolInput"))
                .and_then(|v| v.as_object()) {
                let fpath = input.get("file_path")
                    .or_else(|| input.get("path"))
                    .or_else(|| input.get("filePath"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let content = input.get("content")
                    .or_else(|| input.get("fileContent"))
                    .or_else(|| input.get("newContent"))
                    .or_else(|| input.get("text"))
                    .or_else(|| input.get("fileText"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                // Edit ops: conteúdo pode estar em new_string/newString/new_str
                let content = if content.is_empty() {
                    input.get("new_string")
                        .or_else(|| input.get("newString"))
                        .or_else(|| input.get("new_str"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                } else {
                    content
                };
                if !content.is_empty() {
                    write_scan_data = Some((fpath, content.to_string()));
                }
            }
        }
    }

    // ── BLOQUEIO GLOBAL: Delete tool (ANTES da tradução) ──
    // Política: NENHUM agente IA pode deletar arquivos. Exclusivo humano.
    // Deve rodar ANTES de translate_devin_to_nemesis() porque
    // a tradução converte "Delete" → "pre_write_code", mascarando a tool.
    if let Ok(raw_val) = serde_json::from_str::<serde_json::Value>(&stdin_peek) {
        let raw_tool = raw_val.get("tool_name")
            .or_else(|| raw_val.get("toolName"))
            .or_else(|| raw_val.get("tool"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if raw_tool == "Delete" || raw_tool == "delete" {
            nemesis_block(
                "Exclusao de arquivos bloqueada para agentes de IA. Apenas o usuario humano pode remover arquivos.",
                Some("Use o terminal local para remover arquivos. Agentes IA nao tem permissao para operacoes destrutivas de exclusao.")
            );
        }
    }

    if !stdin_peek.is_empty() {
        let preview = &stdin_peek[..stdin_peek.len().min(100)];

        match translate_devin_to_nemesis(&stdin_peek) {
            Ok(translated) => {
                if translated != stdin_peek {
                    stdin_peek = translated;
                }
            }
            Err(_) => {}
        }
    }

    // ============================================================
    // AUTO-DEFESA: Bloquear acesso a .nemesis/ (protecao do framework)
    // ============================================================
    // Bloqueia Read/Write/Edit/Bash em paths protegidos do .nemesis/
    // para evitar que o agente LLM leia ou modifique o proprio Nemesis.
    {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdin_peek) {
            let tool_name = val.get("tool_name")
                .or_else(|| val.get("toolName"))
                .or_else(|| val.get("tool"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Resolver tool type a partir de agent_action_name (formato Nemesis traduzido)
            let agent_action = val.get("agent_action_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let effective_tool = if tool_name.is_empty() {
                match agent_action {
                    "pre_read_code" | "post_read_code" => "Read",
                    "pre_write_code" | "post_write_code" => "Write",
                    "pre_run_command" | "post_run_command" => "Bash",
                    "pre_mcp_tool_use" | "post_mcp_tool_use" => "MCP",
                    _ => ""
                }
            } else {
                tool_name
            };

            // Extrair path de varios formatos de stdin
            // Suporta formato Devin/Codex (tool_input) e formato Nemesis (tool_info)
            let tool_input_val = val.get("tool_input")
                .or_else(|| val.get("toolInput"))
                .or_else(|| val.get("tool_info"));
            let path = tool_input_val
                .and_then(|ti| ti.get("file_path").or_else(|| ti.get("filePath")))
                .or_else(|| tool_input_val.and_then(|ti| ti.get("path")))
                .or_else(|| tool_input_val.and_then(|ti| ti.get("search_path")))
                .or_else(|| tool_input_val.and_then(|ti| ti.get("query")))
                .or_else(|| tool_input_val.and_then(|ti| ti.get("target_directory")))
                .or_else(|| tool_input_val.and_then(|ti| ti.get("pattern")))     // Cursor Glob/Grep: pattern contém path
                .or_else(|| val.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // Se o path veio de um pattern Glob (ex: ".nemesis/**/*"), extrair diretório base
            let path = if path.contains("**") || (path.contains('*') && !path.contains('/')) {
                // Extrai o diretório antes do primeiro ** ou *
                if let Some(idx) = path.find("**") {
                    path[..idx].trim_end_matches('/').to_string()
                } else if let Some(idx) = path.find('*') {
                    path[..idx].trim_end_matches('/').to_string()
                } else {
                    path
                }
            } else {
                path
            };
            // Cursor Glob/Grep: extrair includes e pattern como paths adicionais
            let mut glob_paths: Vec<String> = Vec::new();
            if let Some(includes) = tool_input_val.and_then(|ti| ti.get("includes")).and_then(|v| v.as_array()) {
                for item in includes {
                    if let Some(s) = item.as_str() {
                        glob_paths.push(s.to_string());
                    }
                }
            }
            // Extrair pattern como path adicional (Glob/Grep com pattern bruto)
            if let Some(pattern) = tool_input_val.and_then(|ti| ti.get("pattern")).and_then(|v| v.as_str()) {
                if !pattern.is_empty() && pattern != "**/*" && pattern != "*" {
                    // Extrai diretório base do pattern
                    let base = if let Some(idx) = pattern.find("**") {
                        pattern[..idx].trim_end_matches('/').to_string()
                    } else if let Some(idx) = pattern.find('*') {
                        pattern[..idx].trim_end_matches('/').to_string()
                    } else {
                        pattern.to_string()
                    };
                    if !base.is_empty() && base != "." && base != ".." {
                        glob_paths.push(base);
                    }
                }
            }

            // Tambem verificar command_line para Bash envolvendo .nemesis/
            let bash_path = val.get("tool_info")
                .and_then(|ti| ti.get("command_line"))
                .or_else(|| val.get("tool_input")
                    .and_then(|ti| ti.get("command")))
                .or_else(|| val.get("toolInput")
                    .and_then(|ti| ti.get("command")))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let combined_path = format!("{} {}", path, bash_path);

            // DENYLIST: Verificar denylist-folder-files.json para todos os paths
            if !path.is_empty() {
                if let Some(ref dl) = load_denylist_folder_files(&project_dir) {
                    let is_write = matches!(effective_tool,
                        "Write" | "Edit" | "MultiEdit" | "create_file" | "str_replace_editor"
                        | "write_file" | "edit_file" | "str_replace" | "apply_patch"
                        | "str_replace_based_edit_tool" | "StrReplace" | "TabWrite"
                    );
                    // Bash com redirect tambem conta como write
                    let is_bash_write = (effective_tool == "Bash" || effective_tool == "bash")
                        && (bash_path.contains('>') || combined_path.contains('>'));
                    if let Some((message, suggestion)) = check_folder_file_access(dl, &path, is_write || is_bash_write) {
                        nemesis_block(&message, Some(&suggestion));
                    }
                }
                // Verificar glob_paths (Cursor Glob/Grep includes)
                for gp in &glob_paths {
                    if let Some(ref dl) = load_denylist_folder_files(&project_dir) {
                        if let Some((message, suggestion)) = check_folder_file_access(dl, gp, false) {
                            nemesis_block(&message, Some(&suggestion));
                        }
                    }
                }
            }

            // DENYLIST-DRIVEN: Extrair paths de comandos Bash + file_path
            // Verificar TODOS os paths contra denylist-folder-files.json
            // Regra: allowed_exceptions (full access) > absolute_block (block all) > write_block (block write)
            {
                let mut all_paths: Vec<String> = Vec::new();

                if !path.is_empty() {
                    all_paths.push(path.clone());
                }

                // Paths extraidos do comando Bash (generico — qualquer comando)
                if !bash_path.is_empty() {
                    // Captura paths absolutos, relativos e dot-prefixed de qualquer comando
                    let path_re = regex::Regex::new(
                        r#"(?:^|\s)(['"]?)((?:/[^\s;|&'">]+|\.\.?/[^\s;|&'">]+|\.[a-zA-Z0-9][^\s;|&'">]*))['"]?"#
                    ).unwrap();

                    for cap in path_re.captures_iter(&bash_path) {
                        let raw = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                        if !raw.is_empty() && raw != "." && raw != ".."
                            && raw != "./" && raw != "../"
                        {
                            let resolved = if raw.starts_with('/') {
                                raw.to_string()
                            } else {
                                project_dir.join(raw).to_string_lossy().to_string()
                            };
                            all_paths.push(resolved);
                        }
                    }
                }

                // Adicionar glob_paths (Cursor Glob/Grep includes)
                for gp in &glob_paths {
                    if !gp.is_empty() {
                        let resolved = if gp.starts_with('/') {
                            gp.clone()
                        } else {
                            project_dir.join(gp).to_string_lossy().to_string()
                        };
                        all_paths.push(resolved);
                    }
                }

                // Wildcard/glob detection: check parent directories against deny list
                if !all_paths.is_empty() {
                    if let Some(ref dl) = load_denylist_folder_files(&project_dir) {
                        for p in &all_paths {
                            if p.contains('*') || p.contains('?') {
                                // Extract parent directory from wildcard path
                                let parent = if let Some(idx) = p.rfind('/') {
                                    &p[..idx + 1]  // include trailing slash
                                } else {
                                    continue;
                                };

                                if parent.is_empty() || parent == "./" || parent == "../" {
                                    continue;
                                }

                                // Check if ANY blocked path falls within this parent directory
                                let is_parent_blocked = dl.absolute_block.paths.iter()
                                    .any(|blocked| blocked.starts_with(parent)
                                        || parent.contains(blocked));
                                let is_parent_write_blocked = dl.write_block.files.iter()
                                    .any(|f| {
                                        let full = format!("{}{}", parent, f);
                                        dl.absolute_block.paths.iter().any(|b| full.contains(b))
                                            || f.starts_with(parent)
                                    });

                                if is_parent_blocked || is_parent_write_blocked {
                                    nemesis_block(
                                        &format!("NEMESIS SEC - ESCRITA FORA DO ESCOPO PERMITIDO · {}", p),
                                        Some("Não use wildcards (*, ?) para acessar diretórios protegidos. Especifique arquivos individualmente com caminho explícito.")
                                    );
                                }
                            }
                        }
                    }
                }

                if !all_paths.is_empty() {
                    if let Some(ref dl) = load_denylist_folder_files(&project_dir) {
                        let is_write = matches!(effective_tool,
                            "Write" | "Edit" | "MultiEdit" | "create_file" | "str_replace_editor"
                            | "write_file" | "edit_file" | "str_replace" | "apply_patch"
                            | "str_replace_based_edit_tool" | "StrReplace" | "TabWrite"
                        );
                        let is_bash_write = (effective_tool == "Bash" || effective_tool == "bash")
                            && (bash_path.contains('>') || combined_path.contains('>'));
                        let is_write_op = is_write || is_bash_write;

                        for p in &all_paths {
                            // Path canônico + denylist (fecha traversal src/../.cursor/...)
                            if let Some((message, suggestion)) =
                                check_folder_file_access(dl, p, is_write_op)
                            {
                                nemesis_block(&message, Some(&suggestion));
                            }
                        }
                    }
                }
            }
        }
    }

    // Extrair comando bash do JSON
    let bash_command = if stdin_peek.contains("\"agent_action_name\"") && stdin_peek.contains("\"pre_run_command\"") {
        let parsed: NemesisInput = serde_json::from_str(&stdin_peek).unwrap_or_else(|_| NemesisInput {
            agent_action_name: "".to_string(),
            tool_info: HashMap::new(),
        });
        parsed.tool_info.get("command_line")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    } else if stdin_peek.contains("\"toolName\"") || stdin_peek.contains("\"tool_name\"") {
        let parsed: DevinInput = serde_json::from_str(&stdin_peek).unwrap_or_else(|_| DevinInput {
            tool_name: None,
            tool_name_alt: None,
            tool_input: None,
            tool_input_alt: None,
        });
        parsed.tool_input.as_ref()
            .or(parsed.tool_input_alt.as_ref())
            .and_then(|m| m.get("command"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    } else {
        String::new()
    };

    // ============================================================
    // VALIDACOES
    // ============================================================
    if !bash_command.is_empty() {
        // ── EXTRAIR TODOS OS SEGMENTOS DO COMANDO UMA ÚNICA VEZ ──
        let all_segments = extract_all_segments(&bash_command);

        // 1. Verificar TODAS as deny-lists de comandos
        {
            let deny_list_paths = [
                project_dir.join(".nemesis").join("workflow-enforcement").join("config").join("deny-list.json"),
                project_dir.join(".nemesis").join("workflow-enforcement").join("config").join("deny-list-base.json"),
                project_dir.join(".nemesis").join("workflow-enforcement").join("config").join("deny-list-generic.json"),
            ];

            for deny_path in &deny_list_paths {
                let deny_content = match fs::read_to_string(deny_path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                if !deny_content.is_empty() {
                    if let Ok(deny_list) = serde_json::from_str::<DenyList>(&deny_content) {
                        if let Some(ref layers) = deny_list.layers {
                            // Layer: commands
                            if let Some(commands_layer) = layers.get("commands") {
                                for segment in &all_segments {
                                    for pattern in &commands_layer.patterns {
                                        if pattern.enabled == Some(false) { continue; }
                                        if pattern.pattern_type != "regex" { continue; }
                                        if let Ok(re) = Regex::new(&pattern.pattern) {
                                            if re.is_match(segment) {
                                                nemesis_block(
                                                    &pattern.message,
                                                    pattern.suggestion.as_deref(),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            // Layer: nemesis_evasion — tentativas de bypass do Nemesis
                            if let Some(evasion_layer) = layers.get("nemesis_evasion") {
                                for segment in &all_segments {
                                    for pattern in &evasion_layer.patterns {
                                        if pattern.enabled == Some(false) { continue; }
                                        if pattern.pattern_type != "regex" { continue; }
                                        if let Ok(re) = Regex::new(&pattern.pattern) {
                                            if re.is_match(segment) {
                                                nemesis_block(
                                                    &pattern.message,
                                                    pattern.suggestion.as_deref(),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Auto-sync com eBPF commands.toml (verificação em todos os segmentos)
        {
            let commands_toml_path = project_dir
                .join(".nemesis")
                .join("ebpf-kernel")
                .join("denylist-ebpf")
                .join("commands.toml");
            let ebpf_commands = load_ebpf_blocked_commands(&commands_toml_path);

            for blocked_cmd in &ebpf_commands {
                let escaped = regex::escape(blocked_cmd);
                let pattern = format!(r"(?:^|\s){}[\s$]|{}$", escaped, escaped);
                if let Ok(re) = Regex::new(&pattern) {
                    for segment in &all_segments {
                        if re.is_match(segment) {
                            nemesis_block(
                                "NEMESIS SEC - COMANDO NAO PERMITIDO",
                                Some("Este comando está na denylist do Nemesis eBPF.")
                            );
                        }
                    }
                }
            }
        }

        // 2b. Defesa em profundidade: Defender analisa o comando completo
        // com decoders, entropy e regex de malware (Mac/Windows: esta é a única
        // barreira além do pretool, já que não há eBPF)
        {
            let defender_result = nemesis_defender::scan_command(&bash_command);
            if defender_result.severity == nemesis_defender::Severity::Malicious {
                let _evidence: Vec<String> = defender_result.violations.iter()
                    .map(|v| format!("[{}] {}", v.visitor, v.message))
                    .collect();
                nemesis_block(
                    "NEMESIS SEC - COMANDO NAO PERMITIDO",
                    Some("Payloads ofuscados ou maliciosos sao bloqueados pelo Domo de Ferro.")
                );
            }
        }

        // 3. Validadores específicos em TODOS os segmentos
        for segment in &all_segments {
            // Redirect TS/TSX
            if let Some(violation) = validate_redirect_content(segment) {
                nemesis_block(
                    "NEMESIS SEC - COMANDO NAO PERMITIDO",
                    Some("Use a edit tool do IDE para escrever arquivos TypeScript")
                );
            }

            // Arquivos criticos
            if let Some(msg) = validate_critical_files(segment) {
                nemesis_block(&msg, Some("Arquivos de configuracao sao protegidos — nao modifique via bash"));
            }

            // NOTA: validate_require, validate_module_exports, validate_import_type,
            // validate_eslint_bypass, validate_mass_update, validate_smart_component,
            // validate_system_level, validate_package_install foram movidos para
            // deny-list.json commands layer (cmd-001, cmd-002, cmd-003, cmd-004,
            // cmd-022, cmd-099, cmd-101, cmd-102, cmd-103) como fonte única de verdade.
        }
    }

    // ============================================================
    // WRITE CONTENT SCANNING — scan inline do payload antes de permitir
    // Usa write_scan_data capturado ANTES da tradução (stdin original).
    // ============================================================
    if let Some((ref file_path_str, ref content_str)) = write_scan_data {
        let path = std::path::Path::new(file_path_str.as_str());
        let scan_result = nemesis_defender::scan_content(path, content_str.as_bytes());

        if scan_result.severity == nemesis_defender::Severity::Malicious {
            let _evidence: Vec<String> = scan_result.violations.iter()
                .map(|v| {
                    let fix = v.suggestion.as_deref()
                        .map(|s| format!(" → FIX: {}", s))
                        .unwrap_or_default();
                    format!("[{}] {} (linha {}:{}){}", v.visitor, v.message, v.line, v.col, fix)
                })
                .collect();
            write_session_event("Write", file_path_str, true, 2);
            nemesis_block(
                "NEMESIS SEC - CONTEUDO MALICIOSO DETECTADO",
                Some("O arquivo contem padroes maliciosos detectados pelo Domo de Ferro. Revise o conteudo.")
            );
        }

        if scan_result.severity == nemesis_defender::Severity::Suspicious {
            let evidence: Vec<String> = scan_result.violations.iter()
                .map(|v| format!("[{}] {}", v.visitor, v.message))
                .collect();
            eprintln!("[NEMESIS WARNING] Conteudo suspeito em {}: {}", file_path_str, evidence.join("; "));
        }

        // ============================================================
        // DENY-LIST QUALITY SCANNING — valida conteudo contra regex de
        // todas as deny-lists em .nemesis/workflow-enforcement/config/
        // ============================================================
        let config_dir = project_dir.join(".nemesis").join("workflow-enforcement").join("config");
        if let Some(quality_hit) = check_content_all_deny_lists(file_path_str, content_str, &config_dir) {
            let rule_msg = quality_hit.rule.as_deref().unwrap_or(".devin/rules/README.md");
            let suggestion = quality_hit.suggestion.as_deref().unwrap_or("Revise o padrao de codigo conforme as convencoes do projeto.");
            write_session_event("Write", file_path_str, true, 1);
            nemesis_block(
                &quality_hit.message,
                Some(suggestion),
            );
        }
    }

    // ============================================================
    // Resolver path do binario Rust nemesis-pretool-hook
    // ============================================================
    let candidate_bins = [
        project_dir.join(".nemesis").join("target").join("release").join("nemesis-pretool-hook"),
        project_dir.join(".nemesis").join("target").join("debug").join("nemesis-pretool-hook"),
    ];
    let hook_bin = candidate_bins.iter().find(|p| p.exists()).cloned();
    let hook_script = match hook_bin {
        Some(bin) => bin,
        None => {
            nemesis_log("BLOCKED", "nemesis-pretool-hook binary not found. Run 'cargo build --release'.");
            std::process::exit(2);
        }
    };

    // ============================================================
    // Reler stdin
    // ============================================================
    let mut input = stdin_peek;

    if input.is_empty() {
        let mut buffer = String::new();
        if io::stdin().read_to_string(&mut buffer).is_ok() {
            input = buffer;
        }
    }

    if input.is_empty() {
        nemesis_block("Input vazio recebido", Some("Verifique a configuracao do hook no IDE"));
    }

    if serde_json::from_str::<serde_json::Value>(&input).is_err() {
        nemesis_block("JSON invalido recebido", Some("Verifique o formato do payload enviado ao hook"));
    }

    // ============================================================
    // Executar binario Rust nemesis-pretool-hook
    // ============================================================

    let output = Command::new(&hook_script)
        .current_dir(&project_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match output {
        Ok(child) => child,
        Err(e) => {
            nemesis_block(
                &format!("Erro ao executar enforcement validator: {}", e),
                Some("Execute 'cargo build --release' em .nemesis/")
            );
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }

    let result = child.wait_with_output();

    match result {
        Ok(output) => {
            let exit_code = output.status.code().unwrap_or(0);
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            let stderr_str = String::from_utf8_lossy(&output.stderr);

            let is_real_violation = exit_code == 2
                || stdout_str.contains("NEMESIS BLOCKED")
                || stderr_str.contains("NEMESIS BLOCKED");

            if is_real_violation {
                eprint!("{}{}", stderr_str, stdout_str);
                std::process::exit(2);
            }

            if exit_code != 0 {
                nemesis_block(
                    &format!("Erro interno do enforcement validator (exit {})", exit_code),
                    Some("Verifique a instalacao do Nemesis — erros nao sao permitidos")
                );
            }
        }
        Err(e) => {
            nemesis_block(
                &format!("Falha ao aguardar resultado do validator: {}", e),
                Some("Verifique a instalacao do Nemesis")
            );
        }
    }

    // ============================================================
    // APROVADO — registrar evento de sessao permitido
    // ============================================================
    CURRENT_TOOL.with(|c| {
        let (tool_type, target) = &*c.borrow();
        if !tool_type.is_empty() {
            write_session_event(tool_type, target, false, 0);
        }
    });
    // Antigravity: emitir JSON de decisao allow no stdout
    IS_ANTIGRAVITY.with(|f| {
        if *f.borrow() {
            let _ = io::stdout().write_all(b"{\"decision\":\"allow\"}\n");
            let _ = io::stdout().flush();
        }
    });
    eprintln!("[NEMESIS OK] Execution permitted.");
}
