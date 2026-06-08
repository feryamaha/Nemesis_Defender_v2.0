use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use nemesis::harvest::nemesis_harvest::run_harvest;

async fn merge_deny_list(
    new_output: serde_json::Value,
    existing_path: &Path,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if !existing_path.exists() {
        return Ok(new_output);
    }

    match fs::read_to_string(existing_path) {
        Ok(content) => {
            let mut merged = new_output.clone();
            
            if let Ok(existing) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(existing_layers) = existing.get("layers").and_then(|l| l.as_object()) {
                    if let Some(merged_layers) = merged.get_mut("layers").and_then(|l| l.as_object_mut()) {
                        for (layer_name, layer) in existing_layers {
                            if let Some(patterns) = layer.get("patterns").and_then(|p| p.as_array()) {
                                let manual_patterns: Vec<_> = patterns
                                    .iter()
                                    .filter(|p| p.get("source").and_then(|s| s.as_str()) == Some("manual"))
                                    .cloned()
                                    .collect();

                                if !manual_patterns.is_empty() {
                                    if let Some(merged_layer) = merged_layers.get_mut(layer_name) {
                                        if let Some(merged_patterns) = merged_layer.get_mut("patterns").and_then(|p| p.as_array_mut()) {
                                            // Remover patterns nao-manuais existentes
                                            merged_patterns.retain(|p| {
                                                p.get("source").and_then(|s| s.as_str()) != Some("manual")
                                            });
                                            // Adicionar patterns manuais
                                            merged_patterns.extend(manual_patterns);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Ok(merged)
        }
        Err(_) => {
            eprintln!("[NEMESIS INSTALL] Aviso: nao foi possivel fazer merge com deny-list existente. Sobrescrevendo.");
            Ok(new_output)
        }
    }
}

fn validate_deny_list(deny_list_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(deny_list_path)?;
    let data: serde_json::Value = serde_json::from_str(&content)?;

    let required_layers = vec![
        "typescript", "react", "css", "nextjs", "api", "security", "workflow", "bypass", "commands", "project",
    ];

    for layer in &required_layers {
        let layers = data.get("layers").and_then(|l| l.as_object());
        if layers.is_none() || !layers.unwrap().contains_key(*layer) {
            return Err(format!("Camada obrigatoria ausente na deny-list: {}", layer).into());
        }
    }

    let mut invalid = 0;
    if let Some(layers) = data.get("layers").and_then(|l| l.as_object()) {
        for (layer_name, layer) in layers {
            if let Some(patterns) = layer.get("patterns").and_then(|p| p.as_array()) {
                for p in patterns {
                    if let Some(pattern_type) = p.get("type").and_then(|t| t.as_str()) {
                        if pattern_type == "regex" {
                            if let Some(pattern_str) = p.get("pattern").and_then(|p| p.as_str()) {
                                if regex::Regex::new(pattern_str).is_err() {
                                    eprintln!("[NEMESIS INSTALL] Regex invalido em {}/{}: {}", layer_name, p.get("id").and_then(|i| i.as_str()).unwrap_or("unknown"), pattern_str);
                                    invalid += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if invalid > 0 {
        eprintln!("[NEMESIS INSTALL] {} regex(es) invalido(s) detectado(s) — desativados no runtime.", invalid);
    }

    Ok(())
}

fn detect_ides() -> Vec<String> {
    let mut detected_ides: Vec<String> = vec![];

    // Claude Code
    if env::var("CLAUDE_PROJECT_DIR").is_ok() || env::var("CLAUDE_CODE").is_ok() {
        detected_ides.push("claude_code".to_string());
    }

    // VS Code / GitHub Copilot
    if env::var("VSCODE_AGENT_HOST").is_ok() || env::var("GITHUB_COPILOT_HOOK").is_ok() {
        detected_ides.push("vscode_copilot".to_string());
    }

    // Cursor
    if env::var("CURSOR_USER_DATA_DIR").is_ok() || env::var("CURSOR_TRACE").is_ok() {
        detected_ides.push("cursor".to_string());
    }

    // Devin (default)
    detected_ides.push("devin".to_string());

    detected_ides
}

fn generate_ide_configs(ides: &[String], project_root: &Path) {
    for ide in ides {
        match ide.as_str() {
            "claude_code" => {
                let claude_dir = project_root.join(".claude");
                if !claude_dir.exists() {
                    fs::create_dir_all(&claude_dir).ok();
                }

                let claude_settings_path = claude_dir.join("settings.json");
                if !claude_settings_path.exists() {
                    let claude_settings = serde_json::json!({
                        "hooks": {
                            "pre_tool_use": [
                                {
                                    "command": format!("bash {}", project_root.join(".nemesis/hooks/nemesis-pretool-check.sh").display()),
                                    "show_output": true,
                                }
                            ]
                        }
                    });
                    fs::write(&claude_settings_path, serde_json::to_string_pretty(&claude_settings).unwrap()).ok();
                    println!("[NEMESIS INSTALL] ✓ Criado .claude/settings.json");
                } else {
                    println!("[NEMESIS INSTALL] → .claude/settings.json ja existe (mantido)");
                }
            }
            "vscode_copilot" => {
                let github_dir = project_root.join(".github/hooks");
                if !github_dir.exists() {
                    fs::create_dir_all(&github_dir).ok();
                }

                let github_hooks_path = github_dir.join("nemesis.json");
                if !github_hooks_path.exists() {
                    let github_hooks = serde_json::json!({
                        "hooks": {
                            "pre_write_code": [{ "command": format!("bash {}", project_root.join(".nemesis/hooks/nemesis-pretool-check.sh").display()), "show_output": true }],
                            "pre_run_command": [{ "command": format!("bash {}", project_root.join(".nemesis/hooks/nemesis-pretool-check.sh").display()), "show_output": true }],
                            "pre_read_code": [{ "command": format!("bash {}", project_root.join(".nemesis/hooks/nemesis-pretool-check.sh").display()), "show_output": true }],
                            "pre_mcp_tool_use": [{ "command": format!("bash {}", project_root.join(".nemesis/hooks/nemesis-pretool-check.sh").display()), "show_output": true }],
                        }
                    });
                    fs::write(&github_hooks_path, serde_json::to_string_pretty(&github_hooks).unwrap()).ok();
                    println!("[NEMESIS INSTALL] ✓ Criado .github/hooks/nemesis.json");
                } else {
                    println!("[NEMESIS INSTALL] → .github/hooks/nemesis.json ja existe (mantido)");
                }
            }
            "cursor" => {
                let cursor_dir = project_root.join(".cursor");
                if !cursor_dir.exists() {
                    fs::create_dir_all(&cursor_dir).ok();
                }

                let cursor_settings_path = cursor_dir.join("settings.json");
                if !cursor_settings_path.exists() {
                    let cursor_settings = serde_json::json!({
                        "hooks": {
                            "pre_tool_use": [{ "command": format!("bash {}", project_root.join(".nemesis/hooks/nemesis-pretool-check.sh").display()), "show_output": true }]
                        }
                    });
                    fs::write(&cursor_settings_path, serde_json::to_string_pretty(&cursor_settings).unwrap()).ok();
                    println!("[NEMESIS INSTALL] ✓ Criado .cursor/settings.json");
                } else {
                    println!("[NEMESIS INSTALL] → .cursor/settings.json ja existe (mantido)");
                }
            }
            "devin" => {
                let script_path = project_root.join(".nemesis/hooks/nemesis-pretool-check.sh");
                let hooks_path = project_root.join(".devin/hooks.json");
                let ws_dir = project_root.join(".devin");

                if !ws_dir.exists() {
                    fs::create_dir_all(&ws_dir).ok();
                }

                let config = serde_json::json!({
                    "hooks": {
                        "pre_write_code": [{ "command": format!("bash {}", script_path.display()), "show_output": true }],
                        "pre_run_command": [{ "command": format!("bash {}", script_path.display()), "show_output": true }],
                        "pre_read_code": [{ "command": format!("bash {}", script_path.display()), "show_output": true }],
                        "pre_mcp_tool_use": [{ "command": format!("bash {}", script_path.display()), "show_output": true }],
                    }
                });

                fs::write(&hooks_path, serde_json::to_string_pretty(&config).unwrap()).ok();
                println!("  ✓ .devin/hooks.json regenerado com path dinamico");
            }
            _ => {}
        }
    }
}

pub fn main() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
    let args: Vec<String> = env::args().collect();
    let dry_run = args.contains(&"--dry-run".to_string());
    
    let project_root = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let deny_list_path = project_root.join(".nemesis/workflow-enforcement/config/deny-list.json");

    println!("[NEMESIS INSTALL] Iniciando auto-adaptacao...\n");

    println!("[NEMESIS INSTALL] [1/4] Lendo stack do projeto...");
    let result = run_harvest().await;

    println!(
        "[NEMESIS INSTALL] Stack detectada: {}",
        result.stack_detected.iter().map(|(k, v)| format!("{}@{}", k, v)).collect::<Vec<_>>().join(", ")
    );
    println!("[NEMESIS INSTALL] Padroes gerados: {}", result.patterns_generated);
    println!("  → De ESLint: {}", result.patterns_from_eslint);
    println!("  → De tsconfig: {}", result.patterns_from_tsconfig);
    println!("  → De rules: {}", result.patterns_from_rules);

    println!("\n[NEMESIS INSTALL] [2/4] Re-hidratando rules...");
    if !result.rules_rehydrated.is_empty() {
        for f in &result.rules_rehydrated {
            println!("  ✓ .devin/rules/{} atualizado", f);
        }
    } else {
        println!("  → Nenhuma rule atualizada");
    }

    if !result.new_rules_created.is_empty() {
        println!("\n[NEMESIS INSTALL] [3/4] Novas rules criadas (precisam de revisao humana):");
        for f in &result.new_rules_created {
            println!("  ✓ .devin/rules/auto-harvest/{}", f);
        }
    } else {
        println!("\n[NEMESIS INSTALL] [3/4] Nenhuma nova rule auto-harvest criada");
    }

    if !result.patterns_needing_manual_review.is_empty() {
        println!("\n[NEMESIS INSTALL] ⚠  Padroes em linguagem natural (precisam de regex manual):");
        for p in result.patterns_needing_manual_review.iter().take(5) {
            println!("  - {}", p);
        }
        if result.patterns_needing_manual_review.len() > 5 {
            println!("  ... e mais {}", result.patterns_needing_manual_review.len() - 5);
        }
        println!("  → Adicione em deny-list.json na camada \"project\" com type: \"regex\"");
    }

    println!("\n[NEMESIS INSTALL] [4/4] Gerando deny-list.json...");
    let output_json = serde_json::to_value(&result.output).unwrap();
    let merged = match merge_deny_list(output_json, &deny_list_path).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[NEMESIS INSTALL] Erro ao fazer merge: {}", e);
            serde_json::to_value(&result.output).unwrap()
        }
    };

    if !dry_run {
        fs::write(&deny_list_path, serde_json::to_string_pretty(&merged).unwrap()).ok();
        if let Err(e) = validate_deny_list(&deny_list_path) {
            eprintln!("[NEMESIS INSTALL] Erro na validacao: {}", e);
        }
        println!("[NEMESIS INSTALL] ✅ deny-list.json salva em: {}", deny_list_path.display());
    } else {
        println!("[NEMESIS INSTALL] --dry-run: deny-list.json NAO foi salva");
        let preview = serde_json::to_string_pretty(&merged).unwrap();
        println!("{}\n...", &preview[..preview.len().min(500)]);
    }

    println!("\n[NEMESIS INSTALL] [5/5] Configurando IDEs...");
    let detected_ides = detect_ides();
    println!("[NEMESIS INSTALL] IDEs detectados: {}", detected_ides.join(", "));

    if !dry_run {
        generate_ide_configs(&detected_ides, &project_root);
    } else {
        println!("[NEMESIS INSTALL] --dry-run: Configs IDE NAO geradas");
    }

    println!("\n[NEMESIS INSTALL] ✅ Nemesis adaptado para este projeto");
    println!("[NEMESIS INSTALL] Para adicionar regras manuais: edite deny-list.json na camada \"project\"");
    println!("[NEMESIS INSTALL] Para re-executar: bun nemesis:install\n");
    });
}
