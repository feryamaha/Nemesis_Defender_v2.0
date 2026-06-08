// src/hooks.rs
use std::fs;
use std::path::Path;
use std::io::{self, Write};
use crate::templates;

pub fn generate_hooks(target_dir: &Path, ide: &str, hook_path: &str) -> anyhow::Result<()> {
    let config = match ide {
        "Claude Code" => {
            let content = templates::substitute_hook_path(templates::CLAUDE_SETTINGS, hook_path);
            (target_dir.join(".claude/settings.json"), content)
        },
        "Devin" => {
            let content = templates::substitute_hook_path(templates::WINDSURF_HOOKS, hook_path);
            (target_dir.join(".devin/hooks.json"), content)
        },
        "Cursor" => {
            let content = templates::substitute_hook_path(templates::CURSOR_HOOKS, hook_path);
            (target_dir.join(".cursor/nemesis-setup.md"), content)
        },
        "Codex" => {
            // Codex precisa de 2 arquivos: hooks.json + config.toml
            let hooks_content = templates::substitute_hook_path(templates::CODEX_HOOKS, hook_path);
            let config_content = templates::substitute_hook_path(templates::CODEX_CONFIG, hook_path);

            // Gerar hooks.json
            generate_hooks_file(target_dir, ".codex/hooks.json", &hooks_content, ide)?;

            // Gerar config.toml
            generate_hooks_file(target_dir, ".codex/config.toml", &config_content, ide)?;

            return Ok(());
        },
        "OpenClaude" => {
            let content = templates::substitute_hook_path(templates::OPENCODE_SETTINGS, hook_path);
            (target_dir.join(".openclaude/settings.json"), content)
        },
        "VSCode" => {
            let content = templates::VSCODE_PLACEHOLDER.to_string();
            (target_dir.join(".vscode/nemesis-setup.md"), content)
        },
        "Ghostty" => {
            let content = templates::GHOSTTY_PLACEHOLDER.to_string();
            (target_dir.join(".ghostty/nemesis-setup.md"), content)
        },
        _ => return Err(anyhow::anyhow!("IDE desconhecido: {}", ide)),
    };

    generate_hooks_file(target_dir, &config.0.to_string_lossy(), &config.1, ide)?;
    Ok(())
}

fn generate_hooks_file(target_dir: &Path, file_path: &str, content: &str, ide: &str) -> anyhow::Result<()> {
    let full_path = target_dir.join(file_path);

    // Criar diretorio se nao existir
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Se arquivo JA existe, perguntar ao usuario
    if full_path.exists() {
        println!("[nemesis] {} already exists.", full_path.display());
        print!("[nemesis] Add Nemesis hooks to existing file? (y/n): ");
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        let response = response.trim().to_lowercase();

        if response != "y" && response != "yes" {
            println!("[nemesis] {} — skipped (user choice)", ide);
            return Ok(());
        }

        // Se e JSON e ja existe, mesclar
        if file_path.ends_with(".json") {
            merge_json_file(&full_path, content)?;
            println!("[nemesis] Configurado: {} (merged)", ide);
            return Ok(());
        }

        // Se e TOML ou outro formato, substituir (TOML nao suporta merge facil)
        if file_path.ends_with(".toml") {
            fs::write(&full_path, content)?;
            println!("[nemesis] Configurado: {} (TOML replaced)", ide);
            return Ok(());
        }
    }

    // Se arquivo NAO existe, criar
    fs::write(&full_path, content)?;
    println!("[nemesis] Configurado: {} ({})", ide, full_path.display());

    Ok(())
}

fn merge_json_file(file_path: &Path, new_content: &str) -> anyhow::Result<()> {
    // Ler JSON existente
    let existing_text = fs::read_to_string(file_path)?;
    let mut existing: serde_json::Value = serde_json::from_str(&existing_text)?;

    // Parsear novo conteudo
    let new_json: serde_json::Value = serde_json::from_str(new_content)?;

    // Mesclar secção "hooks" apenas
    if let Some(hooks_obj) = new_json.get("hooks") {
        existing["hooks"] = hooks_obj.clone();
    }

    // Escrever resultado
    let merged_text = serde_json::to_string_pretty(&existing)?;
    fs::write(file_path, merged_text)?;

    Ok(())
}
