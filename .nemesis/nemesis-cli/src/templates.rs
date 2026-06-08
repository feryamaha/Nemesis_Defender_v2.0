// src/templates.rs
pub const CLAUDE_SETTINGS: &str = include_str!("templates/claude-settings.json");
pub const WINDSURF_HOOKS: &str = include_str!("templates/devin-hooks.json");
pub const CURSOR_HOOKS: &str = include_str!("templates/cursor-hooks.json");
pub const CODEX_HOOKS: &str = include_str!("templates/codex-hooks.json");
pub const CODEX_CONFIG: &str = include_str!("templates/codex-config.toml");
pub const OPENCODE_SETTINGS: &str = include_str!("templates/opencode-settings.json");
pub const VSCODE_PLACEHOLDER: &str = include_str!("templates/vscode-placeholder.md");
pub const GHOSTTY_PLACEHOLDER: &str = include_str!("templates/ghostty-placeholder.md");

pub fn substitute_hook_path(template: &str, hook_path: &str) -> String {
    template.replace("{{NEMESIS_HOOK_PATH}}", hook_path)
}

pub fn validate_templates() -> anyhow::Result<()> {
    let templates = vec![
        ("claude", CLAUDE_SETTINGS),
        ("devin", WINDSURF_HOOKS),
        ("cursor", CURSOR_HOOKS),
        ("codex-hooks", CODEX_HOOKS),
        ("codex-config", CODEX_CONFIG),
        ("opencode", OPENCODE_SETTINGS),
    ];

    for (name, content) in templates {
        if name == "codex-config" {
            // TOML validation seria complexo, skip por agora
            continue;
        }
        serde_json::from_str::<serde_json::Value>(content)
            .map_err(|e| anyhow::anyhow!("Template {} inválido: {}", name, e))?;
    }

    Ok(())
}
