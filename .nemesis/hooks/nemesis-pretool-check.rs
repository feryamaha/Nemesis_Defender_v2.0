// =============================================================================
// Nemesis PreToolUse Hook - Entry Point Universal (Cross-Platform)
// diretorio: .nemesis/hooks/nemesis-pretool-check.rs
// =============================================================================
//
// Funciona em Windows (PowerShell), MacOS (zsh/bash) e Linux (bash).
// Recebe JSON via stdin do Devin, delega para pretool-hook.rs via execucao.
// Retorna exit code 0 (permitir) ou 2 (bloquear).
//
// POLITICA DE FALHAS:
// - Violacao de regra real                    -> exit 2 (bloquear)
// - Erro interno de infra (tsx crash)         -> exit 0 (permitir)
//   MOTIVO: Erros de infraestrutura nao devem impedir o trabalho da IA.
//           O Nemesis e guardiao de regras, nao gargalo de disponibilidade.
//
// PROTECAO ANTI-BYPASS POR CRASH FORCADO:
//   Se o hook retornar qualquer saida contendo 'NEMESIS BLOCKED',
//   o exit code e sempre tratado como bloqueio, independente do codigo numerico.
//   Isso previne bypass por crash forcado (exit 1 com stderr manipulado).
// =============================================================================

use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ============================================================
// ESTRUTURAS DE DADOS
// ============================================================

#[derive(Debug, serde::Deserialize)]
struct ToolInput {
    #[serde(rename = "toolName")]
    tool_name: Option<String>,
    #[serde(rename = "toolInput")]
    tool_input: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug)]
struct HostEnvironment {
    os: String,
    package_manager: String,
}

// ============================================================
// RESOLUCAO AUTOMATICA DE PATH
// ============================================================

fn detect_host_environment(project_root: &Path) -> HostEnvironment {
    let os = env::consts::OS.to_string();

    let has_yarn_lock = project_root.join("yarn.lock").exists();
    let has_bun_lock = project_root.join("bun.lockb").exists();
    let has_npm_lock = project_root.join("package-lock.json").exists();
    let has_pnpm_lock = project_root.join("pnpm-lock.yaml").exists();

    let package_manager = if has_yarn_lock {
        "yarn"
    } else if has_bun_lock {
        "bun"
    } else if has_npm_lock {
        "npm"
    } else if has_pnpm_lock {
        "pnpm"
    } else {
        "bun"
    };

    HostEnvironment {
        os,
        package_manager: package_manager.to_string(),
    }
}

fn find_hook_path(project_root: &Path) -> Option<PathBuf> {
    let possible_paths = [
        project_root.join("src").join("workflow-enforcement").join("cli").join("pretool-hook.rs"),
        project_root.join(".nemesis").join("workflow-enforcement").join("cli").join("pretool-hook.rs"),
        project_root.join("workflow-enforcement").join("cli").join("pretool-hook.rs"),
        project_root.join("dist").join("workflow-enforcement").join("cli").join("pretool-hook.js"),
        project_root.join("target").join("release").join("pretool-hook"),
        project_root.join("target").join("debug").join("pretool-hook"),
    ];

    for candidate in &possible_paths {
        if candidate.exists() {
            return Some(candidate.clone());
        }
    }

    None
}

// ============================================================
// PRE-VALIDACAO DE HEREDOC
// ============================================================

fn pre_validate_heredoc_bypass(tool_input: &ToolInput) -> Option<String> {
    if tool_input.tool_name.as_deref() != Some("Bash") {
        return None;
    }

    let command = match &tool_input.tool_input {
        Some(input) => match input.get("command") {
            Some(cmd) => cmd.as_str().unwrap_or(""),
            None => return None,
        },
        None => return None,
    };

    if command.is_empty() {
        return None;
    }

    let critical_file_patterns = [
        Regex::new(r"tsconfig\.json$").unwrap(),
        Regex::new(r"package\.json$").unwrap(),
        Regex::new(r"\.eslintrc").unwrap(),
        Regex::new(r"next\.config").unwrap(),
        Regex::new(r"tailwind\.config").unwrap(),
        Regex::new(r"postcss\.config").unwrap(),
        Regex::new(r"\.env").unwrap(),
    ];

    // Detectar heredoc: cat > file << 'EOF'
    let heredoc_regex = Regex::new(
        r#"(?:cat|tee)\s*>\s*([^\s<]+)\s*<<\s*['"]?(?:EOF|HEREDOC|END)['"]?\n([\s\S]*?)\n(?:EOF|HEREDOC|END)"#
    ).unwrap();

    if let Some(caps) = heredoc_regex.captures(command) {
        let target_file = caps[1].trim();
        if critical_file_patterns.iter().any(|p| p.is_match(target_file)) {
            return Some(format!(
                "NEMESIS BLOCKED: Criacao de arquivo critico via heredoc bloqueada: {}",
                target_file
            ));
        }
        // Verificacao basica de conteudo de heredoc
        let content = &caps[2];
        let strict_disable = Regex::new(r#""strict"\s*:\s*false"#).unwrap();
        let no_implicit_any = Regex::new(r#""noImplicitAny"\s*:\s*false"#).unwrap();

        if strict_disable.is_match(content) || no_implicit_any.is_match(content) {
            return Some(
                "NEMESIS BLOCKED: Heredoc contem desabilitacao de TypeScript strict mode".to_string(),
            );
        }
    }

    // Detectar echo redirect: echo "..." > file
    let echo_regex = Regex::new(
        r#"echo\s+["'](.+?)["']\s*(?:>>?)\s*([^\s;|&]+)"#
    ).unwrap();

    if let Some(caps) = echo_regex.captures(command) {
        let target_file = &caps[2];
        if critical_file_patterns.iter().any(|p| p.is_match(target_file)) {
            return Some(format!(
                "NEMESIS BLOCKED: NEMESIS SEC - COMANDO NAO PERMITIDO · {}",
                target_file
            ));
        }
    }

    // Detectar printf redirect
    let printf_regex = Regex::new(r"printf\s.+.(?:>>?)\s*\S+\.(tsx?|jsx?|json)").unwrap();
    if printf_regex.is_match(command) {
        return Some(
            "NEMESIS BLOCKED: NEMESIS SEC - COMANDO NAO PERMITIDO".to_string(),
        );
    }

    None
}

// ============================================================
// MAIN
// ============================================================

fn main() {
    // Determinar project_root a partir do diretorio do executavel
    let current_dir = env::current_dir().expect("Falha ao obter diretorio atual");
    let project_root = current_dir.clone();

    let host_env = detect_host_environment(&project_root);
    eprintln!(
        "Nemesis v2 - Projeto hospedeiro detectado: {} / {}",
        host_env.os, host_env.package_manager
    );

    let hook_path = match find_hook_path(&project_root) {
        Some(path) => path,
        None => {
            // FAIL-OPEN: hook nao encontrado = problema de instalacao, nao violacao de regra
            eprintln!("[NEMESIS WARNING] pretool-hook.rs nao encontrado. Instalacao pode estar incompleta.");
            eprintln!("Localizacoes verificadas:");
            eprintln!("  - src/workflow-enforcement/cli/pretool-hook.rs");
            eprintln!("  - .nemesis/workflow-enforcement/cli/pretool-hook.rs");
            eprintln!("  - workflow-enforcement/cli/pretool-hook.rs");
            eprintln!("  - dist/workflow-enforcement/cli/pretool-hook.js");
            eprintln!("  - target/release/pretool-hook");
            eprintln!("  - target/debug/pretool-hook");
            eprintln!("Permitindo operacao — verifique a instalacao do Nemesis.");
            std::process::exit(0);
        }
    };

    // Ler stdin
    let mut input = String::new();
    if let Err(err) = io::stdin().read_to_string(&mut input) {
        eprintln!("[NEMESIS WARNING] Erro ao ler stdin: {}", err);
        std::process::exit(0);
    }

    let input = input.trim();
    if input.is_empty() {
        eprintln!("[NEMESIS WARNING] Nenhum input recebido via stdin. Permitindo operacao.");
        std::process::exit(0);
    }

    // Validar que o input e JSON valido antes de passar ao hook
    let parsed_input: ToolInput = match serde_json::from_str(input) {
        Ok(parsed) => parsed,
        Err(_) => {
            eprintln!("[NEMESIS WARNING] Input nao e JSON valido. Permitindo operacao.");
            std::process::exit(0);
        }
    };

    // Executar pre-validacao de heredoc
    if let Some(block_message) = pre_validate_heredoc_bypass(&parsed_input) {
        eprintln!("{}", block_message);
        std::process::exit(2);
    }

    // Executar o hook
    let output = Command::new(&hook_path)
        .arg("--stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match output {
        Ok(child) => child,
        Err(err) => {
            eprintln!("[NEMESIS WARNING] Erro ao executar hook: {}. Permitindo operacao.", err);
            std::process::exit(0);
        }
    };

    // Enviar input para o stdin do hook
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(err) = stdin.write_all(input.as_bytes()) {
            eprintln!("[NEMESIS WARNING] Erro ao enviar input para hook: {}. Permitindo operacao.", err);
            std::process::exit(0);
        }
    }

    let result = child.wait_with_output();

    match result {
        Ok(output) => {
            let exit_code = output.status.code().unwrap_or(0);
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            let full_output = format!("{}{}", stderr_str, stdout_str);

            // Verificar se contem NEMESIS BLOCKED (protecao extra)
            if stdout_str.contains("NEMESIS BLOCKED") || stderr_str.contains("NEMESIS BLOCKED") {
                eprint!("{}", full_output);
                std::process::exit(2);
            }

            // Deteccao de violacao real vs crash de infra
            let is_real_violation = exit_code == 2 || full_output.contains("NEMESIS BLOCKED");

            if is_real_violation {
                if !full_output.is_empty() {
                    eprint!("{}", full_output);
                }
                std::process::exit(2);
            }

            // Hook retornou exit 0 -> permitir
            std::process::exit(0);
        }
        Err(err) => {
            // Crash de infra -> FAIL-OPEN com log detalhado
            eprintln!("[NEMESIS WARNING] Erro interno no hook — operacao permitida por seguranca de disponibilidade.");
            eprintln!("[Detalhes]: {}", err);
            eprintln!("Verifique o Nemesis se esse aviso se repetir com frequencia.");
            std::process::exit(0);
        }
    }
}
