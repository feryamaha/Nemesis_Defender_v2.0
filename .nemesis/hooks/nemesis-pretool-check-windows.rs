// =============================================================================
// Nemesis PreToolUse Hook - PowerShell/Windows Version
// =============================================================================
//
// Este script e chamado automaticamente pelo Devin IDE via PreToolUse hook
// antes de executar qualquer ferramenta (Edit, Write, Bash, etc.)
//
// Recebe JSON via stdin no formato oficial Devin e passa para pretool-hook.ts
// Retorna exit code 2 para bloquear tecnicamente a ferramenta se violacao detectada
//
// Uso: Configurado no frontmatter dos workflows em .devin/workflows/
//
// Exemplo de configuracao no workflow:
//   hooks:
//     PreToolUse:
//       - matcher: "Edit|Write|Bash"
//         hooks:
//           - type: command
//             command: "powershell -File $PROJECT_DIR/.nemesis/hooks/nemesis-pretool-check.ps1"
//
// =============================================================================

use std::env;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ============================================================
// MAIN
// ============================================================

fn main() {
    // Configurar strict mode - em Rust, panics abortam o programa
    // equivalente a Set-StrictMode -Version Latest

    // Detectar diretorio do projeto (subir 2 niveis de .nemesis/hooks/)
    let script_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| {
            eprintln!("NEMESIS ERROR: Falha ao detectar diretorio do script");
            std::process::exit(1);
        });
    
    let project_dir = script_dir.parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| {
            eprintln!("NEMESIS ERROR: Falha ao detectar diretorio do projeto");
            std::process::exit(1);
        });

    // Verificar se estamos em ambiente de desenvolvimento
    let hook_script_ts = project_dir.join("src").join("workflow-enforcement").join("cli").join("pretool-hook.ts");
    let hook_script_js = project_dir.join("dist").join("workflow-enforcement").join("cli").join("pretool-hook.js");
    let hook_script_nemesis = project_dir.join(".nemesis").join("workflow-enforcement").join("cli").join("pretool-hook.ts");

    let (hook_script, runner) = if hook_script_ts.exists() {
        (hook_script_ts, "npx ts-node")
    } else if hook_script_js.exists() {
        // Versao compilada (producao)
        (hook_script_js, "node")
    } else if hook_script_nemesis.exists() {
        // Versao instalada via npx install-genesis
        (hook_script_nemesis, "npx tsx")
    } else {
        eprintln!("NEMESIS ERROR: Hook script nao encontrado");
        eprintln!("Procurado em:");
        eprintln!("  - {}", hook_script_ts.display());
        eprintln!("  - {}", hook_script_js.display());
        eprintln!("  - {}", hook_script_nemesis.display());
        std::process::exit(1);
    };

    // Ler input do stdin (JSON do Devin)
    let mut input_data = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input_data) {
        eprintln!("NEMESIS WARNING: Erro ao ler stdin: {}", e);
        // Permite continuar - o hook.ts vai tratar o erro
    }

    // Verificar se input esta vazio
    let input_data = input_data.trim();
    if input_data.is_empty() {
        eprintln!("NEMESIS WARNING: Input vazio recebido");
        // Permite continuar - o hook.ts vai tratar o erro
    }

    // Executar pretool-hook.ts passando JSON via stdin
    let result = Command::new("npx")
        .args(&["ts-node", &hook_script.to_string_lossy()])
        .current_dir(&project_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match result {
        Ok(child) => child,
        Err(e) => {
            eprintln!("NEMESIS ERROR: Erro ao executar hook: {}", e);
            // Em caso de erro, permite continuar para nao travar o IDE
            std::process::exit(0);
        }
    };

    // Passar input para o processo
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(input_data.as_bytes()) {
            eprintln!("NEMESIS ERROR: Erro ao enviar input: {}", e);
        }
        // Fechar stdin
        drop(stdin);
    }

    // Capturar saida
    match child.wait_with_output() {
        Ok(output) => {
            let exit_code = output.status.code().unwrap_or(0);
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            let stderr_str = String::from_utf8_lossy(&output.stderr);

            // Se exit code 2, bloquear com mensagem no stderr (formato para IA)
            if exit_code == 2 {
                eprintln!("{}", stderr_str);
                std::process::exit(2);
            }

            // Se exit code 1, erro tecnico (nao bloqueia, mas reporta)
            if exit_code == 1 {
                eprintln!("NEMESIS ERROR: Erro tecnico no hook");
                eprintln!("{}", stderr_str);
                // Permite continuar para nao travar o workflow, mas loga o erro
                std::process::exit(0);
            }

            // Exit code 0 = permissao concedida
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("NEMESIS ERROR: Erro ao capturar saida do hook: {}", e);
            // Em caso de erro, permite continuar para nao travar o IDE
            std::process::exit(0);
        }
    }
}
