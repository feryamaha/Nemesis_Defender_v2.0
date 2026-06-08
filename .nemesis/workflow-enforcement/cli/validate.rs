use std::env;
use std::path::Path;

fn print_usage() {
    println!(
        r#"
Nemesis Workflow Validator

Uso:
  nemesis-validate <caminho-do-workflow>
  cargo run --bin nemesis-validate -- <caminho-do-workflow>

Exemplos:
  nemesis-validate .devin/workflows/generate-prompt-rag.md
  nemesis-validate .devin/workflows/audit-create-pr.md

Retorna:
  Exit code 0 - Workflow valido
  Exit code 1 - Workflow invalido ou erro
"#
    );
}

fn format_violations(errors: &[String], warnings: &[String]) -> String {
    let mut output = String::new();

    if !errors.is_empty() {
        output.push_str("\n❌ ERROS:\n");
        for (index, error) in errors.iter().enumerate() {
            output.push_str(&format!("  {}. {}\n", index + 1, error));
        }
    }

    if !warnings.is_empty() {
        output.push_str("\n⚠️  AVISOS:\n");
        for (index, warning) in warnings.iter().enumerate() {
            output.push_str(&format!("  {}. {}\n", index + 1, warning));
        }
    }

    output
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    // Sem argumentos ou help
    if args.len() == 1 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return if args.len() == 1 {
            std::process::exit(1);
        } else {
            Ok(())
        };
    }

    let workflow_path = &args[1];

    // Verifica se arquivo existe
    if !Path::new(workflow_path).exists() {
        eprintln!("\n❌ ERRO: Arquivo nao encontrado: {}\n", workflow_path);
        std::process::exit(1);
    }

    // Resolve caminho absoluto
    let absolute_path = Path::new(workflow_path)
        .canonicalize()
        .unwrap_or_else(|_| Path::new(workflow_path).to_path_buf());

    println!("\n🔍 Nemesis Workflow Validator");
    println!("   Validando: {}\n", workflow_path);

    // Importa e usa WorkflowRunner
    let runner = nemesis::workflow_runner::WorkflowRunner::new(nemesis::types::ExecutionOptions::default());

    let validation = runner.validate_workflow(&absolute_path.to_string_lossy()).await;

    if validation.is_valid {
        println!("✅ WORKFLOW VALIDO\n");

        if !validation.warnings.is_empty() {
            let warning_strings: Vec<String> = validation.warnings.clone();
            println!("{}", format_violations(&[], &warning_strings));
        }

        println!("   Erros: {}", validation.errors.len());
        println!("   Avisos: {}", validation.warnings.len());
        println!("\n🚀 Workflow pronto para execucao\n");
        std::process::exit(0);
    } else {
        println!("🛑 WORKFLOW INVALIDO\n");
        let error_strings: Vec<String> = validation.errors.clone();
        let warning_strings: Vec<String> = validation.warnings.clone();
        println!("{}", format_violations(&error_strings, &warning_strings));
        println!("\n   Total de erros: {}", validation.errors.len());
        println!("   Total de avisos: {}\n", validation.warnings.len());
        std::process::exit(1);
    }
}
