use std::env;
use std::path::PathBuf;

fn print_usage() {
    println!(
        r#"
Nemesis Test All Workflows

Uso:
  nemesis-test-all
  cargo run --bin nemesis-test-all

Opcoes:
  --verbose    Mostra logs detalhados
  --help       Mostra esta ajuda

Retorna:
  Exit code 0 - Todos os workflows validos
  Exit code 1 - Um ou mais workflows invalidos
"#
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    // Verifica flags
    let verbose = args.iter().any(|arg| arg == "--verbose");
    let help = args.iter().any(|arg| arg == "--help" || arg == "-h");

    if help {
        print_usage();
        return Ok(());
    }

    let workflows_path = PathBuf::from(".devin/workflows");

    println!("\n𓍝 Nemesis Test All Workflows");
    println!("   Diretorio: {}\n", workflows_path.display());

    let runner = nemesis::workflow_runner::WorkflowRunner::new(nemesis::types::ExecutionOptions::default());

    // Lista todos os workflows
    let workflow_files: Vec<String> = nemesis::workflow_catalog::WorkflowCatalog::list_workflows(Some(".")).await;

    if workflow_files.is_empty() {
        println!("⚠️  Nenhum workflow encontrado\n");
        return Ok(());
    }

    println!("   Encontrados: {} workflows\n", workflow_files.len());
    println!("{}", "=".repeat(60));

    // Valida todos
    let validation_result = match runner.validate_all_workflows(&workflows_path.to_string_lossy()).await {
        Ok(result) => result,
        Err(e) => {
            eprintln!("\n🔴 ERRO FATAL:\n");
            eprintln!("   {}\n", e);
            std::process::exit(1);
        }
    };

    // Exibe resultados
    println!("\n📋 RESULTADOS:\n");

    let mut has_errors = false;

    for result in &validation_result.results {
        let icon = if result.is_valid { "🟢" } else { "🔴" };
        let workflow_name = PathBuf::from(&result.workflow)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&result.workflow)
            .to_string();

        println!("{} {}", icon, workflow_name);

        if verbose || !result.is_valid {
            if !result.errors.is_empty() {
                println!("   Erros:");
                for (idx, error) in result.errors.iter().enumerate() {
                    println!("      {}. {}", idx + 1, error.message);
                }
            }

            if !result.warnings.is_empty() {
                println!("   Avisos:");
                for (idx, warning) in result.warnings.iter().enumerate() {
                    println!("      {}. {}", idx + 1, warning.message);
                }
            }
        }

        if !result.is_valid {
            has_errors = true;
        }

        if verbose || !result.is_valid || !result.warnings.is_empty() {
            println!();
        }
    }

    println!("{}", "=".repeat(60));

    // Resumo
    let total = validation_result.total as f64;
    let valid = validation_result.valid as f64;
    let compliance = if total > 0.0 {
        (valid / total) * 100.0
    } else {
        0.0
    };

    println!("\n RESUMO:\n");
    println!("   Total:    {}", validation_result.total);
    println!("   🟢 CONF:   {}", validation_result.valid);
    println!("   🔴 NCONF: {}", validation_result.invalid);
    println!("   ‰ Conformidade:      {:.1}%", compliance);

    if has_errors {
        println!("\n🔴 FALHA: Um ou mais workflows possuem erros\n");
        std::process::exit(1);
    } else {
        println!("\n🟢 SUCESSO: Todos os workflows estao Conformes\n");
        std::process::exit(0);
    }
}
