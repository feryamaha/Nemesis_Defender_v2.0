use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ScopeConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rag_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_files: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_files: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
}

fn get_scope_dir() -> PathBuf {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    cwd.join(".nemesis")
}

fn get_scope_file() -> PathBuf {
    get_scope_dir().join("scope.json")
}

fn ensure_dir() {
    let scope_dir = get_scope_dir();
    if !scope_dir.exists() {
        fs::create_dir_all(&scope_dir).expect("Failed to create scope directory");
    }
}

fn read_scope() -> ScopeConfig {
    let scope_file = get_scope_file();
    if !scope_file.exists() {
        return ScopeConfig {
            allowed_files: Some(Vec::new()),
            allowed_patterns: Some(Vec::new()),
            blocked_files: Some(Vec::new()),
            created_at: Some(chrono::Utc::now().to_rfc3339()),
            ..Default::default()
        };
    }

    match fs::read_to_string(&scope_file) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|_| {
            ScopeConfig {
                allowed_files: Some(Vec::new()),
                allowed_patterns: Some(Vec::new()),
                blocked_files: Some(Vec::new()),
                created_at: Some(chrono::Utc::now().to_rfc3339()),
                ..Default::default()
            }
        }),
        Err(_) => ScopeConfig {
            allowed_files: Some(Vec::new()),
            allowed_patterns: Some(Vec::new()),
            blocked_files: Some(Vec::new()),
            created_at: Some(chrono::Utc::now().to_rfc3339()),
            ..Default::default()
        },
    }
}

fn write_scope(scope: &ScopeConfig) {
    ensure_dir();
    let scope_file = get_scope_file();
    let content = serde_json::to_string_pretty(scope).expect("Failed to serialize scope");
    fs::write(&scope_file, content).expect("Failed to write scope file");
}

fn normalize_file_path(file_path: &str) -> String {
    file_path.replace('\\', "/").replacen("./", "", 1)
}

fn extract_files_from_rag(rag_content: &str) -> Vec<String> {
    let mut files: HashSet<String> = HashSet::new();

    // Pattern 1: @src/path/to/file.tsx ou @[src/path/to/file.tsx]
    let at_pattern = Regex::new(r"@\[?([^\s\]]+\.(tsx?|jsx?|css|json|md))\]?").unwrap();
    for cap in at_pattern.captures_iter(rag_content) {
        files.insert(normalize_file_path(&cap[1]));
    }

    // Pattern 2: Arquivo mencionado em bullets: - src/path/to/file.tsx
    let bullet_pattern = Regex::new(r"[-*]\s+(src/[^\s]+\.(tsx?|jsx?|css|json))").unwrap();
    for cap in bullet_pattern.captures_iter(rag_content) {
        files.insert(normalize_file_path(&cap[1]));
    }

    // Pattern 3: Arquivo entre backticks: `src/path/to/file.tsx`
    let backtick_pattern = Regex::new(r"`(src/[^`]+\.(tsx?|jsx?|css|json))`").unwrap();
    for cap in backtick_pattern.captures_iter(rag_content) {
        files.insert(normalize_file_path(&cap[1]));
    }

    // Filtrar arquivos de regras e workflows (nao sao editaveis)
    files.into_iter()
        .filter(|f| !f.starts_with(".devin/") && !f.starts_with("Feature-Documentation/") && !f.starts_with(".nemesis/"))
        .collect()
}

fn cmd_set(files: &[String]) {
    if files.is_empty() {
        eprintln!("Erro: Forneca pelo menos um arquivo.");
        eprintln!("Uso: nemesis-scope set <file1> [file2] ...");
        std::process::exit(1);
    }

    let scope = ScopeConfig {
        allowed_files: Some(files.iter().map(|f| normalize_file_path(f)).collect()),
        allowed_patterns: Some(Vec::new()),
        blocked_files: Some(Vec::new()),
        created_at: Some(chrono::Utc::now().to_rfc3339()),
        ..Default::default()
    };

    write_scope(&scope);
    println!("Escopo definido com {} arquivo(s):", files.len());
    for file in scope.allowed_files.as_ref().unwrap() {
        println!("  + {}", file);
    }
}

fn cmd_add(file: &str) {
    let mut scope = read_scope();
    if scope.allowed_files.is_none() {
        scope.allowed_files = Some(Vec::new());
    }

    let normalized = normalize_file_path(file);
    let files = scope.allowed_files.as_mut().unwrap();
    if !files.contains(&normalized) {
        files.push(normalized.clone());
    }

    write_scope(&scope);
    println!("Arquivo adicionado ao escopo: {}", normalized);
    println!("Total de arquivos no escopo: {}", scope.allowed_files.as_ref().unwrap().len());
}

fn cmd_add_pattern(pattern: &str) {
    let mut scope = read_scope();
    if scope.allowed_patterns.is_none() {
        scope.allowed_patterns = Some(Vec::new());
    }

    let normalized = normalize_file_path(pattern);
    let patterns = scope.allowed_patterns.as_mut().unwrap();
    if !patterns.contains(&normalized) {
        patterns.push(normalized.clone());
    }

    write_scope(&scope);
    println!("Pattern adicionado ao escopo: {}", normalized);
}

fn cmd_from_rag(rag_file: &str) {
    if !PathBuf::from(rag_file).exists() {
        eprintln!("Erro: Arquivo RAG nao encontrado: {}", rag_file);
        std::process::exit(1);
    }

    let rag_content = fs::read_to_string(rag_file).expect("Failed to read RAG file");
    let files = extract_files_from_rag(&rag_content);

    if files.is_empty() {
        println!("Nenhum arquivo de codigo encontrado no RAG.");
        println!("O escopo sera criado vazio (modo aberto).");
    }

    let scope = ScopeConfig {
        task: Some("Extraido do RAG".to_string()),
        rag_reference: Some(normalize_file_path(rag_file)),
        allowed_files: Some(files.clone()),
        allowed_patterns: Some(vec![
            "src/types/**/*.types.ts".to_string(),
            "src/hooks/**/*.hook.ts".to_string(),
        ]),
        blocked_files: Some(Vec::new()),
        created_at: Some(chrono::Utc::now().to_rfc3339()),
    };

    write_scope(&scope);
    println!("Escopo extraido do RAG: {}", rag_file);
    println!("Arquivos encontrados ({}):", files.len());
    for file in &files {
        println!("  + {}", file);
    }
    println!("\nPatterns padrao adicionados:");
    for pattern in scope.allowed_patterns.as_ref().unwrap() {
        println!("  + {}", pattern);
    }
    println!("\nEscopo salvo em: .nemesis/scope.json");
}

fn cmd_show() {
    let scope_file = get_scope_file();
    if !scope_file.exists() {
        println!("Nenhum escopo ativo (modo aberto - todos os arquivos permitidos).");
        return;
    }

    let scope = read_scope();
    println!("=== Escopo Nemesis Ativo ===\n");

    if let Some(ref task) = scope.task {
        println!("Tarefa: {}", task);
    }
    if let Some(ref rag) = scope.rag_reference {
        println!("RAG: {}", rag);
    }
    if let Some(ref created) = scope.created_at {
        println!("Criado em: {}", created);
    }

    println!("\nArquivos permitidos:");
    if let Some(ref files) = scope.allowed_files {
        if !files.is_empty() {
            for file in files {
                println!("  + {}", file);
            }
        } else {
            println!("  (nenhum - modo aberto)");
        }
    }

    if let Some(ref patterns) = scope.allowed_patterns {
        if !patterns.is_empty() {
            println!("\nPatterns permitidos:");
            for pattern in patterns {
                println!("  + {}", pattern);
            }
        }
    }

    if let Some(ref blocked) = scope.blocked_files {
        if !blocked.is_empty() {
            println!("\nArquivos bloqueados:");
            for file in blocked {
                println!("  - {}", file);
            }
        }
    }
}

fn cmd_clear() {
    let scope_file = get_scope_file();
    if scope_file.exists() {
        let scope = read_scope();
        fs::remove_file(&scope_file).expect("Failed to remove scope file");
        println!("Escopo removido. Modo aberto (todos os arquivos permitidos).");
    } else {
        println!("Nenhum escopo ativo para remover.");
    }
}

fn show_help() {
    println!(
        r#"
Nemesis Scope Manager - Controle de escopo de edicao

Comandos:
  nemesis-scope set <file1> [file2] ...   Define escopo com arquivos especificos
  nemesis-scope add <file>                 Adiciona arquivo ao escopo existente
  nemesis-scope add-pattern <glob>         Adiciona pattern glob ao escopo
  nemesis-scope from-rag <rag-file>        Extrai arquivos do prompt RAG automaticamente
  nemesis-scope show                       Mostra escopo atual
  nemesis-scope clear                      Remove escopo (modo aberto)

Exemplos:
  nemesis-scope set "src/components/ui/Button.tsx"
  nemesis-scope add "src/types/ui/button.types.ts"
  nemesis-scope add-pattern "src/hooks/**/*.hook.ts"
  nemesis-scope from-rag "Feature-Documentation/prompts/032_descricao.md"
  nemesis-scope show
  nemesis-scope clear

Funcionamento:
  - O escopo define quais arquivos a IA pode editar
  - O PreToolUse hook valida automaticamente cada Edit/Write
  - Sem escopo ativo = modo aberto (permite tudo)
  - Com escopo ativo = apenas arquivos listados sao permitidos
"#
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(|s| s.as_str());

    match command {
        Some("set") => cmd_set(&args[2..]),
        Some("add") => {
            if args.len() < 3 {
                eprintln!("Erro: Forneca o arquivo para adicionar.");
                std::process::exit(1);
            }
            cmd_add(&args[2]);
        }
        Some("add-pattern") => {
            if args.len() < 3 {
                eprintln!("Erro: Forneca o pattern para adicionar.");
                std::process::exit(1);
            }
            cmd_add_pattern(&args[2]);
        }
        Some("from-rag") => {
            if args.len() < 3 {
                eprintln!("Erro: Forneca o caminho do arquivo RAG.");
                std::process::exit(1);
            }
            cmd_from_rag(&args[2]);
        }
        Some("show") => cmd_show(),
        Some("clear") => cmd_clear(),
        _ => {
            show_help();
            if command.is_some() {
                std::process::exit(1);
            }
        }
    }
}
