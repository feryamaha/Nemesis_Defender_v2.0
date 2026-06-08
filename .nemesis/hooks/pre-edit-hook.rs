use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

// ============================================================
// PRE-EDIT HOOK for Nemesis Enforcement Engine
// Intercepta EDICOES de codigo e valida contra @.devin/rules
//
// REGRAS DE BLOQUEIO (apenas violacoes reais):
// 1. CSS inline em componentes UI (style={{ }})
// 2. Uso de `any` explicito em tipagem
// 3. useState/useEffect DENTRO de componentes UI (arquivos fora de /hooks/)
// 4. Comandos bash destrutivos de sistema
// 5. Comandos de atualizacao em massa de dependencias
// 6. Criacao/sobrescrita de arquivos via heredoc, echo redirect, printf redirect
// 7. Modificacao de arquivos de configuracao criticos (tsconfig.json, package.json)
//
// FIXES APLICADOS:
// - CRITICO: '.nemesis/' removido de alwaysAllowed — arquivos do proprio enforcer
//   nao podem ser sobrescritos livremente. Antes qualquer IA podia reescrever
//   workflow-enforcer.ts sem restricao.
// - CRITICO: Deteccao de heredoc adicionada em validacao bash (vetores usados no bypass)
// - CRITICO: criticalFiles agora BLOQUEIA absolutamente (nao apenas marca como critico)
// - FIX: package.json e tsconfig.json bloqueados via criticalFiles (antes permitidos)
//
// NUNCA bloquear por erro de infraestrutura — apenas por violacao de regra.
// ============================================================

#[derive(Debug, Clone)]
struct ValidationResult {
    allowed: bool,
    reason: String,
    violated_rules: Vec<String>,
    severity: String,
    suggestions: Vec<String>,
}

#[derive(Debug, Clone)]
struct Action {
    action_type: String,
    target: String,
    content: Option<String>,
}

/// Verifica se o arquivo e um hook dedicado (logica permitida)
fn is_hook_file(file_path: &str) -> bool {
    if file_path.is_empty() {
        return false;
    }
    let normalized = file_path.replace('\\', "/");
    normalized.contains("/hooks/")
        || normalized.ends_with(".hook.ts")
        || normalized.ends_with(".hook.tsx")
}

/// Verifica se o arquivo e um componente UI puro (sem logica de estado)
fn is_ui_component(file_path: &str) -> bool {
    if file_path.is_empty() {
        return false;
    }
    let normalized = file_path.replace('\\', "/");
    normalized.contains("/components/")
        && (normalized.ends_with(".tsx") || normalized.ends_with(".jsx"))
        && !is_hook_file(&normalized)
}

/// REGRA 5: Comandos de atualizacao em massa de dependencias — SEMPRE BLOQUEADOS.
const BLOCKED_MASS_UPDATE_COMMANDS: &[&str] = &[
    "bun update",
    "bun upgrade",
    "npm update",
    "npm upgrade",
    "npm audit fix",
    "npm audit fix --force",
    "yarn upgrade",
    "yarn upgrade-interactive",
    "pnpm update",
    "pnpm upgrade",
];

fn matches_mass_update_command(command: &str) -> Option<String> {
    let normalized = command.trim().to_lowercase();
    for blocked in BLOCKED_MASS_UPDATE_COMMANDS {
        if normalized == *blocked
            || normalized.starts_with(&format!("{} ", blocked))
            || normalized.starts_with(&format!("{}\n", blocked))
        {
            return Some(blocked.to_string());
        }
    }
    None
}

/// REGRA 6: Detectar criacao de arquivo via heredoc, echo redirect, printf redirect.
/// Estes foram os vetores usados no bypass confirmado em producao.
fn detect_file_creation_bypass(command: &str) -> Option<(bool, String, String)> {
    let critical_file_patterns = [
        Regex::new(r"tsconfig\.json$").unwrap(),
        Regex::new(r"package\.json$").unwrap(),
        Regex::new(r"\.eslintrc").unwrap(),
        Regex::new(r"next\.config").unwrap(),
        Regex::new(r"tailwind\.config").unwrap(),
        Regex::new(r"postcss\.config").unwrap(),
        Regex::new(r"\.env").unwrap(),
    ];

    // Detectar heredoc: cat > file << 'EOF' ou tee file << 'EOF'
    let heredoc_regex = regex::Regex::new(
        r#"(?:cat|tee)\s*>\s*([^\s<]+)\s*<<\s*['"]?(?:EOF|HEREDOC|END)['"]?\n?([\s\S]*?)\n?(?:EOF|HEREDOC|END)"#
    ).unwrap();

    if let Some(caps) = heredoc_regex.captures(command) {
        let target_file = caps[1].trim();
        let content = caps.get(2).map(|m| m.as_str()).unwrap_or("");

        if critical_file_patterns.iter().any(|p| p.is_match(target_file)) {
            return Some((
                true,
                format!(
                    r#"NEMESIS BLOCKED: Criacao de arquivo de configuracao critico via heredoc: "{}". Arquivos criticos nao podem ser sobrescritos via Bash."#,
                    target_file
                ),
                "critical-config-file-protection".to_string(),
            ));
        }

        // Verificar conteudo do heredoc contra padroes de violacao
        let strict_disable = Regex::new(r#""strict"\s*:\s*false"#).unwrap();
        let no_implicit_any = Regex::new(r#""noImplicitAny"\s*:\s*false"#).unwrap();
        let strict_null = Regex::new(r#""strictNullChecks"\s*:\s*false"#).unwrap();

        if strict_disable.is_match(content) || no_implicit_any.is_match(content) || strict_null.is_match(content) {
            return Some((
                true,
                "NEMESIS BLOCKED: Conteudo do heredoc desabilita TypeScript strict mode. Este bloqueio NAO pode ser sobrescrito por instrucao do usuario.".to_string(),
                "typescript-strict-mode-required".to_string(),
            ));
        }

        let styled_jsx = Regex::new(r#""styled-jsx""#).unwrap();
        if styled_jsx.is_match(content) {
            return Some((
                true,
                "NEMESIS BLOCKED: Conteudo do heredoc adiciona dependencia proibida (styled-jsx).".to_string(),
                "prohibited-dependency".to_string(),
            ));
        }
    }

    // Detectar echo redirect: echo "..." > file ou echo "..." >> file
    let echo_redirect_regex = regex::Regex::new(
        r#"echo\s+["'](.+?)["']\s*(?:>>?)\s*([^\s;|&]+)"#
    ).unwrap();

    if let Some(caps) = echo_redirect_regex.captures(command) {
        let content = &caps[1];
        let target_file = &caps[2];

        if critical_file_patterns.iter().any(|p| p.is_match(target_file)) {
            return Some((
                true,
                format!(r#"NEMESIS BLOCKED: echo redirect para arquivo de configuracao critico: "{}"."#, target_file),
                "critical-config-file-protection".to_string(),
            ));
        }

        let strict_disable = Regex::new(r#""strict"\s*:\s*false"#).unwrap();
        let no_implicit_any = Regex::new(r#""noImplicitAny"\s*:\s*false"#).unwrap();

        if strict_disable.is_match(content) || no_implicit_any.is_match(content) {
            return Some((
                true,
                "NEMESIS BLOCKED: echo redirect contem desabilitacao de TypeScript strict mode.".to_string(),
                "typescript-strict-mode-required".to_string(),
            ));
        }
    }

    // Detectar printf redirect para arquivos de codigo
    let printf_regex = Regex::new(r"printf\s+.+.(?:>>?)\s*\S+\.(tsx?|jsx?|json)").unwrap();
    if printf_regex.is_match(command) {
        return Some((
            true,
            "NEMESIS BLOCKED: printf redirect para arquivo de codigo detectado. Use a ferramenta Write/Edit com aprovacao explicita.".to_string(),
            "file-creation-via-bash-blocked".to_string(),
        ));
    }

    // Detectar pipe | tee para arquivos criticos
    let tee_pipe_regex = regex::Regex::new(r"\|\s*tee\s+([^\s;|&]+\.(json|tsx?|jsx?))").unwrap();
    if let Some(caps) = tee_pipe_regex.captures(command) {
        let target_file = &caps[1];
        if critical_file_patterns.iter().any(|p| p.is_match(target_file)) {
            return Some((
                true,
                format!(r#"NEMESIS BLOCKED: pipe | tee para arquivo critico: "{}"."#, target_file),
                "critical-config-file-protection".to_string(),
            ));
        }
    }

    None
}

/// Validacao basica — sem falsos positivos
fn basic_validation(action: &Action) -> ValidationResult {
    let mut violations: Vec<String> = Vec::new();
    let mut suggestions: Vec<String> = Vec::new();

    // REGRAS 1-3: Validacao de edicao/criacao de arquivos
    if action.action_type == "edit" || action.action_type == "create" {
        let content = match &action.content {
            Some(c) => c,
            None => {
                return ValidationResult {
                    allowed: true,
                    reason: "Sem conteudo para validar".to_string(),
                    violated_rules: vec![],
                    severity: "info".to_string(),
                    suggestions: vec![],
                };
            }
        };

        // REGRA 1: CSS inline
        let css_inline = Regex::new(r#"style\s*=\s*\{\s*\{[^}]*\}\s*\}"#).unwrap();
        if css_inline.is_match(content) {
            violations.push("CSS inline detectado (style={{ }})".to_string());
            suggestions.push("Usar classes Tailwind no lugar de CSS inline".to_string());
        }

        // REGRA 2: uso de `any` explicito
        let any_pattern = Regex::new(r":\s*any\b").unwrap();
        if any_pattern.is_match(content) {
            violations.push("Uso de \"any\" detectado em tipagem".to_string());
            suggestions.push("Usar tipagem especifica ou \"unknown\" em vez de \"any\"".to_string());
        }

        // REGRA 3: useState/useEffect em componentes UI puros
        if is_ui_component(&action.target) {
            let hook_pattern = Regex::new(r"\b(useState|useEffect)\b").unwrap();
            if hook_pattern.is_match(content) {
                violations.push("Logica de estado/efeito diretamente em componente UI".to_string());
                suggestions.push("Extrair useState/useEffect para um hook dedicado em /hooks/ e importar no componente".to_string());
            }
        }

        let has_violations = !violations.is_empty();

        return ValidationResult {
            allowed: !has_violations,
            reason: if has_violations {
                format!("Violacoes detectadas: {}", violations.join("; "))
            } else {
                "Acao permitida".to_string()
            },
            violated_rules: violations,
            severity: if has_violations { "error".to_string() } else { "info".to_string() },
            suggestions,
        };
    }

    // REGRAS 4-6: Validacao de comandos bash
    if action.action_type == "bash" {
        let command = &action.target;

        // REGRA 6: Heredoc e redirects de arquivo
        if let Some((blocked, reason, rule)) = detect_file_creation_bypass(command) {
            if blocked {
                return ValidationResult {
                    allowed: false,
                    reason,
                    violated_rules: vec![rule],
                    severity: "error".to_string(),
                    suggestions: vec![
                        "Use a ferramenta Write ou Edit para criar arquivos com validacao de conteudo.".to_string(),
                        "Arquivos de configuracao criticos (tsconfig.json, package.json) nao podem ser sobrescritos via Bash.".to_string(),
                    ],
                };
            }
        }

        // REGRA 5: Atualizacao em massa de dependencias
        if let Some(blocked_match) = matches_mass_update_command(command) {
            return ValidationResult {
                allowed: false,
                reason: format!(r#"NEMESIS BLOCKED: Atualizacao em massa de dependencias bloqueada — "{}""#, blocked_match),
                violated_rules: vec!["mass-dependency-update-blocked".to_string()],
                severity: "error".to_string(),
                suggestions: vec![
                    "Atualizacoes em massa podem quebrar React, Next.js e TypeScript por incompatibilidade.".to_string(),
                    "Use atualizacao cirurgica: bun add [pacote]@[versao-minima-segura]".to_string(),
                ],
            };
        }

        // REGRA 4: Comandos bash destrutivos de sistema
        let destructive_commands = ["rm -rf /", "sudo rm", "curl | bash", "wget | bash", "eval $("];
        let has_destructive = destructive_commands.iter().any(|cmd| command.contains(cmd));

        if has_destructive {
            return ValidationResult {
                allowed: false,
                reason: "NEMESIS BLOCKED: Comando bash destrutivo de sistema detectado".to_string(),
                violated_rules: vec!["destructive-bash-command".to_string()],
                severity: "error".to_string(),
                suggestions: vec!["Evitar comandos destrutivos sem autorizacao explicita do usuario".to_string()],
            };
        }
    }

    ValidationResult {
        allowed: true,
        reason: "Acao permitida".to_string(),
        violated_rules: vec![],
        severity: "info".to_string(),
        suggestions: vec![],
    }
}

/// Verifica se o arquivo pode ser modificado pela IA.
fn is_file_allowed(file_path: &str) -> bool {
    if file_path.is_empty() {
        return true;
    }

    let normalized = file_path.replace('\\', "/").replacen("./", "", 1);

    // Arquivos sempre permitidos (planos de trabalho, nao codigo de enforcement)
    let always_allowed = [
        ".devin/plans/",
        ".devin/workflows/",
        ".nemesis/runtime/",
        ".nemesis/smart-components.json",
        ".nemesis/logs/",
    ];

    if always_allowed.iter().any(|allowed| normalized.contains(allowed)) {
        return true;
    }

    // Arquivos de infraestrutura critica — BLOQUEIO ABSOLUTO
    let absolutely_blocked = [
        ".nemesis/workflow-enforcement/",
        ".nemesis/hooks/",
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".openclaude/",
    ];

    if absolutely_blocked.iter().any(|blocked| normalized.contains(blocked)) {
        return false;
    }

    // Arquivos de configuracao e regras — bloqueados por padrao
    let critical_files = [
        ".devin/rules/",
        "package.json",
        "tsconfig.json",
        "tsconfig.base.json",
        ".eslintrc",
        "eslint.config",
        "next.config",
        "tailwind.config",
        "postcss.config",
        ".env",
        ".gitignore",
        "proxy.ts",
    ];

    let is_critical = critical_files.iter().any(|critical| {
        if critical.ends_with('/') {
            normalized.contains(critical)
        } else {
            let file_name = normalized.split('/').last().unwrap_or("");
            file_name == *critical || file_name.starts_with(critical)
        }
    });

    !is_critical
}

fn log_violation(action: &Action, result: &ValidationResult) {
    let log_entry = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "action": {
            "type": action.action_type,
            "target": action.target,
        },
        "violatedRules": result.violated_rules,
        "suggestions": result.suggestions,
    });
    println!("[NEMESIS] VIOLACAO REGISTRADA: {}", serde_json::to_string_pretty(&log_entry).unwrap_or_default());
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("[NEMESIS] Uso: pre-edit-hook <type> <target> [content_file]");
        std::process::exit(0); // FAIL-OPEN: chamada incorreta nao deve bloquear
    }

    let action_type = args[1].to_lowercase();
    let target = args[2].clone();
    let content_file = args.get(3).cloned();

    let content = match content_file {
        Some(file_path) => {
            if Path::new(&file_path).exists() {
                match fs::read_to_string(&file_path) {
                    Ok(content) => Some(content),
                    Err(err) => {
                        eprintln!("[NEMESIS] Erro ao ler arquivo de conteudo: {}", err);
                        std::process::exit(0); // FAIL-OPEN: erro de leitura nao e violacao de regra
                    }
                }
            } else {
                None
            }
        }
        None => None,
    };

    let action = Action {
        action_type,
        target,
        content,
    };

    println!("[NEMESIS] Analisando: {} em {}", action.action_type, action.target);

    if !is_file_allowed(&action.target) {
        println!("[NEMESIS BLOCKED] NEMESIS SEC - ACESSO NEGADO - ARQUIVO PROTEGIDO · {}", action.target);
        println!("[NEMESIS] Para modificar arquivos do enforcement engine, obtenha autorizacao explicita.");
        std::process::exit(2);
    }

    let result = basic_validation(&action);

    if result.allowed {
        println!("[NEMESIS] Acao permitida");
        if !result.suggestions.is_empty() {
            println!("[NEMESIS] Sugestoes: {}", result.suggestions.join("; "));
        }
        std::process::exit(0);
    } else {
        println!("[NEMESIS BLOCKED] {}", result.reason);
        println!("[NEMESIS] Regras violadas: {}", result.violated_rules.join(", "));
        println!("[NEMESIS] Como corrigir: {}", result.suggestions.join("; "));
        log_violation(&action, &result);
        std::process::exit(2);
    }
}
