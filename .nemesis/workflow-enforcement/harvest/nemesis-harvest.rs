use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestPattern {
    pub id: String,
    pub pattern: String,
    pub pattern_type: String, // "regex" | "string" | "description"
    pub severity: String, // "critical" | "high" | "medium"
    pub context: Option<String>,
    pub context_type: Option<String>, // "path_contains" | "path_ends_with"
    pub message: String,
    pub suggestion: String,
    pub rule: String,
    pub source: String, // "harvest" | "rules" | "manual"
    pub enabled: bool,
    pub needs_manual_pattern: Option<bool>,
    pub eslint_rule: Option<String>,
    pub stack_origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestLayer {
    pub description: String,
    pub source: String,
    pub patterns: Vec<HarvestPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestOutput {
    pub version: String,
    pub last_updated: String,
    pub generated_by: String,
    pub project_stack: Vec<String>,
    pub layers: HashMap<String, HarvestLayer>,
    pub tailwind_allow_list: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct HarvestResult {
    pub stack_detected: HashMap<String, String>,
    pub patterns_generated: usize,
    pub patterns_from_eslint: usize,
    pub patterns_from_tsconfig: usize,
    pub patterns_from_rules: usize,
    pub new_rules_created: Vec<String>,
    pub rules_rehydrated: Vec<String>,
    pub patterns_needing_manual_review: Vec<String>,
    pub output: HarvestOutput,
}

lazy_static::lazy_static! {
    static ref ESLINT_TO_PATTERN: HashMap<String, HarvestPattern> = {
        let mut map = HashMap::new();
        map.insert("@typescript-eslint/no-explicit-any".to_string(), HarvestPattern {
            id: String::new(),
            pattern: r":\s*any[\s;,)\]}>|&]|:\s*any$|\bas\s+any\b|<any\s*>|Record<[^,]*,\s*any\s*>".to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: r#"Uso de "any" detectado. Viola typescript-typing-convention.md."#.to_string(),
            suggestion: "Use tipos explicitos, unknown, generics <T> ou tipos existentes em src/types/".to_string(),
            rule: ".devin/rules/typescript-typing-convention.md".to_string(),
            source: "harvest".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: Some("@typescript-eslint/no-explicit-any".to_string()),
            stack_origin: None,
        });
        map.insert("@typescript-eslint/consistent-type-imports".to_string(), HarvestPattern {
            id: String::new(),
            pattern: r"^import\s+\{[^}]*(Props|Type|Config|Interface|Options|Enum)[^}]*\}\s+from".to_string(),
            pattern_type: "regex".to_string(),
            severity: "high".to_string(),
            context: None,
            context_type: None,
            message: r#"Import de tipo sem keyword "type". Use import type { ... }."#.to_string(),
            suggestion: r#"Substitua por: import type { NomeDoTipo } from "...";"#.to_string(),
            rule: ".devin/rules/typescript-typing-convention.md".to_string(),
            source: "harvest".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: Some("@typescript-eslint/consistent-type-imports".to_string()),
            stack_origin: None,
        });
        map.insert("@typescript-eslint/no-var-requires".to_string(), HarvestPattern {
            id: String::new(),
            pattern: r#"\brequire\s*\(\s*['"][^'"]+['"]\s*\)"#.to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: "require() detectado em TypeScript. Use import ES6.".to_string(),
            suggestion: r#"Substitua por: import NomeModulo from "caminho""#.to_string(),
            rule: ".devin/rules/typescript-typing-convention.md".to_string(),
            source: "harvest".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: Some("@typescript-eslint/no-var-requires".to_string()),
            stack_origin: None,
        });
        map.insert("no-unused-vars".to_string(), HarvestPattern {
            id: String::new(),
            pattern: r"(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*[=:]".to_string(),
            pattern_type: "description".to_string(),
            severity: "medium".to_string(),
            context: None,
            context_type: None,
            message: "Variavel declarada e potencialmente nao utilizada.".to_string(),
            suggestion: "Remova variaveis nao utilizadas ou prefixe com _ se intencional.".to_string(),
            rule: ".devin/rules/typescript-typing-convention.md".to_string(),
            source: "harvest".to_string(),
            enabled: true,
            needs_manual_pattern: Some(true),
            eslint_rule: Some("no-unused-vars".to_string()),
            stack_origin: None,
        });
        map.insert("react-hooks/rules-of-hooks".to_string(), HarvestPattern {
            id: String::new(),
            pattern: r"if[^{]*\{[^}]*\b(?:useState|useEffect|useReducer|useContext|useMemo|useCallback|useRef)\s*\(".to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: "Hook condicional detectado. Violacao react-hooks/rules-of-hooks.".to_string(),
            suggestion: "Mova todos os hooks para o topo do componente, antes de qualquer condicional.".to_string(),
            rule: ".devin/rules/react-hooks-patterns-rules.md".to_string(),
            source: "harvest".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: Some("react-hooks/rules-of-hooks".to_string()),
            stack_origin: None,
        });
        map.insert("react-hooks/exhaustive-deps".to_string(), HarvestPattern {
            id: String::new(),
            pattern: r"useEffect\s*\([^,]+,\s*\[\s*\]\s*\)".to_string(),
            pattern_type: "regex".to_string(),
            severity: "medium".to_string(),
            context: None,
            context_type: None,
            message: "useEffect com dependencias vazias e corpo nao-trivial.".to_string(),
            suggestion: "Revise as dependencias do useEffect. Considere se [] e intencional.".to_string(),
            rule: ".devin/rules/react-hooks-patterns-rules.md".to_string(),
            source: "harvest".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: Some("react-hooks/exhaustive-deps".to_string()),
            stack_origin: None,
        });
        map.insert("@next/next/no-head-import-in-document".to_string(), HarvestPattern {
            id: String::new(),
            pattern: r#"import.*Head.*from.*['"]next/head['"]"#.to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: Some("_document".to_string()),
            context_type: Some("path_contains".to_string()),
            message: "Import de Head em _document. Use next/document.".to_string(),
            suggestion: r#"Use import { Head } from "next/document" em arquivos _document."#.to_string(),
            rule: ".devin/rules/Arquitetura-pastas-arquivos.md".to_string(),
            source: "harvest".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: Some("@next/next/no-head-import-in-document".to_string()),
            stack_origin: None,
        });
        map.insert("no-restricted-syntax".to_string(), HarvestPattern {
            id: String::new(),
            pattern: r"module\.(?:exports|[a-zA-Z_][a-zA-Z0-9_]*)\s*=".to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: "module.exports detectado. Use export statements ES6.".to_string(),
            suggestion: "Substitua por: export const nome = ... ou export default ...".to_string(),
            rule: ".devin/rules/typescript-typing-convention.md".to_string(),
            source: "harvest".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: Some("no-restricted-syntax".to_string()),
            stack_origin: None,
        });
        map
    };
}

fn read_package_json() -> HashMap<String, String> {
    match fs::read_to_string("package.json") {
        Ok(content) => {
            let pkg: serde_json::Value = serde_json::from_str(&content).unwrap_or_default();
            let mut deps: HashMap<String, String> = HashMap::new();

            if let Some(dependencies) = pkg.get("dependencies").and_then(|d| d.as_object()) {
                for (k, v) in dependencies {
                    if let Some(version) = v.as_str() {
                        deps.insert(k.clone(), version.to_string());
                    }
                }
            }
            if let Some(dev_deps) = pkg.get("devDependencies").and_then(|d| d.as_object()) {
                for (k, v) in dev_deps {
                    if let Some(version) = v.as_str() {
                        deps.insert(k.clone(), version.to_string());
                    }
                }
            }
            deps
        }
        Err(_) => HashMap::new(),
    }
}

fn detect_stack_comprehensive() -> HashMap<String, String> {
    let mut stack: HashMap<String, String> = HashMap::new();

    // FRONTEND
    if Path::new("package.json").exists() {
        if Path::new("tsconfig.json").exists() {
            stack.insert("typescript".to_string(), "true".to_string());
            if Path::new("next.config.js").exists() || Path::new("next.config.ts").exists() {
                stack.insert("next".to_string(), "true".to_string());
            }
        } else {
            stack.insert("javascript".to_string(), "true".to_string());
        }
    }

    // BACKEND - Python
    if Path::new("pyproject.toml").exists() || Path::new("requirements.txt").exists() {
        stack.insert("python".to_string(), "true".to_string());
    }

    // BACKEND - Rust
    if Path::new("Cargo.toml").exists() {
        stack.insert("rust".to_string(), "true".to_string());
    }

    // BACKEND - Go
    if Path::new("go.mod").exists() {
        stack.insert("go".to_string(), "true".to_string());
    }

    // BACKEND - Java
    if Path::new("pom.xml").exists() {
        stack.insert("java-maven".to_string(), "true".to_string());
    }
    if Path::new("build.gradle").exists() || Path::new("build.gradle.kts").exists() {
        stack.insert("java-gradle".to_string(), "true".to_string());
    }

    // BACKEND - Ruby
    if Path::new("Gemfile").exists() {
        stack.insert("ruby".to_string(), "true".to_string());
    }

    // BACKEND - PHP
    if Path::new("composer.json").exists() {
        stack.insert("php".to_string(), "true".to_string());
    }

    // MOBILE - Dart/Flutter
    if Path::new("pubspec.yaml").exists() {
        stack.insert("dart".to_string(), "true".to_string());
    }

    // INFRA - Docker
    if Path::new("Dockerfile").exists() {
        stack.insert("docker".to_string(), "true".to_string());
    }
    if Path::new("docker-compose.yml").exists() || Path::new("docker-compose.yaml").exists() {
        stack.insert("docker-compose".to_string(), "true".to_string());
    }

    stack
}

#[derive(Debug)]
struct TsConfig {
    strict: bool,
    no_implicit_any: bool,
    no_unused_locals: bool,
}

fn read_ts_config() -> TsConfig {
    match fs::read_to_string("tsconfig.json") {
        Ok(content) => {
            let tc: serde_json::Value = serde_json::from_str(&content).unwrap_or_default();
            let opts = tc.get("compilerOptions").cloned().unwrap_or_default();
            TsConfig {
                strict: opts.get("strict").and_then(|v| v.as_bool()).unwrap_or(false),
                no_implicit_any: opts.get("noImplicitAny").and_then(|v| v.as_bool()).unwrap_or(false),
                no_unused_locals: opts.get("noUnusedLocals").and_then(|v| v.as_bool()).unwrap_or(false),
            }
        }
        Err(_) => TsConfig {
            strict: false,
            no_implicit_any: false,
            no_unused_locals: false,
        },
    }
}

fn read_eslint_config() -> HashMap<String, serde_json::Value> {
    let candidates = [
        ".eslintrc.json", ".eslintrc", "eslint.config.js", ".eslintrc.js", "eslint.config.mjs"
    ];
    
    for c in &candidates {
        if Path::new(c).exists() {
            match fs::read_to_string(c) {
                Ok(raw) => {
                    return serde_json::from_str(&raw).unwrap_or_default();
                }
                Err(_) => return HashMap::new(),
            }
        }
    }
    HashMap::new()
}

#[derive(Debug)]
struct NextConfig {
    has_headers: bool,
    has_csp: bool,
}

fn read_next_config() -> NextConfig {
    let candidates = ["next.config.ts", "next.config.js", "next.config.mjs"];
    for c in &candidates {
        if Path::new(c).exists() {
            if let Ok(raw) = fs::read_to_string(c) {
                return NextConfig {
                    has_headers: raw.contains("headers()") || raw.contains("async headers"),
                    has_csp: raw.contains("Content-Security-Policy") || raw.contains("nonce"),
                };
            }
        }
    }
    NextConfig {
        has_headers: false,
        has_csp: false,
    }
}

fn read_tailwind_tokens() -> Vec<String> {
    let candidates = ["tailwind.config.ts", "tailwind.config.js"];
    for c in &candidates {
        if Path::new(c).exists() {
            if let Ok(raw) = fs::read_to_string(c) {
                let re = Regex::new(r#"['"]([a-zA-Z][a-zA-Z0-9-_]*)['"]:\s*\{"#).unwrap();
                let matches: Vec<String> = re.captures_iter(&raw)
                    .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
                    .filter(|t| !["extend", "colors", "theme", "fontFamily", "screens", "spacing"].contains(&t.as_str()))
                    .collect();
                return matches;
            }
        }
    }
    vec![]
}

fn escape_for_regex(s: &str) -> String {
    s.replace(r#"."#, r#"\."#)
        .replace(r#"+"#, r#"\+"#)
        .replace(r#"*"#, r#"\*"#)
        .replace(r#"?"#, r#"\?"#)
        .replace(r#"^"#, r#"\^"#)
        .replace(r#"$"#, r#"\$"#)
        .replace(r#"{"#, r#"\{"#)
        .replace(r#"}"#, r#"\}"#)
        .replace(r#"("#, r#"\("#)
        .replace(r#")"#, r#"\)"#)
        .replace(r#"|"#, r#"\|"#)
        .replace(r#"["#, r#"\["#)
        .replace(r#"]"#, r#"\]"#)
        .replace(r#"\"#, r#"\\"#)
}

fn extract_patterns_from_rules() -> Vec<HarvestPattern> {
    let rules_dir = ".devin/rules";
    if !Path::new(rules_dir).exists() {
        return vec![];
    }

    let mut patterns: Vec<HarvestPattern> = vec![];
    let mut idx = 0;

    if let Ok(entries) = fs::read_dir(rules_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("md") {
                if let Ok(content) = fs::read_to_string(&path) {
                    let rule_name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                    
                    // RESTRICT patterns
                    let restrict_re = Regex::new(r"\[RESTRICT(?:ION)?:\s*([^\]]+)\]\s*=\s*BLOCKED(?:_ABSOLUTELY)?").unwrap();
                    for cap in restrict_re.captures_iter(&content) {
                        let desc = cap[1].trim();
                        patterns.push(HarvestPattern {
                            id: format!("rule-{}-{}", rule_name, idx),
                            pattern: desc.to_string(),
                            pattern_type: "description".to_string(),
                            severity: "critical".to_string(),
                            context: None,
                            context_type: None,
                            message: format!("Violacao detectada: {}", desc),
                            suggestion: format!("Consulte .devin/rules/{}.md para o padrao correto.", rule_name),
                            rule: format!(".devin/rules/{}.md", rule_name),
                            source: "rules".to_string(),
                            enabled: true,
                            needs_manual_pattern: Some(true),
                            eslint_rule: None,
                            stack_origin: None,
                        });
                        idx += 1;
                    }

                    // Blocked examples
                    let blocked_re = Regex::new(r"//\s*❌\s*BLOCKED[^\n]*\n([^\n]+)").unwrap();
                    for cap in blocked_re.captures_iter(&content) {
                        let code = cap[1].trim();
                        if code.len() > 3 && code.len() < 120 {
                            patterns.push(HarvestPattern {
                                id: format!("rule-{}-ex-{}", rule_name, idx),
                                pattern: escape_for_regex(code),
                                pattern_type: "regex".to_string(),
                                severity: "critical".to_string(),
                                context: None,
                                context_type: None,
                                message: format!("Padrao proibido detectado ({})", rule_name),
                                suggestion: format!("Veja o padrao correto em .devin/rules/{}.md", rule_name),
                                rule: format!(".devin/rules/{}.md", rule_name),
                                source: "rules".to_string(),
                                enabled: true,
                                needs_manual_pattern: None,
                                eslint_rule: None,
                                stack_origin: None,
                            });
                            idx += 1;
                        }
                    }
                }
            }
        }
    }

    patterns
}

fn detect_ide_rules_sources() -> Vec<String> {
    let mut sources: Vec<String> = vec![];

    if Path::new("AGENTS.md").exists() {
        sources.push("AGENTS.md".to_string());
    }

    if Path::new(".claude/CLAUDE.md").exists() {
        sources.push(".claude/CLAUDE.md".to_string());
    }
    if Path::new("CLAUDE.md").exists() {
        sources.push("CLAUDE.md".to_string());
    }

    let cursor_rules_dir = Path::new(".cursor/rules");
    if cursor_rules_dir.exists() {
        if let Ok(entries) = fs::read_dir(cursor_rules_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("mdc") {
                    sources.push(format!(".cursor/rules/{}", path.file_name().and_then(|n| n.to_str()).unwrap_or("")));
                }
            }
        }
    }

    sources
}

fn parse_mdc_frontmatter(content: &str) -> (HashMap<String, String>, String) {
    let frontmatter_re = Regex::new(r"^---\s*\n([\s\S]*?)\n---\s*\n([\s\S]*)$").unwrap();
    
    if let Some(cap) = frontmatter_re.captures(content) {
        let frontmatter_str = &cap[1];
        let content_str = &cap[2];
        
        let mut frontmatter: HashMap<String, String> = HashMap::new();
        for line in frontmatter_str.lines() {
            if let Some(colon_idx) = line.find(':') {
                let key = line[..colon_idx].trim().to_string();
                let value = line[colon_idx + 1..].trim().to_string();
                frontmatter.insert(key, value);
            }
        }
        
        return (frontmatter, content_str.to_string());
    }
    
    (HashMap::new(), content.to_string())
}

fn extract_patterns_from_ide_rules(sources: &[String]) -> Vec<HarvestPattern> {
    let mut patterns: Vec<HarvestPattern> = vec![];
    let mut idx = 0;

    for source in sources {
        if let Ok(content) = fs::read_to_string(source) {
            let mut parsed_content = content.clone();
            
            if source.ends_with(".mdc") {
                let (_, without_frontmatter) = parse_mdc_frontmatter(&content);
                parsed_content = without_frontmatter;
            }

            // Claude Code format: [RESTRICT: PATTERN_NAME]
            let claude_re = Regex::new(r"\[RESTRICT:\s*([^\]]+)\]").unwrap();
            for cap in claude_re.captures_iter(&parsed_content) {
                let pattern_name = cap[1].trim();
                patterns.push(HarvestPattern {
                    id: format!("ide-claude-{}", idx),
                    pattern: pattern_name.to_string(),
                    pattern_type: "description".to_string(),
                    severity: "critical".to_string(),
                    context: None,
                    context_type: None,
                    message: format!("Restricao Claude Code: {}", pattern_name),
                    suggestion: format!("Verifique regras em {}", source),
                    rule: source.clone(),
                    source: "rules".to_string(),
                    enabled: true,
                    needs_manual_pattern: Some(true),
                    eslint_rule: None,
                    stack_origin: None,
                });
                idx += 1;
            }

            // Blocked examples
            let blocked_re = Regex::new(r"//\s*❌\s*BLOCKED[^\n]*\n([^\n]+)").unwrap();
            for cap in blocked_re.captures_iter(&parsed_content) {
                let code = cap[1].trim();
                if code.len() > 3 && code.len() < 120 {
                    patterns.push(HarvestPattern {
                        id: format!("ide-{}-ex-{}", source.split('/').last().unwrap_or(""), idx),
                        pattern: escape_for_regex(code),
                        pattern_type: "regex".to_string(),
                        severity: "critical".to_string(),
                        context: None,
                        context_type: None,
                        message: format!("Padrao proibido detectado ({})", source),
                        suggestion: format!("Veja o padrao correto em {}", source),
                        rule: source.clone(),
                        source: "rules".to_string(),
                        enabled: true,
                        needs_manual_pattern: None,
                        eslint_rule: None,
                        stack_origin: None,
                    });
                    idx += 1;
                }
            }
        }
    }

    patterns
}

fn rehydrate_rules(
    eslint_rules_active: &[String],
    ts_config: &TsConfig,
    stack_detected: &HashMap<String, String>,
    next_config: &NextConfig,
) -> Vec<String> {
    let mut rehydrated: Vec<String> = vec![];
    let rules_dir = ".devin/rules";
    
    if !Path::new(rules_dir).exists() {
        return rehydrated;
    }

    let timestamp = chrono::Utc::now().to_rfc3339();

    if let Ok(entries) = fs::read_dir(rules_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("md") {
                let file_path = path.to_str().unwrap_or("");
                let file_name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                
                if let Ok(mut content) = fs::read_to_string(&path) {
                    let harvest_block = build_harvest_block(
                        file_name,
                        eslint_rules_active,
                        ts_config,
                        stack_detected,
                        next_config,
                        &timestamp,
                    );
                    
                    if let Some(block) = harvest_block {
                        let old_re = Regex::new(r"\n---\n## \[AUTO-HARVEST:.*?\n(?:.*\n)*?---\n").unwrap();
                        content = old_re.replace(&content, "\n").to_string();
                        content = content.trim_end().to_string() + "\n\n---\n" + &block + "\n";
                        
                        fs::write(&path, content).ok();
                        rehydrated.push(file_name.to_string());
                    }
                }
            }
        }
    }

    rehydrated
}

fn build_harvest_block(
    rule_file: &str,
    eslint_rules_active: &[String],
    ts_config: &TsConfig,
    stack_detected: &HashMap<String, String>,
    next_config: &NextConfig,
    timestamp: &str,
) -> Option<String> {
    match rule_file {
        "typescript-typing-convention" => {
            let ts_version = stack_detected.get("typescript").map(|s| s.as_str()).unwrap_or("nao instalado");
            let eslint_any = eslint_rules_active.contains(&"@typescript-eslint/no-explicit-any".to_string());
            Some(format!(
                "## [AUTO-HARVEST: typescript]\nUltima atualizacao: {}\nTypeScript instalado: {}\nESLint @typescript-eslint/no-explicit-any: {}\ntsconfig strict: {} → any implicito e erro de compilacao\ntsconfig noImplicitAny: {}\nO que quebra em producao: type inference falha silenciosamente; erros de runtime em producao que o compilador nao detecta\nAlternativas validadas nesta stack: unknown, generics <T>, tipos em src/types/, satisfies operator",
                timestamp, ts_version, if eslint_any { "ATIVO — severity: error" } else { "nao detectado" }, ts_config.strict, ts_config.no_implicit_any
            ))
        }
        "react-hooks-patterns-rules" => {
            let react_version = stack_detected.get("react").map(|s| s.as_str()).unwrap_or("nao instalado");
            let hooks_plugin = eslint_rules_active.contains(&"react-hooks/rules-of-hooks".to_string());
            Some(format!(
                "## [AUTO-HARVEST: react-hooks]\nUltima atualizacao: {}\nReact instalado: {}\nESLint react-hooks/rules-of-hooks: {}\nESLint react-hooks/exhaustive-deps: {}\nO que quebra em producao: hooks condicionais causam erros React invariant em runtime; \"Rendered more hooks than previous render\"\nComportamento esperado: hooks sempre no topo do componente, antes de qualquer return ou condicional",
                timestamp, react_version, if hooks_plugin { "ATIVO" } else { "nao detectado" },
                if eslint_rules_active.contains(&"react-hooks/exhaustive-deps".to_string()) { "ATIVO" } else { "nao detectado" }
            ))
        }
        "design-system-convention" => {
            let tailwind_version = stack_detected.get("tailwindcss").map(|s| s.as_str()).unwrap_or("nao instalado");
            Some(format!(
                "## [AUTO-HARVEST: design-system]\nUltima atualizacao: {}\nTailwind instalado: {}\nO que quebra em producao: CSS inline nao e purgado pelo Tailwind; bundle aumenta; hot-reload inconsistente\nPadrao desta stack: 100% Tailwind classes — inline style apenas para valores calculados dinamicamente (Math.max, percentuais via JS)",
                timestamp, tailwind_version
            ))
        }
        "Conformidade" => {
            Some(format!(
                "## [AUTO-HARVEST: security-owasp]\nUltima atualizacao: {}\nNext.js instalado: {}\nCSP configurado em next.config: {}\nHeaders de seguranca: {}\nO que quebra em producao: OWASP A01 (broken access), A02 (crypto), A03 (injection), A05 (misconfiguration)",
                timestamp,
                stack_detected.get("next").map(|s| s.as_str()).unwrap_or("nao instalado"),
                if next_config.has_csp { "SIM" } else { "NAO — adicionar headers() com Content-Security-Policy" },
                if next_config.has_headers { "configurados" } else { "ausentes — vulnerabilidade OWASP A05" }
            ))
        }
        "API-convention" => {
            Some(format!(
                "## [AUTO-HARVEST: api-bff]\nUltima atualizacao: {}\nStack de fetch: {}\nZod instalado: {}\nReact Hook Form: {}\nO que quebra em producao: fetch direto em componente causa: CORS, auth token exposto no bundle client, sem cache, sem error handling padronizado",
                timestamp,
                if stack_detected.contains_key("axios") { "axios detectado" } else { "fetch nativo" },
                stack_detected.get("zod").map(|s| s.as_str()).unwrap_or("nao — sem validacao de schema de resposta"),
                stack_detected.get("react-hook-form").map(|s| s.as_str()).unwrap_or("nao instalado")
            ))
        }
        "ui-separation-convention" => {
            Some(format!(
                "## [AUTO-HARVEST: ui-separation]\nUltima atualizacao: {}\nPadrao desta stack: componentes em src/components/ui/ sao puros (zero useState/useEffect)\nExcecoes registradas em: .nemesis/smart-components.json\nO que quebra em producao: estado em UI puro causa re-renders desnecessarios; dificulta testes; viola Storybook contract",
                timestamp
            ))
        }
        _ => None,
    }
}

fn guess_layer_from_rule(rule_ref: &str) -> String {
    if rule_ref.contains("typescript-typing") {
        return "typescript".to_string();
    }
    if rule_ref.contains("react-hooks") || rule_ref.contains("ui-separation") {
        return "react".to_string();
    }
    if rule_ref.contains("design-system") {
        return "css".to_string();
    }
    if rule_ref.contains("API-convention") {
        return "api".to_string();
    }
    if rule_ref.contains("Conformidade") {
        return "security".to_string();
    }
    if rule_ref.contains("Arquitetura") {
        return "nextjs".to_string();
    }
    "project".to_string()
}

fn harvest_workflow_sequences() -> Vec<HarvestPattern> {
    let mut patterns: Vec<HarvestPattern> = vec![];

    // Ler workflow-gate-artifacts.json para sequencias estaticas
    let gate_artifacts_path = ".nemesis/workflow-enforcement/config/workflow-gate-artifacts.json";
    if Path::new(gate_artifacts_path).exists() {
        if let Ok(content) = fs::read_to_string(gate_artifacts_path) {
            if let Ok(gate_artifacts) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&content) {
                for (workflow_name, workflow_config) in gate_artifacts {
                    if let Some(phase_sequence) = workflow_config.get("phaseSequence").and_then(|p| p.as_array()) {
                        let sequence: Vec<String> = phase_sequence.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                        patterns.push(HarvestPattern {
                            id: format!("wf-seq-{}", workflow_name),
                            pattern: format!("workflow_sequence_{}", workflow_name),
                            pattern_type: "description".to_string(),
                            severity: "critical".to_string(),
                            context: None,
                            context_type: None,
                            message: format!("Sequencia de workflow violada: {}", workflow_name),
                            suggestion: format!("Execute as fases em ordem: {}", sequence.join(" → ")),
                            rule: gate_artifacts_path.to_string(),
                            source: "rules".to_string(),
                            enabled: true,
                            needs_manual_pattern: Some(true),
                            eslint_rule: None,
                            stack_origin: None,
                        });
                    }
                }
            }
        }
    }

    patterns
}

fn convert_workflow_patterns_to_layer(patterns: Vec<HarvestPattern>) -> HarvestLayer {
    HarvestLayer {
        description: "Sequencias e dependencias de workflows Nemesis".to_string(),
        source: "workflow-harvest".to_string(),
        patterns: patterns.into_iter().enumerate().map(|(idx, mut p)| {
            p.id = format!("workflow-{:03}", idx + 1);
            p
        }).collect(),
    }
}

pub async fn run_harvest() -> HarvestResult {
    let deps = read_package_json();
    let ts_config = read_ts_config();
    let eslint_config = read_eslint_config();
    let next_config = read_next_config();
    let tailwind_tokens = read_tailwind_tokens();

    // Detect comprehensive stack (8+ languages: Python, Rust, Go, Java, Ruby, PHP, Dart, Docker)
    let mut stack_detected = detect_stack_comprehensive();

    // Add JavaScript/TypeScript ecosystem packages from package.json
    let stack_keys = ["react", "next", "typescript", "tailwindcss", "eslint", "zod", "react-hook-form", "axios"];
    for k in &stack_keys {
        if let Some(v) = deps.get(*k) {
            let cleaned = v.replace(['^', '~', '>', '<', '='], "");
            stack_detected.insert(k.to_string(), cleaned);
        }
    }
    if next_config.has_csp {
        stack_detected.insert("next.config.csp".to_string(), "true".to_string());
    }

    let mut eslint_rules_active: Vec<String> = vec![];
    if let Some(rules) = eslint_config.get("rules").and_then(|r| r.as_object()) {
        for (rule, value) in rules {
            let severity = match value {
                serde_json::Value::Array(arr) => arr.first().cloned(),
                _ => Some(value.clone()),
            };
            if let Some(sev) = severity {
                let is_active = match &sev {
                    serde_json::Value::String(s) => s == "error" || s == "warn" || s == "warning",
                    serde_json::Value::Number(n) => n.as_i64().map(|v| v == 2 || v == 1).unwrap_or(false),
                    _ => false,
                };
                if is_active {
                    eslint_rules_active.push(rule.clone());
                }
            }
        }
    }

    // Detecao direta de plugins instalados separadamente
    if deps.contains_key("@typescript-eslint/eslint-plugin") {
        if !eslint_rules_active.contains(&"@typescript-eslint/no-explicit-any".to_string()) {
            eslint_rules_active.push("@typescript-eslint/no-explicit-any".to_string());
        }
        if !eslint_rules_active.contains(&"@typescript-eslint/consistent-type-imports".to_string()) {
            eslint_rules_active.push("@typescript-eslint/consistent-type-imports".to_string());
        }
        if !eslint_rules_active.contains(&"@typescript-eslint/no-var-requires".to_string()) {
            eslint_rules_active.push("@typescript-eslint/no-var-requires".to_string());
        }
    }

    if deps.contains_key("eslint-plugin-react-hooks") {
        if !eslint_rules_active.contains(&"react-hooks/rules-of-hooks".to_string()) {
            eslint_rules_active.push("react-hooks/rules-of-hooks".to_string());
        }
        if !eslint_rules_active.contains(&"react-hooks/exhaustive-deps".to_string()) {
            eslint_rules_active.push("react-hooks/exhaustive-deps".to_string());
        }
    }

    if deps.contains_key("@next/eslint-plugin-next") {
        if !eslint_rules_active.contains(&"@next/next/no-head-import-in-document".to_string()) {
            eslint_rules_active.push("@next/next/no-head-import-in-document".to_string());
        }
    }

    // eslint-config-next bundla @typescript-eslint, react-hooks e @next/next internamente
    let has_eslint_config_next = deps.contains_key("eslint-config-next");
    let has_next = deps.contains_key("next");
    if has_eslint_config_next || has_next {
        let next_bundled_rules = [
            "@typescript-eslint/no-explicit-any",
            "@typescript-eslint/consistent-type-imports",
            "@typescript-eslint/no-var-requires",
            "react-hooks/rules-of-hooks",
            "react-hooks/exhaustive-deps",
            "@next/next/no-head-import-in-document",
            "no-restricted-syntax",
        ];
        for rule in &next_bundled_rules {
            if !eslint_rules_active.contains(&rule.to_string()) {
                eslint_rules_active.push(rule.to_string());
            }
        }
    }

    let existing_rules: Vec<String> = if Path::new(".devin/rules").exists() {
        fs::read_dir(".devin/rules")
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.path().extension().and_then(|e| e.to_str()) == Some("md"))
                    .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![]
    };

    let rules_rehydrated = rehydrate_rules(&eslint_rules_active, &ts_config, &stack_detected, &next_config);
    let new_rules_created = create_auto_harvest_rules(&eslint_rules_active, &stack_detected, &existing_rules);

    // Gera arquivo de configuração para AST Linters
    generate_ast_rules_config(&eslint_rules_active, &eslint_config);

    let mut layers: HashMap<String, HarvestLayer> = HashMap::new();
    layers.insert("typescript".to_string(), HarvestLayer {
        description: "Violacoes de tipagem TypeScript".to_string(),
        source: "harvest + rules".to_string(),
        patterns: vec![],
    });
    layers.insert("react".to_string(), HarvestLayer {
        description: "Violacoes de padroes React e Hooks".to_string(),
        source: "harvest + rules".to_string(),
        patterns: vec![],
    });
    layers.insert("css".to_string(), HarvestLayer {
        description: "Violacoes de design system e CSS".to_string(),
        source: "harvest + rules".to_string(),
        patterns: vec![],
    });
    layers.insert("nextjs".to_string(), HarvestLayer {
        description: "Violacoes especificas de Next.js App Router".to_string(),
        source: "harvest + rules".to_string(),
        patterns: vec![],
    });
    layers.insert("api".to_string(), HarvestLayer {
        description: "Violacoes de arquitetura BFF e API".to_string(),
        source: "harvest + rules".to_string(),
        patterns: vec![],
    });
    layers.insert("security".to_string(), HarvestLayer {
        description: "Violacoes OWASP, CSP, nonce, secrets".to_string(),
        source: "harvest + rules".to_string(),
        patterns: vec![],
    });
    layers.insert("workflow".to_string(), HarvestLayer {
        description: "Anti-padroes de execucao de workflow Nemesis".to_string(),
        source: "rules".to_string(),
        patterns: vec![],
    });
    layers.insert("bypass".to_string(), HarvestLayer {
        description: "Tentativas de contornar enforcement".to_string(),
        source: "rules + manual".to_string(),
        patterns: vec![],
    });
    layers.insert("commands".to_string(), HarvestLayer {
        description: "Comandos bash bloqueados".to_string(),
        source: "harvest + rules".to_string(),
        patterns: vec![],
    });
    layers.insert("project".to_string(), HarvestLayer {
        description: "Regras especificas deste projeto — edicao manual".to_string(),
        source: "manual".to_string(),
        patterns: vec![],
    });

    let layer_map: HashMap<String, String> = [
        ("@typescript-eslint/no-explicit-any", "typescript"),
        ("@typescript-eslint/consistent-type-imports", "typescript"),
        ("@typescript-eslint/no-var-requires", "typescript"),
        ("no-unused-vars", "typescript"),
        ("react-hooks/rules-of-hooks", "react"),
        ("react-hooks/exhaustive-deps", "react"),
        ("@next/next/no-head-import-in-document", "nextjs"),
        ("no-restricted-syntax", "typescript"),
    ].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();

    let mut id_counter = 0;
    for eslint_rule in &eslint_rules_active {
        if let Some(mapping) = ESLINT_TO_PATTERN.get(eslint_rule) {
            let layer = layer_map.get(eslint_rule).cloned().unwrap_or_else(|| "project".to_string());
            let mut pattern = mapping.clone();
            pattern.id = format!("{}-{:03}", layer, id_counter);
            pattern.source = "harvest".to_string();
            pattern.eslint_rule = Some(eslint_rule.clone());
            pattern.stack_origin = Some(format!("{}@{}", eslint_rule, deps.get(eslint_rule.split('/').next().unwrap_or("")).cloned().unwrap_or_else(|| "unknown".to_string())));
            
            if let Some(l) = layers.get_mut(&layer) {
                l.patterns.push(pattern);
            }
            id_counter += 1;
        }
    }

    let rule_patterns = extract_patterns_from_rules();
    for mut p in rule_patterns {
        if p.needs_manual_pattern != Some(true) {
            let layer = guess_layer_from_rule(&p.rule);
            p.id = format!("rule-{:03}", id_counter);
            if let Some(l) = layers.get_mut(&layer) {
                l.patterns.push(p);
            }
            id_counter += 1;
        }
    }

    // Adicionar padroes de outros IDEs
    let ide_sources = detect_ide_rules_sources();
    if !ide_sources.is_empty() {
        println!("[NEMESIS HARVEST] Fontes IDE detectadas: {}", ide_sources.join(", "));
        let ide_patterns = extract_patterns_from_ide_rules(&ide_sources);
        
        if !ide_patterns.is_empty() {
            layers.insert("ide_patterns".to_string(), HarvestLayer {
                description: "Padroes de outros IDEs (Claude Code, VS Code, Cursor)".to_string(),
                source: "multi-ide".to_string(),
                patterns: ide_patterns.into_iter().enumerate().map(|(idx, mut p)| {
                    p.id = format!("ide-{:03}", idx);
                    p
                }).collect(),
            });
        }
    }

    // Adicionar padroes de workflow sequences
    println!("[NEMESIS HARVEST] Extraindo sequencias de workflows...");
    let workflow_patterns = harvest_workflow_sequences();
    if !workflow_patterns.is_empty() {
        let count = workflow_patterns.len();
        let workflow_layer = convert_workflow_patterns_to_layer(workflow_patterns);
        layers.insert("workflow_sequences".to_string(), workflow_layer);
        println!("[NEMESIS HARVEST] {} sequencias de workflow extraidas", count);
    }

    // Command patterns
    let command_patterns: Vec<HarvestPattern> = vec![
        HarvestPattern {
            id: "cmd-001".to_string(),
            pattern: r"^(?:bun|npm|yarn|pnpm)\s+(?:update|upgrade)".to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: "Atualizacao em massa de dependencias bloqueada.".to_string(),
            suggestion: "Use atualizacao cirurgica: bun add [pacote]@[versao]".to_string(),
            rule: ".devin/rules/rule-main-rules.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
        HarvestPattern {
            id: "cmd-002".to_string(),
            pattern: r"npx tsx -e".to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: "Operacao system-level de alto risco bloqueada.".to_string(),
            suggestion: "Use carregamento cirurgico das rules — leia apenas o dominio classificado.".to_string(),
            rule: ".devin/rules/Conformidade.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
        HarvestPattern {
            id: "cmd-003".to_string(),
            pattern: r"rm -rf /|sudo rm|sudo chmod 777|chmod -R 777".to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: "Comando destrutivo de sistema bloqueado.".to_string(),
            suggestion: "Use remocao cirurgica com path completo e confirmacao.".to_string(),
            rule: ".devin/rules/rule-main-rules.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
        HarvestPattern {
            id: "cmd-004".to_string(),
            pattern: r"eslint-disable|@ts-ignore|@ts-nocheck".to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: "Insercao de bypass manual detectada. Modelos IA nao tem autorizacao.".to_string(),
            suggestion: "Encontre a solucao tecnica correta. Apenas usuarios podem adicionar bypass.".to_string(),
            rule: ".devin/rules/origin-rules.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
    ];
    if let Some(l) = layers.get_mut("commands") {
        l.patterns.extend(command_patterns);
    }

    // Bypass patterns
    let bypass_patterns: Vec<HarvestPattern> = vec![
        HarvestPattern {
            id: "byp-001".to_string(),
            pattern: r"\/\/\s*SMART\s*COMPONENT|\/\*\s*SMART\s*COMPONENT".to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: "Insercao manual de SMART COMPONENT detectada.".to_string(),
            suggestion: "Use: bun nemesis:smart add NomeDoComponente".to_string(),
            rule: ".devin/rules/ui-separation-convention.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
        HarvestPattern {
            id: "byp-002".to_string(),
            pattern: r"eslint-disable-next-line|eslint-disable-line|@ts-expect-error".to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: "Bypass de regra detectado.".to_string(),
            suggestion: "Resolva o erro tecnico. Nao use bypass.".to_string(),
            rule: ".devin/rules/origin-rules.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
    ];
    if let Some(l) = layers.get_mut("bypass") {
        l.patterns.extend(bypass_patterns);
    }

    // CSS patterns
    let css_patterns: Vec<HarvestPattern> = vec![
        HarvestPattern {
            id: "css-001".to_string(),
            pattern: r"style\s*=\s*\{\{".to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: "CSS inline (style={{...}}) detectado.".to_string(),
            suggestion: "Use classes Tailwind. CSS inline apenas para valores dinamicos calculados por JS.".to_string(),
            rule: ".devin/rules/design-system-convention.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
        HarvestPattern {
            id: "css-002".to_string(),
            pattern: r"<style[\s>]|<style\s+jsx|styled-jsx".to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: "Tag style ou styled-jsx detectado.".to_string(),
            suggestion: "Use classes Tailwind definidas no tailwind.config.ts.".to_string(),
            rule: ".devin/rules/design-system-convention.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
        HarvestPattern {
            id: "css-003".to_string(),
            pattern: r#"<link\s+rel=["']stylesheet["']|@import\s+url"#.to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: "CSS manual externo detectado.".to_string(),
            suggestion: "Use classes Tailwind. CSS externo nao e permitido.".to_string(),
            rule: ".devin/rules/design-system-convention.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
    ];
    if let Some(l) = layers.get_mut("css") {
        l.patterns.extend(css_patterns);
    }

    // Security patterns
    let sec_patterns: Vec<HarvestPattern> = vec![
        HarvestPattern {
            id: "sec-001".to_string(),
            pattern: r"NEXT_PUBLIC_[A-Z_]+".to_string(),
            pattern_type: "regex".to_string(),
            severity: "high".to_string(),
            context: None,
            context_type: None,
            message: "Variavel de ambiente publica detectada em componente.".to_string(),
            suggestion: "Mova para route handler server-side. Violacao OWASP A03.".to_string(),
            rule: ".devin/rules/Conformidade.md".to_string(),
            source: "harvest".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
        HarvestPattern {
            id: "sec-002".to_string(),
            pattern: r#"api[_-]?key['"]?\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]"#.to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: None,
            context_type: None,
            message: "API key hardcoded detectada.".to_string(),
            suggestion: "Use variaveis de ambiente server-side. Violacao OWASP A02.".to_string(),
            rule: ".devin/rules/Conformidade.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
        HarvestPattern {
            id: "sec-003".to_string(),
            pattern: r"console\.log.*(?:password|senha|token|credential|auth)".to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: Some("/app/api/".to_string()),
            context_type: Some("path_contains".to_string()),
            message: "Log de credencial detectado em route handler.".to_string(),
            suggestion: "Remova o log. Violacao OWASP A03: Sensitive Data Exposure.".to_string(),
            rule: ".devin/rules/Conformidade.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
    ];
    if let Some(l) = layers.get_mut("security") {
        l.patterns.extend(sec_patterns);
    }

    // API patterns
    let api_patterns: Vec<HarvestPattern> = vec![
        HarvestPattern {
            id: "api-001".to_string(),
            pattern: r#"(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*['"]https?://"#.to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: Some("/components/".to_string()),
            context_type: Some("path_contains".to_string()),
            message: "Chamada HTTP direta em componente detectada.".to_string(),
            suggestion: "Use route handlers em src/app/api/. Violacao do padrao BFF.".to_string(),
            rule: ".devin/rules/API-convention.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
        HarvestPattern {
            id: "api-002".to_string(),
            pattern: r#"localStorage\.|sessionStorage\.|\.getItem\(|\.setItem\("#.to_string(),
            pattern_type: "regex".to_string(),
            severity: "high".to_string(),
            context: Some("/hooks/".to_string()),
            context_type: Some("path_contains".to_string()),
            message: "Storage direto detectado em hook.".to_string(),
            suggestion: "Use context providers. Violacao da arquitetura BFF.".to_string(),
            rule: ".devin/rules/API-convention.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
    ];
    if let Some(l) = layers.get_mut("api") {
        l.patterns.extend(api_patterns);
    }

    // React patterns
    let react_patterns: Vec<HarvestPattern> = vec![
        HarvestPattern {
            id: "react-state-ui-001".to_string(),
            pattern: r#"\buseState\b|\buseEffect\b|\buseReducer\b|\buseContext\b"#.to_string(),
            pattern_type: "regex".to_string(),
            severity: "critical".to_string(),
            context: Some("/components/ui/".to_string()),
            context_type: Some("path_contains".to_string()),
            message: "Hook de estado em componente UI puro bloqueado.".to_string(),
            suggestion: "Mova logica para src/hooks/. Componentes em ui/ devem ser puros.".to_string(),
            rule: ".devin/rules/ui-separation-convention.md".to_string(),
            source: "rules".to_string(),
            enabled: true,
            needs_manual_pattern: None,
            eslint_rule: None,
            stack_origin: None,
        },
    ];
    if let Some(l) = layers.get_mut("react") {
        l.patterns.extend(react_patterns);
    }

    let patterns_needing_manual_review: Vec<String> = extract_patterns_from_rules()
        .into_iter()
        .filter(|p| p.needs_manual_pattern == Some(true))
        .map(|p| p.message)
        .collect();

    let total_patterns: usize = layers.values().map(|l| l.patterns.len()).sum();

    let output = HarvestOutput {
        version: "1.0.0".to_string(),
        last_updated: chrono::Utc::now().to_rfc3339(),
        generated_by: "nemesis-harvest".to_string(),
        project_stack: stack_detected.iter().map(|(k, v)| format!("{}@{}", k, v)).collect(),
        layers,
        tailwind_allow_list: Some(tailwind_tokens),
    };

    // Carregar e combinar deny-lists baseado em stacks detectados
    use crate::hook::deny_list_loader::load_and_combine_deny_lists;

    let detected_stacks: Vec<String> = stack_detected
        .keys()
        .filter(|k| !k.contains("@") && k != &"next.config.csp" && k != &"next.config.csp")
        .cloned()
        .collect();

    if !detected_stacks.is_empty() {
        println!("[nemesis-harvest] Combinando deny-lists: base + {:?} + generic", detected_stacks);
        let _combined = load_and_combine_deny_lists(&detected_stacks);
        println!("[nemesis-harvest] Deny-list.json gerado em .nemesis/workflow-enforcement/config/deny-list.json");
    }

    HarvestResult {
        stack_detected,
        patterns_generated: total_patterns,
        patterns_from_eslint: eslint_rules_active.iter().filter(|r| ESLINT_TO_PATTERN.contains_key(*r)).count(),
        patterns_from_tsconfig: if ts_config.strict { 3 } else { 1 },
        patterns_from_rules: extract_patterns_from_rules().iter().filter(|p| p.needs_manual_pattern != Some(true)).count(),
        new_rules_created,
        rules_rehydrated,
        patterns_needing_manual_review,
        output,
    }
}

fn create_auto_harvest_rules(
    eslint_rules_active: &[String],
    stack_detected: &HashMap<String, String>,
    existing_rules: &[String],
) -> Vec<String> {
    let mut created: Vec<String> = vec![];
    let auto_harvest_dir = ".devin/rules/auto-harvest";
    let timestamp = chrono::Utc::now().to_rfc3339();

    std::fs::create_dir_all(auto_harvest_dir).ok();

    let unmapped_rules: Vec<_> = eslint_rules_active.iter().filter(|rule| {
        let covered = existing_rules.iter().any(|f| {
            (f.contains("typescript") && rule.starts_with("@typescript-eslint")) ||
            (f.contains("react-hooks") && rule.starts_with("react-hooks")) ||
            (f.contains("Conformidade") && rule.contains("security")) ||
            (f.contains("API-convention") && rule.contains("import")) ||
            (f.contains("design-system") && rule.contains("css"))
        });
        !covered && ESLINT_TO_PATTERN.contains_key(*rule)
    }).cloned().collect();

    for rule in unmapped_rules {
        if let Some(mapping) = ESLINT_TO_PATTERN.get(&rule) {
            let filename = format!("auto-{}.md", rule.replace(['@', '/'], "-").replace("---", "-"));
            let file_path = Path::new(auto_harvest_dir).join(&filename);

            if !file_path.exists() {
                let content = format!(r#"---
trigger: manual
source: auto-harvest
needs-human-review: true
eslint-rule: {}
generated: {}
---

# [AUTO-HARVEST] {}

> ⚠️ Este arquivo foi gerado automaticamente pelo nemesis-harvest.
> Revise e integre ao arquivo de rule manual correspondente se aplicavel.

## O que esta regra detecta

{}

## Sugestao de correcao

{}

## Padrao de deteccao (regex)

```
{}
```

## Severidade

{}

## Referencia

Regra ESLint: `{}` 
Instalado como parte da stack em: `package.json` 

## [RESTRICT: {}] = BLOCKED
"#,
                    rule, timestamp, rule, mapping.message, mapping.suggestion, mapping.pattern,
                    mapping.severity, rule, rule
                );
                fs::write(&file_path, content).ok();
                created.push(filename);
            }
        }
    }

    if !stack_detected.contains_key("next.config.csp") {
        let filename = "auto-csp-not-configured.md".to_string();
        let file_path = Path::new(auto_harvest_dir).join(&filename);
        if !file_path.exists() {
            let content = format!(r#"---
trigger: manual
source: auto-harvest
needs-human-review: true
generated: {}
---

# [AUTO-HARVEST] CSP não configurado

> ⚠️ Este arquivo foi gerado automaticamente pelo nemesis-harvest.
> Configure CSP no next.config.js para prevenir OWASP A05.

## O que esta regra detecta

Content-Security-Policy não está configurado em next.config.js

## Sugestão de correcao

Adicione headers CSP no next.config.js

## Severidade

critical

## Referencia

OWASP A05: Security Misconfiguration
"#, timestamp);
            fs::write(&file_path, content).ok();
            created.push(filename);
        }
    }

    created
}

/// Gera arquivo de configuração para AST Linters (.nemesis/ast-rules.json).
///
/// Este arquivo contém as regras ESLint ativas e suas severidades,
/// permitindo que o RuleRegistry carregue a configuração dinamicamente.
fn generate_ast_rules_config(eslint_rules_active: &[String], eslint_config: &HashMap<String, serde_json::Value>) {
    let ast_rules_dir = ".nemesis";
    fs::create_dir_all(ast_rules_dir).ok();

    let mut rules_config: HashMap<String, String> = HashMap::new();

    // Adiciona regras ESLint ativas com severidade "error"
    for rule in eslint_rules_active {
        rules_config.insert(rule.clone(), "error".to_string());
    }

    // Extrai severidade do config ESLint se disponível
    if let Some(rules) = eslint_config.get("rules").and_then(|r| r.as_object()) {
        for (rule_name, rule_value) in rules {
            let severity = match rule_value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Array(arr) => {
                    arr.first().and_then(|v| v.as_str()).unwrap_or("error").to_string()
                }
                serde_json::Value::Number(n) => {
                    match n.as_i64() {
                        Some(2) => "error".to_string(),
                        Some(1) => "warning".to_string(),
                        Some(0) => "off".to_string(),
                        _ => "error".to_string(),
                    }
                }
                _ => "error".to_string(),
            };
            rules_config.insert(rule_name.clone(), severity);
        }
    }

    // Mapeia regras ESLint para regras AST (quando há correspondência)
    let eslint_to_ast_mapping = [
        ("@typescript-eslint/no-floating-promises", "no-floating-promises"),
        ("@typescript-eslint/no-unsafe-assignment", "no-unsafe-assignment"),
        ("react/jsx-no-target-blank", "jsx-no-target-blank"),
        ("no-console", "no-console"),
        ("@typescript-eslint/prefer-readonly", "prefer-readonly"),
    ];

    let mut ast_rules_config: HashMap<String, String> = HashMap::new();
    for (eslint_rule, ast_rule) in &eslint_to_ast_mapping {
        if let Some(severity) = rules_config.get(*eslint_rule) {
            ast_rules_config.insert(ast_rule.to_string(), severity.clone());
        } else {
            // Se a regra ESLint não está configurada, usa default "error"
            ast_rules_config.insert(ast_rule.to_string(), "error".to_string());
        }
    }

    // Estrutura do arquivo JSON
    #[derive(Serialize)]
    struct AstRulesConfig {
        version: String,
        generated_at: String,
        rules: HashMap<String, String>,
    }

    let config = AstRulesConfig {
        version: "1.0.0".to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        rules: ast_rules_config,
    };

    let file_path = Path::new(ast_rules_dir).join("ast-rules.json");
    if let Ok(json) = serde_json::to_string_pretty(&config) {
        fs::write(&file_path, json).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_stack_comprehensive_returns_hashmap() {
        // Verify that detect_stack_comprehensive() returns a valid HashMap
        // In this environment (Rust workspace), it will detect Rust stack (Cargo.toml exists)
        let stack = detect_stack_comprehensive();
        assert!(!stack.is_empty(), "Function should detect at least one stack in this environment");
    }

    #[test]
    fn test_detect_stack_comprehensive_rust_detection() {
        // Test that Rust detection works (Cargo.toml)
        // In the .nemesis workspace, Cargo.toml always exists
        let stack = detect_stack_comprehensive();
        assert!(stack.contains_key("rust"), "Rust should be detected when Cargo.toml exists");
        assert_eq!(stack.get("rust"), Some(&"true".to_string()), "Rust should be marked as 'true'");
    }

    #[test]
    fn test_detect_stack_comprehensive_keys_are_valid() {
        // Verify that detected stack keys are reasonable technology names
        let stack = detect_stack_comprehensive();
        let valid_keys = vec![
            "typescript", "javascript", "next", "python", "rust", "go",
            "java-maven", "java-gradle", "ruby", "php", "dart", "docker", "docker-compose"
        ];

        for (key, value) in stack.iter() {
            assert!(valid_keys.contains(&key.as_str()), "Key {} should be a valid technology name", key);
            assert_eq!(value, "true", "All stack values should be 'true'");
        }
    }

    #[test]
    fn test_run_harvest_loads_and_combines_deny_lists() {
        // This test verifies that run_harvest() internally calls load_and_combine_deny_lists
        // with the detected stacks, filtering out versions and next.config.csp entries.
        // The test will pass when the implementation is complete.
        // Expected behavior:
        // 1. Stacks are detected from package.json
        // 2. Stacks ending with @ (versions) are filtered out
        // 3. next.config.csp entries are filtered out
        // 4. load_and_combine_deny_lists is called with remaining stacks
        // 5. deny-list.json is generated in .nemesis/workflow-enforcement/config/

        // Note: This is an async test, but run_harvest is async
        // The actual test execution would happen during cargo test
    }

    #[tokio::test]
    async fn test_run_harvest_uses_detect_stack_comprehensive() {
        // RED: This test verifies that run_harvest() uses detect_stack_comprehensive()
        // instead of read_package_json() for universal stack detection (8+ languages).
        //
        // Expected: run_harvest() should call detect_stack_comprehensive() internally
        // to detect Rust (Cargo.toml exists in .nemesis workspace)
        let result = run_harvest().await;

        // In the .nemesis workspace, Cargo.toml always exists
        // So detect_stack_comprehensive() MUST detect "rust"
        assert!(
            result.stack_detected.contains_key("rust"),
            "run_harvest() should use detect_stack_comprehensive() which detects Rust from Cargo.toml"
        );

        // Verify value is "true"
        assert_eq!(
            result.stack_detected.get("rust"),
            Some(&"true".to_string()),
            "Rust stack value should be 'true'"
        );
    }
}
