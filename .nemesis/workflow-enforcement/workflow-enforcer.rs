//! Workflow Enforcer for Nemesis Enforcement Engine
//! 
//! RESTRICTION CATALOG
//! Every prohibition extracted from all 9 project rule files.
//! Source annotations reference the exact rule file and section.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use regex::Regex;
use lazy_static::lazy_static;

use crate::types::{
    WorkflowDefinition,
    ValidationResult,
    Violation,
    EnforcementConfig,
    PermissionRequest,
    PreToolValidationInput,
    PreToolValidationResult,
};
use crate::permission_gate::RiskLevel;
use crate::workflow_validators::WorkflowValidators;
use crate::permission_gate::PermissionGate;
use crate::violation_logger::ViolationLogger;

use ast_linters::validator::validate_semantic;

// =============================================================================
// RESTRICTION CATALOG
// Every prohibition extracted from all 9 project rule files.
// Source annotations reference the exact rule file and section.
// =============================================================================

lazy_static! {
    // SOURCE: react-hooks-patterns-rules.md - Section 3.1
    // PROHIBITION: Hooks called inside conditionals (if/else/ternary/early return)
    static ref CONDITIONAL_HOOK_PATTERNS: Vec<Regex> = vec![
        // if (...) { useState/useEffect/... (
        Regex::new(r"if\s*\([^)]*\)\s*\{[^}]*\b(useState|useEffect|useCallback|useMemo|useRef|useContext|useReducer|useWatch|useDropInput|useFloatingLabel)\s*\(").unwrap(),
        // if (...) useState/useEffect/... (  — without braces
        Regex::new(r"if\s*\([^)]*\)\s+\b(useState|useEffect|useCallback|useMemo|useRef|useContext|useReducer|useWatch|useDropInput|useFloatingLabel)\s*\(").unwrap(),
        // else { useState/useEffect/... (
        Regex::new(r"else\s*\{[^}]*\b(useState|useEffect|useCallback|useMemo|useRef|useContext|useReducer|useWatch|useDropInput|useFloatingLabel)\s*\(").unwrap(),
        // ternary ? { useState (
        Regex::new(r"\?\s*\{[^}]*\b(useState|useEffect|useCallback|useMemo|useRef|useContext|useReducer)\s*\(").unwrap(),
    ];

    // SOURCE: react-hooks-patterns-rules.md - Section 3.2
    // PROHIBITION: Direct synchronous setState in the body of useEffect
    static ref SYNC_SET_STATE_IN_EFFECT_PATTERNS: Vec<Regex> = vec![
        // useEffect(() => { setXxx(  — without any if guard before setState
        Regex::new(r"useEffect\s*\(\s*\(\s*\)\s*=>\s*\{\s*(set[A-Z][a-zA-Z]*)\s*\(").unwrap(),
        // useEffect(() => { setActiveArrow / setIsPlaying / setCurrentSlide
        Regex::new(r"useEffect\s*\([^)]*\)\s*\{\s*(setActiveArrow|setIsPlaying|setCurrentSlide)\s*\(").unwrap(),
    ];

    // SOURCE: react-hooks-patterns-rules.md - Section 3.3
    // PROHIBITION: Variable reassignment during render
    static ref VARIABLE_REASSIGNMENT_PATTERNS: Vec<Regex> = vec![
        // let hasX = false  followed by  hasX = true  inside a map/forEach
        Regex::new(r"let\s+\w+\s*=\s*false[^}]+\w+\s*=\s*true").unwrap(),
    ];

    // SOURCE: typescript-typing-convention.md - Section 7
    // SOURCE: ui-separation-convention.md - Section 7
    // SOURCE: Conformidade.md - Section 2.3
    // SOURCE: Arquitetura-pastas-arquivos.md - Checklist Section 9
    // PROHIBITION: any typing in any form
    static ref ANY_TYPING_PATTERNS: Vec<Regex> = vec![
        Regex::new(r":\s*any\b").unwrap(),
        Regex::new(r"as\s+any\b").unwrap(),
        Regex::new(r"<any>").unwrap(),
        Regex::new(r"Array<any>").unwrap(),
        Regex::new(r"Promise<any>").unwrap(),
        Regex::new(r"Record<string,\s*any>").unwrap(),
        Regex::new(r"Map<[^,]+,\s*any>").unwrap(),
        Regex::new(r"\(\s*\)\s*:\s*any\b").unwrap(),
    ];

    // SOURCE: design-system-convention.md - Section 3, Section 5.1, Section 9
    // PROHIBITION: CSS inline (style={{ }}) - must use Tailwind classes
    static ref INLINE_CSS_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"style\s*=\s*\{\{").unwrap(),
        Regex::new(r"<style\s*>").unwrap(),
        Regex::new(r#"className[^"]*"[^"]*#[0-9A-Fa-f]{3,6}"#).unwrap(),
    ];

    // SOURCE: design-system-convention.md - Section 9 (Absolute Prohibitions)
    // PROHIBITION: Multiple separate class constants repeating the same variant condition
    static ref DESIGN_SYSTEM_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"const\s+\w+Classes\s*=[^;]+variant\s*===[^;]+;\s*const\s+\w+Classes\s*=[^;]+variant\s*==="#).unwrap(),
    ];

    // SOURCE: ui-separation-convention.md - Section 4, Section 7
    // PROHIBITION: useState/useEffect/business logic directly in UI components
    static ref UI_LOGIC_SEPARATION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"useState\s*\("#).unwrap(),
        Regex::new(r#"useEffect\s*\("#).unwrap(),
        Regex::new(r#"useCallback\s*\("#).unwrap(),
        Regex::new(r#"useMemo\s*\("#).unwrap(),
    ];

    // SOURCE: ui-separation-convention.md - Section 8.1
    // PROHIBITION: Nested interactive elements (causes hydration errors)
    static ref NESTED_INTERACTIVE_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"<a\b[^>]*>[\s\S]*?<a\b").unwrap(),
        Regex::new(r"<button\b[^>]*>[\s\S]*?<button\b").unwrap(),
        Regex::new(r"<form\b[^>]*>[\s\S]*?<form\b").unwrap(),
    ];

    // SOURCE: typescript-typing-convention.md - Section 5 (Exceptions), Section 4
    // PROHIBITION: Inline typing in reusable UI/shared components
    static ref INLINE_TYPING_IN_UI_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"export\s+function\s+[A-Z]\w+\s*\(\s*\{[^}]*\}\s*:\s*\{[^}]*\}\s*\)"#).unwrap(),
    ];

    // SOURCE: API-convention.md - Section 3.1 (3-Layer Architecture)
    // PROHIBITION: Direct fetch to external API bypassing BFF layer
    static ref BFF_BYPASS_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"fetch\s*\(\s*['"`]https?:\/\/(?!localhost)"#).unwrap(),
        Regex::new(r#"axios\s*\.\s*(get|post|put|delete)\s*\(\s*['"`]https?:\/\/(?!localhost)"#).unwrap(),
        Regex::new(r"process\.env\.NEXT_PUBLIC_\w+TOKEN[^}]+fetch").unwrap(),
    ];

    // SOURCE: Conformidade.md - Section 3.2, 3.3
    // SOURCE: API-convention.md - Section 5.3
    // PROHIBITION: Security misconfigurations — ABSOLUTE blocks, no user override
    static ref SECURITY_VIOLATION_PATTERNS: Vec<Regex> = vec![
        // localStorage/sessionStorage storing tokens or passwords
        Regex::new(r#"localStorage\s*\.\s*setItem\s*\([^)]*[Tt]oken"#).unwrap(),
        Regex::new(r#"localStorage\s*\.\s*setItem\s*\([^)]*[Pp]assword"#).unwrap(),
        Regex::new(r#"sessionStorage\s*\.\s*setItem\s*\([^)]*[Tt]oken"#).unwrap(),
        // console.log of credentials
        Regex::new(r#"(?i)console\s*\.\s*log.*password"#).unwrap(),
        // Manual JWT (btoa base64 encoding as JWT substitute)
        Regex::new(r#"btoa\s*\([^)]+header[^)]+\)\s*\+\s*'\.'[^+]+\+\s*btoa"#).unwrap(),
        // bypass parameter in route
        Regex::new(r#"searchParams\.\s*get\s*\(\s*['"]bypass['"]\s*\)"#).unwrap(),
        // Removing security headers explicitly
        Regex::new(r#"headers\s*\.\s*delete\s*\(\s*['"]Content-Security-Policy['"]\s*\)"#).unwrap(),
        Regex::new(r#"headers\s*\.\s*delete\s*\(\s*['"]X-Frame-Options['"]\s*\)"#).unwrap(),
        // CORS wildcard
        Regex::new(r#"'Access-Control-Allow-Origin'\s*[:=]\s*['"]\\*['"]"#).unwrap(),
        // No rate limiting / bypass comments
        Regex::new(r#"(?i)//\s*(no rate limit|bypass security|skip validation|sem validação)"#).unwrap(),
        // Exposed hashed passwords in response object
        Regex::new(r#"hashedPassword.*:"#).unwrap(),
        // Debug information with credentials
        Regex::new(r#"(?i)debug.*[:=].*\{[^}]*(password|token|credential)"#).unwrap(),
        // Long expiration tokens (unix timestamp, 10+ digits)
        Regex::new(r#"exp.*[:=].*\d{10,}"#).unwrap(),
        // Security headers removal
        Regex::new(r#"(?i)compatibilidade.*test.*headers"#).unwrap(),
        // Direct database response without transformation
        Regex::new(r#"(?i)raw.*database.*response"#).unwrap(),
        // Token with 30 days expiration explicitly mentioned
        Regex::new(r#"(?i)30.*dias.*expiração|30.*days.*expiration"#).unwrap(),
        // Development/debug mode with exposed data
        Regex::new(r#"(?i)development.*mode.*exposed|debug.*mode.*data"#).unwrap(),
    ];

    // SOURCE: Conformidade.md - Section 3.1 (CSP/Nonce)
    // PROHIBITION: unsafe-eval in production, missing nonce
    static ref CSP_VIOLATION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"'unsafe-eval'(?![^`]*isDev|[^`]*development)"#).unwrap(),
        Regex::new(r#"script-src[^;]*'unsafe-inline'"#).unwrap(),
    ];

    // SOURCE: Arquitetura-pastas-arquivos.md - Section 4.1, 4.5
    // PROHIBITION: importing next/navigation in main-content components
    static ref ARCHITECTURE_VIOLATION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"from\s+['"]next/navigation['"]"#).unwrap(),
    ];

    // SOURCE: design-system-convention.md - Section 2.1
    // PROHIBITION: Direct hex colors outside tailwind.config.ts
    static ref HARDCODED_COLOR_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?:bg|text|border|ring|fill|stroke)-\[#[0-9A-Fa-f]{3,6}\]").unwrap(),
        Regex::new(r#"(?:color|background|backgroundColor|borderColor)\s*:\s*['"]#[0-9A-Fa-f]{3,6}['"]"#).unwrap(),
    ];

    // SOURCE: Conformidade.md §2.3 (TypeScript strict MANDATORY)
    // SOURCE: design-system-convention.md §3 (only Tailwind, no styled-jsx)
    // PROHIBITION: Disabling TypeScript strict mode in config files
    // PROHIBITION: Adding prohibited dependencies (styled-jsx)
    static ref TS_SUPPRESSION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"@ts-ignore").unwrap(),
        Regex::new(r"@ts-nocheck").unwrap(),
        Regex::new(r"@ts-expect-error(?!\s*--)").unwrap(), // allow only with explanation
    ];

    // SOURCE: rule-main-rules.md - Section 5 (Absolute Prohibitions)
    // SOURCE: origin-rules.md - Section 2
    // PROHIBITED COMMANDS: dangerous shell operations
    static ref FORBIDDEN_COMMANDS: Vec<Regex> = vec![
        Regex::new(r"rm\s+-rf\s+/").unwrap(),
        Regex::new(r"sudo\s+rm").unwrap(),
        Regex::new(r"format\s+c:").unwrap(),
        Regex::new(r"dd\s+if=").unwrap(),
        Regex::new(r"shutdown").unwrap(),
        Regex::new(r"reboot").unwrap(),
        Regex::new(r"passwd").unwrap(),
        Regex::new(r"chmod\s+777").unwrap(),
        Regex::new(r"chown\s+root").unwrap(),
        Regex::new(r"kill\s+-9").unwrap(),
    ];

    // SOURCE: Conformidade.md - Section 2.5 (Bun)
    // PROHIBITION: npm install --force, yarn add --ignore-scripts
    // PROHIBITION: eslint --config custom, eslint --ignore (governance bypass)
    static ref FORBIDDEN_COMMAND_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"npm.*install.*--force").unwrap(),
        Regex::new(r"yarn.*add.*--ignore-scripts").unwrap(),
        Regex::new(r"eslint.*--config(?!.*package\.json)").unwrap(),
        Regex::new(r"eslint.*--ignore-path").unwrap(),
        Regex::new(r"eslint.*--no-ignore").unwrap(),
        Regex::new(r"bun\s+add.*--no-save").unwrap(),
    ];

    // Critical config files — blocked from creation/overwrite via Bash heredoc
    static ref CRITICAL_CONFIG_FILE_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"/tsconfig\.json$").unwrap(),
        Regex::new(r"/package\.json$").unwrap(),
        Regex::new(r"/.eslintrc").unwrap(),
        Regex::new(r"/next\.config").unwrap(),
        Regex::new(r"/tailwind\.config").unwrap(),
        Regex::new(r"/postcss\.config").unwrap(),
        Regex::new(r"/.env").unwrap(),
        Regex::new(r"/bun\.lockb$").unwrap(),
        Regex::new(r"/yarn\.lock$").unwrap(),
    ];
}

// Config violation patterns with reasons
struct ConfigViolationPattern {
    pattern: Regex,
    reason: String,
    rule: String,
}

fn get_config_violation_patterns() -> Vec<ConfigViolationPattern> {
    vec![
        ConfigViolationPattern {
            pattern: Regex::new(r#""strict"\s*:\s*false"#).unwrap(),
            reason: "strict: false em tsconfig — desabilita TypeScript strict mode globalmente, invalidando todo o enforcement de tipos do projeto".to_string(),
            rule: ".devin/rules/Conformidade.md - Seção 2.3 (TypeScript Strict Mode)".to_string(),
        },
        ConfigViolationPattern {
            pattern: Regex::new(r#""noImplicitAny"\s*:\s*false"#).unwrap(),
            reason: "noImplicitAny: false em tsconfig — permite any implícito em todo o projeto".to_string(),
            rule: ".devin/rules/Conformidade.md - Seção 2.3".to_string(),
        },
        ConfigViolationPattern {
            pattern: Regex::new(r#""strictNullChecks"\s*:\s*false"#).unwrap(),
            reason: "strictNullChecks: false em tsconfig — desabilita verificação de null/undefined".to_string(),
            rule: ".devin/rules/Conformidade.md - Seção 2.3".to_string(),
        },
        ConfigViolationPattern {
            pattern: Regex::new(r#""strictFunctionTypes"\s*:\s*false"#).unwrap(),
            reason: "strictFunctionTypes: false em tsconfig".to_string(),
            rule: ".devin/rules/Conformidade.md - Seção 2.3".to_string(),
        },
        ConfigViolationPattern {
            pattern: Regex::new(r#"styled-jsx"#).unwrap(),
            reason: "Dependência styled-jsx detectada — proibida pelo design system (apenas Tailwind é permitido)".to_string(),
            rule: ".devin/rules/design-system-convention.md - Seção 3 (Tokens: fonte única de verdade)".to_string(),
        },
    ]
}

// Validation result builder
fn blocked(reason: &str, rule: &str, suggestion: &str) -> PreToolValidationResult {
    PreToolValidationResult {
        valid: false,
        reason: Some(reason.to_string()),
        rule: Some(rule.to_string()),
        suggestion: Some(suggestion.to_string()),
    }
}

fn allowed() -> PreToolValidationResult {
    PreToolValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

/// Workflow Enforcer - Main validation engine
pub struct WorkflowEnforcer {
    config: EnforcementConfig,
}

impl WorkflowEnforcer {
    pub fn new(config: EnforcementConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(EnforcementConfig {
            block_unauthorized_commands: true,
            log_violations: true,
            require_permission_for_file_edits: true,
            allowed_languages: vec![
                "bash".to_string(),
                "javascript".to_string(),
                "typescript".to_string(),
                "python".to_string(),
                "markdown".to_string(),
            ],
            mandatory_rules: vec![".devin/rules/rule-main-rules.md".to_string()],
            mode: None,
        })
    }

    /// PUBLIC ENTRY POINT: PreToolUse hook (headless mode)
    pub async fn validate_pre_tool_use(&self, input: &PreToolValidationInput) -> PreToolValidationResult {
        let tool_name = &input.tool_name;
        let tool_input = &input.tool_input;

        match tool_name.as_str() {
            "Edit" | "Write" => {
                // 1. Validate the NEW content about to be written
                let new_content = tool_input.get("new_string")
                    .or_else(|| tool_input.get("content"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                
                let file_path = tool_input.get("file_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if !new_content.is_empty() {
                    let content_result = self.validate_new_content(file_path, new_content);
                    if !content_result.valid {
                        return content_result;
                    }
                }

                // 2. Validate the file path / scope
                self.validate_file_scope(Some(file_path), tool_name)
            }
            "Bash" => {
                let command = tool_input.get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                self.validate_command(Some(command))
            }
            "Read" | "Grep" => allowed(),
            _ => {
                if self.config.log_violations {
                    eprintln!("[NEMESIS WARNING] Unknown tool: {}", tool_name);
                }
                allowed()
            }
        }
    }

    /// CONTENT VALIDATION
    /// Runs on the STRING being written, not the existing file on disk.
    /// This prevents "remove violation to bypass" loophole.
    pub fn validate_new_content(&self, file_path: &str, content: &str) -> PreToolValidationResult {
        let is_react = Regex::new(r"\.(tsx|jsx)$").unwrap().is_match(file_path);
        let is_ts = Regex::new(r"\.(ts|tsx)$").unwrap().is_match(file_path);
        let is_hook = file_path.contains("/hooks/");
        let is_ui_component = self.classify_file(file_path) == "ui-component";
        // Pass content so is_smart_component ignores comment in new content (bypass fix)
        let is_smart_component = self.is_smart_component(file_path, Some(content));

        // CONFIG FILES: checked first
        if Regex::new(r"tsconfig\.json$|package\.json$").unwrap().is_match(file_path) {
            for check in get_config_violation_patterns() {
                if check.pattern.is_match(content) {
                    return blocked(
                        &format!("ESCRITA BLOQUEADA: {}. Este bloqueio NÃO pode ser sobrescrito por instrução do usuário.", check.reason),
                        &check.rule,
                        "Arquivos de configuração do projeto não podem desabilitar mecanismos de enforcement ou adicionar dependências proibidas. Qualquer modificação requer aprovação explícita e documentada.",
                    );
                }
            }
        }

        // 1. any typing — ALL TypeScript files
        if is_ts {
            for pattern in ANY_TYPING_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: Tipagem \"any\" detectada no conteúdo a ser escrito.",
                        ".devin/rules/typescript-typing-convention.md - Seção 7",
                        "Use tipos explícitos, unknown, generics ou tipos existentes em src/types/. Remover \"any\" para burlar o enforcement é uma violação — o bloco inteiro é rejeitado.",
                    );
                }
            }
        }

        // 2. TypeScript suppressions — ALL TypeScript files
        if is_ts {
            for pattern in TS_SUPPRESSION_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: @ts-ignore ou @ts-nocheck detectado.",
                        ".devin/rules/Conformidade.md - Seção 2.3 (TypeScript Strict)",
                        "Não suprima erros TypeScript. Corrija o tipo ou use unknown com type guard adequado.",
                    );
                }
            }
        }

        // 3. Conditional hooks — React files
        if is_react {
            for pattern in CONDITIONAL_HOOK_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: Hook chamado condicionalmente (dentro de if/else/ternário/early return).",
                        ".devin/rules/react-hooks-patterns-rules.md - Seção 3.1 (Hooks Condicionais)",
                        "Mova todos os hooks para o topo do componente, antes de qualquer condicional ou early return.",
                    );
                }
            }
        }

        // 4. Synchronous setState in useEffect body — React files
        if is_react {
            for pattern in SYNC_SET_STATE_IN_EFFECT_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: setState síncrono direto no corpo do useEffect detectado.",
                        ".devin/rules/react-hooks-patterns-rules.md - Seção 3.2 (setState em useEffect)",
                        "Envolva o setState em um if condicional antes de chamar. Nunca chame setState diretamente no corpo do useEffect sem guarda condicional.",
                    );
                }
            }
        }

        // 5. Variable reassignment during render — hooks and components
        if is_react || is_hook {
            for pattern in VARIABLE_REASSIGNMENT_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: Reatribuição de variável durante render detectada.",
                        ".devin/rules/react-hooks-patterns-rules.md - Seção 3.3 (Variable Reassignment)",
                        "Use useState ou derive o valor sem mutar variáveis após o início do render.",
                    );
                }
            }
        }

        // 6. Inline CSS — React files
        if is_react {
            for pattern in INLINE_CSS_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: CSS inline (style={{}}) detectado.",
                        ".devin/rules/design-system-convention.md - Seção 3 (Tokens) e Seção 9 (Proibições)",
                        "Use apenas classes Tailwind definidas em tailwind.config.ts. CSS inline é proibido.",
                    );
                }
            }
        }

        // 7. Hardcoded hex colors — React files
        if is_react {
            for pattern in HARDCODED_COLOR_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: Cor hexadecimal hardcoded detectada.",
                        ".devin/rules/design-system-convention.md - Seção 2.1 (Paleta de Cores)",
                        "Use tokens semânticos do design system (ex: bg-primary-500). Nunca use #hex diretamente em componentes.",
                    );
                }
            }
        }

        // 8. Multiple separate class constants (Design System violation)
        if is_react {
            for pattern in DESIGN_SYSTEM_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: Múltiplas constantes de classe separadas repetindo a mesma condição de variante.",
                        ".devin/rules/design-system-convention.md - Seção 9 (Proibições Absolutas)",
                        "Toda lógica de variante deve viver em um único bloco clsx. Nunca repita a mesma condição variant === em múltiplas constantes separadas.",
                    );
                }
            }
        }

        // 9. Logic in UI components (non-smart)
        if is_ui_component && !is_smart_component {
            for pattern in UI_LOGIC_SEPARATION_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: useState/useEffect/lógica de negócio em componente UI detectado.",
                        ".devin/rules/ui-separation-convention.md - Seção 4 e Seção 7",
                        "Componentes UI devem conter apenas JSX e classes Tailwind. Mova a lógica para hooks em src/hooks/. Para registrar como smart component legítimo, adicione ao .nemesis/smart-components.json — não ao comentário no arquivo.",
                    );
                }
            }
        }

        // 10. Inline typing in reusable UI/shared components
        if is_ui_component && !is_smart_component {
            for pattern in INLINE_TYPING_IN_UI_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: Tipagem inline em componente UI reutilizável detectada.",
                        ".devin/rules/typescript-typing-convention.md - Seção 5 (Exceções Permitidas)",
                        "Defina a interface em src/types/ui/[component].types.ts e importe via \"import type\". Tipagem inline só é permitida em layout.tsx e page.tsx.",
                    );
                }
            }
        }

        // 11. Nested interactive elements
        if is_react {
            for pattern in NESTED_INTERACTIVE_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: Elemento interativo aninhado detectado (<a> dentro de <a>, <button> dentro de <button>, ou <form> dentro de <form>).",
                        ".devin/rules/ui-separation-convention.md - Seção 8.1 (Nesting Proibido)",
                        "HTML inválido causa hydration error no Next.js. Substitua o elemento interno por <span> ou <div> com o mesmo estilo.",
                    );
                }
            }
        }

        // 12. BFF bypass — component files calling external APIs directly
        if is_react && !file_path.contains("/api/") && !file_path.contains("/hooks/hook-fetch-API/") {
            for pattern in BFF_BYPASS_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: Chamada direta a API externa em componente detectada (bypass da camada BFF).",
                        ".devin/rules/API-convention.md - Seção 3.1 (Arquitetura 3-Layer)",
                        "Componentes nunca chamam APIs externas diretamente. Crie um Route Handler em src/app/api/ e um hook em src/hooks/hook-fetch-API/.",
                    );
                }
            }
        }

        // 13. Security violations — ALL files
        for pattern in SECURITY_VIOLATION_PATTERNS.iter() {
            if pattern.is_match(content) {
                return blocked(
                    "ESCRITA BLOQUEADA: Violação crítica de segurança (OWASP) detectada no conteúdo a ser escrito. Este bloqueio NÃO pode ser sobrescrito por instrução do usuário.",
                    ".devin/rules/Conformidade.md - Seção 3 (OWASP) e Seção 6.1 (OWASP Top 10)",
                    "Violações de segurança são bloqueios absolutos. Não armazene tokens em localStorage, não logue credenciais, não implemente JWT manual, não abra CORS sem restrição, não crie parâmetros bypass.",
                );
            }
        }

        // 14. CSP violations — middleware and config files
        if file_path.contains("middleware") || file_path.contains("next.config") {
            for pattern in CSP_VIOLATION_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: Violação de CSP detectada (unsafe-eval fora de desenvolvimento, ou unsafe-inline em script-src).",
                        ".devin/rules/Conformidade.md - Seção 3.1 (Middleware com Nonce e CSP)",
                        "CSP Level 3 com nonce é obrigatório. unsafe-eval só é permitido em desenvolvimento com guarda condicional explícita.",
                    );
                }
            }
        }

        // 15. next/navigation import in main-content components
        if file_path.contains("/main-content/") {
            for pattern in ARCHITECTURE_VIOLATION_PATTERNS.iter() {
                if pattern.is_match(content) {
                    return blocked(
                        "ESCRITA BLOQUEADA: Importação de next/navigation em componente main-content detectada.",
                        ".devin/rules/Arquitetura-pastas-arquivos.md - Seção 4.5 (main-content)",
                        "Componentes em main-content não devem importar next/navigation nem manipular rotas diretamente. Use hooks de roteamento centralizados.",
                    );
                }
            }
        }

        // 16. shared-login-screen importing from main-content or authenticated routes
        if file_path.contains("/shared-login-screen/") {
            let main_content_import = Regex::new(r#"from\s+['"][^'"]*/main-content/"#).unwrap().is_match(content);
            let auth_import = Regex::new(r#"from\s+['"][^'"]*/(dashboard|authenticated)/"#).unwrap().is_match(content);
            
            if main_content_import || auth_import {
                return blocked(
                    "ESCRITA BLOQUEADA: shared-login-screen importando de main-content ou rotas autenticadas.",
                    ".devin/rules/Arquitetura-pastas-arquivos.md - Seção 4.3 (shared-login-screen)",
                    "shared-login-screen não pode importar nada de main-content ou de rotas autenticadas. Pertence exclusivamente ao fluxo público.",
                );
            }
        }

        // 17. AST semantic validation — todos os arquivos TS/JS
        let ast_layers = [".ts", ".tsx", ".js", ".jsx"];
        let ext = std::path::Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{}", e))
            .unwrap_or_default();
        if ast_layers.iter().any(|l| *l == ext) {
            let ast_violations = validate_semantic(content, file_path);
            if !ast_violations.is_empty() {
                let first = &ast_violations[0];
                return blocked(
                    &format!("ESCRITA BLOQUEADA: [AST] {} (linha {})", first.message, first.line),
                    ".devin/rules/Conformidade.md - Seção 3 (AST Semantic Validation)",
                    "Violação semântica detectada por análise de AST. Revise o código e corrija o problema antes de prosseguir.",
                );
            }
        }

        allowed()
    }

    /// FILE SCOPE VALIDATION
    fn validate_file_scope(&self, file_path: Option<&str>, operation: &str) -> PreToolValidationResult {
        let file_path = match file_path {
            Some(fp) if !fp.is_empty() => fp,
            _ => {
                return blocked(
                    "Caminho do arquivo não fornecido.",
                    ".devin/rules/rule-main-rules.md",
                    "Especifique o arquivo a ser modificado.",
                );
            }
        };

        if operation == "Edit" {
            if !Path::new(file_path).exists() {
                return blocked(
                    &format!("Arquivo não existe: {}", file_path),
                    ".devin/rules/rule-main-rules.md",
                    "Verifique o caminho do arquivo antes de tentar editar.",
                );
            }
        }

        let absolute_path = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(file_path)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(file_path));
        
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

        let allowed_external_paths: Vec<String> = vec![
            "/tmp/".to_string(),
            "/var/tmp/".to_string(),
            std::env::var("TEMP").unwrap_or_default(),
            std::env::var("TMP").unwrap_or_default(),
        ].into_iter().filter(|s| !s.is_empty()).collect();

        let is_in_project = absolute_path.starts_with(&cwd);
        let is_allowed_external = allowed_external_paths.iter().any(|p| {
            absolute_path.to_string_lossy().starts_with(p)
        });

        if !is_in_project && !is_allowed_external {
            return blocked(
                &format!("Arquivo fora do escopo do projeto: {}", file_path),
                ".devin/rules/rule-main-rules.md - Seção 5 (Proibições)",
                "NUNCA editar arquivos fora do escopo do projeto sem permissão explícita do usuário.",
            );
        }

        // Log warning for critical config files
        for pattern in CRITICAL_CONFIG_FILE_PATTERNS.iter() {
            if pattern.is_match(&absolute_path.to_string_lossy()) {
                if self.config.log_violations {
                    eprintln!("[NEMESIS WARNING] Modificação de arquivo de configuração crítico: {}", file_path);
                }
                break;
            }
        }

        allowed()
    }

    /// COMMAND VALIDATION
    pub fn validate_command(&self, command: Option<&str>) -> PreToolValidationResult {
        let command = match command {
            Some(c) if !c.is_empty() => c,
            _ => {
                return blocked(
                    "Comando não fornecido.",
                    ".devin/rules/rule-main-rules.md",
                    "Especifique o comando a ser executado.",
                );
            }
        };

        // HEREDOC FILE CREATION DETECTION
        let heredoc_re = Regex::new(r#"(?:cat|tee)\s*>\s*([^\s<]+)\s*<<\s*['"]?(?:EOF|HEREDOC|END)['"]?\n([\s\S]*?)\n(?:EOF|HEREDOC|END)"#).unwrap();
        if let Some(caps) = heredoc_re.captures(command) {
            let target_file = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            let heredoc_content = caps.get(2).map(|m| m.as_str()).unwrap_or("");

            // Block creation of critical config files via heredoc entirely
            for pattern in CRITICAL_CONFIG_FILE_PATTERNS.iter() {
                if pattern.is_match(target_file) {
                    return blocked(
                        &format!("BASH BLOQUEADO: Criação/sobrescrita de arquivo de configuração crítico via terminal: {}. Este bloqueio NÃO pode ser sobrescrito.", target_file),
                        ".devin/rules/rule-main-rules.md - Seção 5 (Proibições)",
                        "Arquivos de configuração críticos (tsconfig.json, package.json, next.config, etc.) não podem ser sobrescritos via comando Bash. Use a ferramenta Edit com aprovação explícita.",
                    );
                }
            }

            // Run heredoc content through full content validation pipeline
            let content_result = self.validate_new_content(target_file, heredoc_content);
            if !content_result.valid {
                return PreToolValidationResult {
                    valid: false,
                    reason: Some(format!("BASH BLOQUEADO: Conteúdo do heredoc viola regras do projeto (arquivo alvo: {}). {}", target_file, content_result.reason.unwrap_or_default())),
                    rule: content_result.rule,
                    suggestion: content_result.suggestion,
                };
            }
        }

        // ECHO REDIRECT DETECTION
        let echo_redirect_re = Regex::new(r#"echo\s+["'](.+?)["']\s*(?:>>?)\s*([^\s;|&]+)"#).unwrap();
        if let Some(caps) = echo_redirect_re.captures(command) {
            let echo_content = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let target_file = caps.get(2).map(|m| m.as_str()).unwrap_or("");

            for pattern in CRITICAL_CONFIG_FILE_PATTERNS.iter() {
                if pattern.is_match(target_file) {
                    return blocked(
                        &format!("BASH BLOQUEADO: echo redirect para arquivo de configuração crítico: {}", target_file),
                        ".devin/rules/rule-main-rules.md - Seção 5",
                        "Não crie ou sobrescreva arquivos de configuração via echo redirect.",
                    );
                }
            }

            let content_result = self.validate_new_content(target_file, echo_content);
            if !content_result.valid {
                return PreToolValidationResult {
                    valid: false,
                    reason: Some(format!("BASH BLOQUEADO: Conteúdo do echo redirect viola regras (arquivo alvo: {}). {}", target_file, content_result.reason.unwrap_or_default())),
                    rule: content_result.rule,
                    suggestion: content_result.suggestion,
                };
            }
        }

        // PRINTF REDIRECT DETECTION
        if Regex::new(r"printf\s+.+(?:>>?)\s*\S+\.(tsx?|jsx?|json)").unwrap().is_match(command) {
            return blocked(
                "BASH BLOQUEADO: printf redirect para arquivo de código detectado.",
                ".devin/rules/rule-main-rules.md - Seção 5",
                "Não crie arquivos de código via printf redirect. Use a ferramenta Write/Edit com aprovação explícita.",
            );
        }

        // TEE PIPE DETECTION
        let tee_pipe_re = Regex::new(r"\|\s*tee\s+(\S+\.(tsx?|jsx?|json))").unwrap();
        if let Some(caps) = tee_pipe_re.captures(command) {
            let target_file = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            for pattern in CRITICAL_CONFIG_FILE_PATTERNS.iter() {
                if pattern.is_match(target_file) {
                    return blocked(
                        &format!("BASH BLOQUEADO: pipe | tee para arquivo de configuração crítico: {}", target_file),
                        ".devin/rules/rule-main-rules.md - Seção 5",
                        "Não sobrescreva arquivos de configuração via pipe | tee.",
                    );
                }
            }
        }

        // Absolute forbidden commands (OS-level destruction)
        for pattern in FORBIDDEN_COMMANDS.iter() {
            if pattern.is_match(command) {
                return blocked(
                    &format!("Comando proibido detectado: {}", &command[..command.len().min(100)]),
                    ".devin/rules/rule-main-rules.md - Seção 5 (Proibições Absolutas)",
                    "Este comando é proibido por questões de segurança do sistema operacional.",
                );
            }
        }

        // Governance bypass commands
        for pattern in FORBIDDEN_COMMAND_PATTERNS.iter() {
            if pattern.is_match(command) {
                return blocked(
                    &format!("Comando de bypass de governança detectado: {}", &command[..command.len().min(100)]),
                    ".devin/rules/Conformidade.md - Seção 2.5 (Bun) e Seção 6.2 (Validação de Dependências)",
                    "Não force instalações, não ignore scripts de segurança, não sobrescreva configuração ESLint centralizada.",
                );
            }
        }

        // High-risk command check (via PermissionGate)
        let safety_check = PermissionGate::check_command_safety(command);
        if safety_check.risk_level == RiskLevel::High {
            return blocked(
                &format!("Comando de alto risco: {}", safety_check.reasons.join(", ")),
                ".devin/rules/Conformidade.md - Seção 3 (Segurança OWASP)",
                "Comandos de sistema precisam de permissão explícita do usuário.",
            );
        }

        if safety_check.risk_level == RiskLevel::Medium && self.config.log_violations {
            eprintln!("[NEMESIS WARNING] Comando de médio risco: {}", &command[..command.len().min(80)]);
        }

        allowed()
    }

    /// FILE CLASSIFICATION
    fn classify_file(&self, file_path: &str) -> &'static str {
        if file_path.contains("/components/ui/") { return "ui-component"; }
        if file_path.contains("/components/shared") { return "shared-component"; }
        if file_path.contains("/hooks/") { return "hook"; }
        if file_path.contains("/app/api/") { return "route"; }
        if file_path.contains("/types/") { return "type"; }
        "other"
    }

    /// SMART COMPONENT DETECTION
    fn is_smart_component(&self, file_path: &str, new_content: Option<&str>) -> bool {
        let known_exceptions = vec![
            "Button.tsx",
            "Container.tsx",
            "InputPesquisaAjuda.tsx",
            "InputSearchHelp.tsx",
        ];

        let file_name = Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // Always check known exceptions first
        if known_exceptions.contains(&file_name) {
            return true;
        }

        // Always check explicit registry
        let registry_path = PathBuf::from(".nemesis/smart-components.json");
        if registry_path.exists() {
            if let Ok(data) = fs::read_to_string(&registry_path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) {
                    if let Some(components) = json.get("smartComponents").and_then(|c| c.as_array()) {
                        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                        let relative = Path::new(file_path)
                            .strip_prefix(&cwd)
                            .unwrap_or_else(|_| Path::new(file_path))
                            .to_string_lossy();
                        
                        for comp in components {
                            if let Some(c) = comp.as_str() {
                                if c == relative.as_ref() {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        // When validating NEW content: STOP HERE.
        // Do NOT check // SMART COMPONENT in the content being written.
        if new_content.is_some() {
            return false;
        }

        // For existing files on disk: check comment and naming convention normally
        if Path::new(file_path).exists() {
            if let Ok(disk_content) = fs::read_to_string(file_path) {
                if disk_content.contains("// SMART COMPONENT") || disk_content.contains("/* SMART COMPONENT */") {
                    return true;
                }
            }
        }

        // Naming convention check
        let stem = Path::new(file_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        Regex::new(r"Smart|Control|Manager|Handler").unwrap().is_match(stem)
    }

    /// WORKFLOW-LEVEL VALIDATION
    pub async fn validate_workflow(&self, workflow: &WorkflowDefinition) -> ValidationResult {
        let result = WorkflowValidators::validate_all(workflow);

        if self.config.log_violations {
            for error in &result.errors {
                ViolationLogger::log_violation(&Violation {
                    violation_type: crate::types::ViolationType::RuleViolation,
                    message: error.message.clone(),
                    rule: Some(".devin/rules".to_string()),
                    command: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    llm_model: None,
                    layer: Some("pretool".to_string()),
                });
            }
        }

        result
    }

    /// Check execution permission
    pub async fn check_execution_permission(&self, workflow: &WorkflowDefinition, command: &str) -> bool {
        let command_language = self.detect_command_language(command);
        
        if !self.config.allowed_languages.contains(&command_language.to_string()) {
            if self.config.log_violations {
                ViolationLogger::log_violation(&Violation {
                    violation_type: crate::types::ViolationType::RuleViolation,
                    message: format!("Command uses unsupported language: {}", command_language),
                    rule: Some(".devin/rules".to_string()),
                    command: Some(command.to_string()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    llm_model: None,
                    layer: Some("pretool".to_string()),
                });
            }
            return false;
        }

        let has_mandatory_rules = self.config.mandatory_rules.iter().all(|r| {
            workflow.content.contains(r)
        });

        if !has_mandatory_rules {
            if self.config.log_violations {
                ViolationLogger::log_violation(&Violation {
                    violation_type: crate::types::ViolationType::RuleViolation,
                    message: "Workflow does not reference mandatory rules".to_string(),
                    rule: Some(".devin/rules".to_string()),
                    command: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    llm_model: None,
                    layer: Some("pretool".to_string()),
                });
            }
            return false;
        }

        let safety_check = PermissionGate::check_command_safety(command);
        let requires_confirmation = safety_check.risk_level != RiskLevel::Low || self.config.require_permission_for_file_edits;

        let permission_request = PermissionRequest {
            command: command.to_string(),
            reason: safety_check.reasons.join(", "),
            workflow: workflow.name.clone(),
            requires_confirmation,
        };

        let has_permission = PermissionGate::request_permission(&permission_request).await;

        if !has_permission && self.config.log_violations {
            ViolationLogger::log_violation(&Violation {
                violation_type: crate::types::ViolationType::PermissionDenied,
                message: format!("Permission denied for command: {}", command),
                rule: Some(".devin/rules/rule-main-rules.md".to_string()),
                command: Some(command.to_string()),
                timestamp: chrono::Utc::now().to_rfc3339(),
                llm_model: None,
                layer: Some("pretool".to_string()),
            });
        }

        has_permission
    }

    fn detect_command_language(&self, command: &str) -> &'static str {
        let c = command.trim().to_lowercase();
        if c.starts_with("npm ") || c.starts_with("npx ") || c.starts_with("yarn ") || c.starts_with("bun ") {
            return "javascript";
        }
        if c.starts_with("python ") || c.starts_with("pip ") {
            return "python";
        }
        if c.contains(".ts") || c.contains(".js") {
            return "javascript";
        }
        if c.contains(".py") {
            return "python";
        }
        "bash"
    }

    /// Enforce workflow execution
    pub async fn enforce_workflow_execution(&self, workflow: &WorkflowDefinition, commands: &[String]) -> EnforcementResult {
        let mut allowed_commands: Vec<String> = vec![];
        let mut blocked_commands: Vec<String> = vec![];
        let mut violations: Vec<Violation> = vec![];

        let validation = self.validate_workflow(workflow).await;
        if !validation.is_valid {
            for command in commands {
                blocked_commands.push(command.clone());
                if self.config.log_violations {
                    let v = Violation {
                        violation_type: crate::types::ViolationType::RuleViolation,
                        message: "Command blocked due to workflow validation failure".to_string(),
                        rule: Some(".devin/rules".to_string()),
                        command: Some(command.clone()),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        llm_model: None,
                        layer: Some("pretool".to_string()),
                    };
                    violations.push(v.clone());
                    ViolationLogger::log_violation(&v);
                }
            }
            return EnforcementResult {
                allowed_commands,
                blocked_commands,
                violations,
            };
        }

        for command in commands {
            let has_permission = self.check_execution_permission(workflow, command).await;
            if has_permission {
                allowed_commands.push(command.clone());
            } else {
                blocked_commands.push(command.clone());
            }
        }

        EnforcementResult {
            allowed_commands,
            blocked_commands,
            violations,
        }
    }

    /// Pre-execution check
    pub async fn pre_execution_check(&self, workflow: &WorkflowDefinition) -> PreExecutionResult {
        let mut reasons: Vec<String> = vec![];
        let mut can_proceed = true;

        let missing_rules: Vec<_> = self.config.mandatory_rules.iter()
            .filter(|r| !workflow.content.contains(*r))
            .cloned()
            .collect();

        if !missing_rules.is_empty() {
            reasons.push(format!("Missing mandatory rules: {}", missing_rules.join(", ")));
            can_proceed = false;
        }

        let validation = self.validate_workflow(workflow).await;
        if !validation.is_valid {
            let error_msgs: Vec<_> = validation.errors.iter().map(|e| e.message.clone()).collect();
            reasons.push(format!("Workflow validation failed: {}", error_msgs.join(", ")));
            can_proceed = false;
        }

        PreExecutionResult { can_proceed, reasons }
    }

    /// Get config
    pub fn get_config(&self) -> &EnforcementConfig {
        &self.config
    }

    /// Update config
    pub fn update_config(&mut self, new_config: EnforcementConfig) {
        self.config = new_config;
    }

    /// Check if headless mode
    pub fn is_headless_mode(&self) -> bool {
        self.config.mode.as_deref() == Some("headless")
    }

    /// Reset
    pub fn reset(&self) {
        PermissionGate::reset();
        ViolationLogger::clear_violations();
    }
}

/// Enforcement result
pub struct EnforcementResult {
    pub allowed_commands: Vec<String>,
    pub blocked_commands: Vec<String>,
    pub violations: Vec<Violation>,
}

/// Pre-execution check result
pub struct PreExecutionResult {
    pub can_proceed: bool,
    pub reasons: Vec<String>,
}
