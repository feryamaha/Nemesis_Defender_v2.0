use regex::Regex;
use std::path::Path;

// Import from sibling module
use super::deny_list_loader::{check_content, DenyPattern};

// ============================================================
// NEMESIS CODE VALIDATOR
// Validacao semantica de codigo via regex rapido
// Roda dentro do PreToolUse hook para bloquear violacoes ANTES da edicao
// ============================================================

#[derive(Debug, Clone)]
pub struct CodeValidationResult {
    pub valid: bool,
    pub reason: Option<String>,
    pub rule: Option<String>,
    pub suggestion: Option<String>,
}

/// Lista de arquivos UI com concessao (smart/hibrido autorizado)
/// Ref: ui-separation-convention.md - Secao 9
const UI_EXCEPTIONS: &[&str] = &["Button.tsx", "Container.tsx", "InputPesquisaAjuda.tsx"];

/// Valida o conteudo de codigo proposto em uma operacao Edit/Write
pub fn validate_code_content(file_path: &str, new_string: Option<&str>) -> CodeValidationResult {
    let new_string = match new_string {
        Some(s) => s,
        None => {
            return CodeValidationResult {
                valid: true,
                reason: None,
                rule: None,
                suggestion: None,
            };
        }
    };

    if file_path.is_empty() {
        return CodeValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    let ext = Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    if ext != "ts" && ext != "tsx" {
        return CodeValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    let file_name = Path::new(file_path)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("");
    let normalized_path = file_path.replace('\\', "/");

    // === DENY-LIST DINAMICA (camada adicional — nao substitui funcoes abaixo) ===
    if let Some(deny_hit) = check_content(file_path, new_string) {
        return CodeValidationResult {
            valid: false,
            reason: Some(deny_hit.message),
            rule: Some(deny_hit.rule),
            suggestion: Some(deny_hit.suggestion),
        };
    }
    // === FIM DENY-LIST DINAMICA ===

    // REGRA 1: Proibir "any" (typescript-typing-convention.md secao 7)
    let any_result = check_any_usage(new_string);
    if !any_result.valid {
        return any_result;
    }

    // REGRA 2: useState/useEffect em componentes UI puros (ui-separation-convention.md)
    let ui_hooks_result = check_ui_hooks(&normalized_path, file_name, new_string);
    if !ui_hooks_result.valid {
        return ui_hooks_result;
    }

    // REGRA 3: type/interface inline em componentes reutilizaveis (typescript-typing-convention.md)
    let inline_type_result = check_inline_types(&normalized_path, file_name, new_string);
    if !inline_type_result.valid {
        return inline_type_result;
    }

    // REGRA 4: CSS inline / style tags (design-system-convention.md)
    let css_inline_result = check_css_inline(new_string);
    if !css_inline_result.valid {
        return css_inline_result;
    }

    // REGRA 5: Hooks condicionais (react-hooks-patterns-rules.md)
    let conditional_hooks_result = check_conditional_hooks(new_string);
    if !conditional_hooks_result.valid {
        return conditional_hooks_result;
    }

    // REGRA 6: Violacoes de seguranca em route handlers (Conformidade.md)
    let security_result = check_security_violations(&normalized_path, new_string);
    if !security_result.valid {
        return security_result;
    }

    // REGRA 7: Violacoes de arquitetura BFF (API-convention.md)
    let bff_result = check_bff_violations(&normalized_path, new_string);
    if !bff_result.valid {
        return bff_result;
    }

    // REGRA 8: Variaveis de ambiente expostas (Conformidade.md)
    let env_result = check_environment_variables(new_string);
    if !env_result.valid {
        return env_result;
    }

    // REGRA 9: Storage direto em hooks (API-convention.md)
    let storage_in_hooks_result = check_storage_in_hooks(&normalized_path, new_string);
    if !storage_in_hooks_result.valid {
        return storage_in_hooks_result;
    }

    // REGRA 10: Chamadas HTTP diretas em hooks (API-convention.md)
    let http_in_hooks_result = check_http_in_hooks(&normalized_path, new_string);
    if !http_in_hooks_result.valid {
        return http_in_hooks_result;
    }

    // REGRA 11: styled-jsx e CSS manual (design-system-convention.md)
    let styled_jsx_result = check_styled_jsx(new_string);

    // REGRA 12: Bloquear insercao manual de bypass eslint pelos modelos IA
    let bypass_insertion_result = check_bypass_insertion(new_string);
    if !bypass_insertion_result.valid {
        return bypass_insertion_result;
    }

    // REGRA 13: Bloquear insercao manual de smart component pelos modelos IA
    let smart_component_insertion_result = check_smart_component_insertion(new_string);
    if !smart_component_insertion_result.valid {
        return smart_component_insertion_result;
    }
    if !styled_jsx_result.valid {
        return styled_jsx_result;
    }

    // ADDED: gap-analysis-2026-02-23 | mirrors ESLint rule: no-unused-vars
    let unused_vars_result = check_unused_vars(new_string);
    if !unused_vars_result.valid {
        return unused_vars_result;
    }

    // ADDED: gap-analysis-2026-02-23 | mirrors ESLint rule: consistent-type-imports
    let consistent_type_imports_result = check_consistent_type_imports(new_string);
    if !consistent_type_imports_result.valid {
        return consistent_type_imports_result;
    }

    // ADDED: gap-analysis-2026-02-23 | mirrors ESLint rule: no-var-requires
    let no_var_requires_result = check_no_var_requires(new_string);
    if !no_var_requires_result.valid {
        return no_var_requires_result;
    }

    // ADDED: gap-analysis-2026-02-23 | mirrors ESLint rule: no-head-import-in-document
    let no_head_import_result = check_no_head_import_in_document(&normalized_path, new_string);
    if !no_head_import_result.valid {
        return no_head_import_result;
    }

    // ADDED: gap-analysis-2026-02-23 | mirrors ESLint rule: no-assign-module-variable
    let no_assign_module_result = check_no_assign_module_variable(new_string);
    if !no_assign_module_result.valid {
        return no_assign_module_result;
    }

    // ADDED: gap-analysis-2026-02-23 | mirrors ESLint rule: adjacent-overload-signatures
    let adjacent_overload_result = check_adjacent_overload_signatures(new_string);
    if !adjacent_overload_result.valid {
        return adjacent_overload_result;
    }

    // ADDED: gap-analysis-2026-02-23 | mirrors ESLint rule: exhaustive-deps (parcial)
    // PENDING_AST_IMPLEMENTATION: cobre apenas array vazio [] com corpo nao-trivial
    let exhaustive_deps_result = check_exhaustive_deps_basic(new_string);
    if !exhaustive_deps_result.valid {
        return exhaustive_deps_result;
    }

    // PENDING_AST_IMPLEMENTATION: jsx-no-undef
    // Deteccao de variaveis nao declaradas em JSX requer analise de escopo AST.
    // Regex produziria falsos positivos inaceitaveis — nao implementado.

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// REGRA 1: Detecta uso de "any" em TypeScript
// Ref: typescript-typing-convention.md - Secao 7
//
// Patterns detectados:
//   : any       (tipo explicito any)
//   as any      (type assertion para any)
//   <any>       (generic any)
//   any[]       (array de any)
//   any,        (any em lista de generics)
//   any>        (any fechando generic)
// =============================================================================
fn check_any_usage(new_string: &str) -> CodeValidationResult {
    let any_patterns = [
        Regex::new(r":\s*any\s*[;,)\]}>|&]").unwrap(), // : any; ou : any, ou : any) etc
        Regex::new(r":\s*any\s*$").unwrap(),           // : any no final da linha
        Regex::new(r"\bas\s+any\b").unwrap(),          // as any
        Regex::new(r"<any\s*>").unwrap(),              // <any>
        Regex::new(r":\s*any\s*\[").unwrap(),          // : any[
        Regex::new(r"\bany\s*\|").unwrap(),            // any | (union com any)
        Regex::new(r"\|\s*any\b").unwrap(),            // | any (union com any)
        Regex::new(r"Record<[^,]*,\s*any\s*>").unwrap(), // Record<string, any>
        Regex::new(r":\s*any\b(?!\w)").unwrap(),       // : any (nao seguido de letra)
    ];

    for pattern in &any_patterns {
        if pattern.is_match(new_string) {
            let lines: Vec<&str> = new_string.lines().collect();
            let matching_line = lines.iter().find(|line| pattern.is_match(line));
            let context = matching_line
                .map(|line| {
                    let trimmed = line.trim();
                    if trimmed.len() > 80 {
                        &trimmed[..80]
                    } else {
                        trimmed
                    }
                })
                .unwrap_or("");

            return CodeValidationResult {
                valid: false,
                reason: Some(format!(r#"Uso de "any" detectado. Linha: "{}""#, context)),
                rule: Some(".devin/rules/typescript-typing-convention.md - Secao 7".to_string()),
                suggestion: Some("Use tipos explicitos, unknown, generics ou tipos existentes em src/types/".to_string()),
            };
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// REGRA 2: Detecta useState/useEffect em componentes UI puros
// Ref: ui-separation-convention.md - Secao 4.1
//
// Componentes em src/components/ui/ devem ser puros (sem estado/efeitos)
// Excecoes: Button.tsx, Container.tsx, InputPesquisaAjuda.tsx
// =============================================================================
fn check_ui_hooks(
    normalized_path: &str,
    file_name: &str,
    new_string: &str,
) -> CodeValidationResult {
    let is_ui_component = normalized_path.contains("/components/ui/");
    let is_exception = UI_EXCEPTIONS.contains(&file_name);

    if !is_ui_component || is_exception {
        return CodeValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    let hook_patterns = [
        (Regex::new(r"\buseState\b").unwrap(), "useState"),
        (Regex::new(r"\buseEffect\b").unwrap(), "useEffect"),
        (Regex::new(r"\buseReducer\b").unwrap(), "useReducer"),
        (Regex::new(r"\buseContext\b").unwrap(), "useContext"),
    ];

    for (pattern, name) in &hook_patterns {
        if pattern.is_match(new_string) {
            return CodeValidationResult {
                valid: false,
                reason: Some(format!(r#"Hook "{}" detectado em componente UI puro: {}"#, name, file_name)),
                rule: Some(".devin/rules/ui-separation-convention.md - Secao 4.1".to_string()),
                suggestion: Some(format!("Mova logica de estado para src/hooks/. Componentes em src/components/ui/ devem ser puros. Excecoes: {}", UI_EXCEPTIONS.join(", "))),
            };
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// REGRA 3: Detecta type/interface inline em componentes reutilizaveis
// Ref: typescript-typing-convention.md - Secao 4
//
// Componentes em src/components/ui/ e src/components/shared/ devem importar tipos
// de src/types/, nao definir inline.
// Excecoes: layout.tsx, page.tsx, componentes com concessao
// =============================================================================
fn check_inline_types(
    normalized_path: &str,
    file_name: &str,
    new_string: &str,
) -> CodeValidationResult {
    let is_reusable = normalized_path.contains("/components/ui/")
        || normalized_path.contains("/components/shared/");
    let is_entrypoint = Regex::new(r"^(layout|page)\.tsx$").unwrap().is_match(file_name);
    let is_exception = UI_EXCEPTIONS.contains(&file_name);

    if !is_reusable || is_entrypoint || is_exception {
        return CodeValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    let type_def_patterns = [
        Regex::new(r"^export\s+(interface|type)\s+\w+").unwrap(),
        Regex::new(r"^(interface|type)\s+\w+").unwrap(),
    ];

    for pattern in &type_def_patterns {
        if pattern.is_match(new_string) {
            let lines: Vec<&str> = new_string.lines().collect();
            for line in &lines {
                if pattern.is_match(line) && !line.trim_start().starts_with("import") {
                    return CodeValidationResult {
                        valid: false,
                        reason: Some(format!("Definicao de tipo inline em componente reutilizavel: {}", file_name)),
                        rule: Some(".devin/rules/typescript-typing-convention.md - Secao 4".to_string()),
                        suggestion: Some("Mova tipos para src/types/. Use import type { ... } no componente.".to_string()),
                    };
                }
            }
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// REGRA 4: Detecta CSS inline e style tags
// Ref: design-system-convention.md - Secao 5
//
// Toda estilizacao deve usar classes Tailwind via tailwind.config.ts.
// CSS inline, style tags e estilos manuais sao proibidos.
// =============================================================================
fn check_css_inline(new_string: &str) -> CodeValidationResult {
    let css_patterns = [
        (Regex::new(r"\bstyle\s*=\s*\{\{").unwrap(), "CSS inline (style={{...}})"),
        (Regex::new(r"<style[\s>]").unwrap(), "Tag <style>"),
        (Regex::new(r"<style\s+jsx").unwrap(), "styled-jsx"),
    ];

    for (pattern, name) in &css_patterns {
        if pattern.is_match(new_string) {
            return CodeValidationResult {
                valid: false,
                reason: Some(format!("{} detectado. Proibido por design-system-convention.md", name)),
                rule: Some(".devin/rules/design-system-convention.md - Secao 5".to_string()),
                suggestion: Some("Use classes Tailwind definidas no tailwind.config.ts. CSS manual e proibido.".to_string()),
            };
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// REGRA 5: Detecta hooks condicionais (useState/useEffect dentro de if/else)
// Ref: react-hooks-patterns-rules.md - Secao 3.1
//
// Patterns detectados:
//   if (...) { useState(...) }
//   if (...) { useEffect(...) }
//   else { useState(...) }
//   ternario com hooks
//   hooks apos early return
// =============================================================================
fn check_conditional_hooks(new_string: &str) -> CodeValidationResult {
    let lines: Vec<&str> = new_string.lines().collect();

    let hook_patterns = [
        Regex::new(r"\buseState\s*\(").unwrap(),
        Regex::new(r"\buseEffect\s*\(").unwrap(),
        Regex::new(r"\buseReducer\s*\(").unwrap(),
        Regex::new(r"\buseContext\s*\(").unwrap(),
        Regex::new(r"\buseMemo\s*\(").unwrap(),
        Regex::new(r"\buseCallback\s*\(").unwrap(),
        Regex::new(r"\buseRef\s*\(").unwrap(),
    ];

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }

        let has_hook = hook_patterns.iter().any(|p| p.is_match(line));
        if !has_hook {
            continue;
        }

        let context_start = if i > 10 { i - 10 } else { 0 };
        let context_lines = &lines[context_start..=i];
        let context_text = context_lines.join("\n");

        let conditional_patterns = [
            Regex::new(r"\bif\s*\([^)]+\)\s*\{[^}]*useState").unwrap(),
            Regex::new(r"\bif\s*\([^)]+\)\s*\{[^}]*useEffect").unwrap(),
            Regex::new(r"\belse\s*\{[^}]*useState").unwrap(),
            Regex::new(r"\belse\s*\{[^}]*useEffect").unwrap(),
            Regex::new(r"\?\s*[^:]*\?\s*[^:]*useState").unwrap(),
            Regex::new(r"\?\s*[^:]*\?\s*[^:]*useEffect").unwrap(),
            Regex::new(r"return\s*[^;]*;[\s\S]*useState").unwrap(),
            Regex::new(r"return\s*[^;]*;[\s\S]*useEffect").unwrap(),
        ];

        for pattern in &conditional_patterns {
            if pattern.is_match(&context_text) {
                let line_num = i + 1;
                let context = if trimmed.len() > 60 {
                    &trimmed[..60]
                } else {
                    trimmed
                };
                return CodeValidationResult {
                    valid: false,
                    reason: Some(format!("Hook condicional detectado. Linha {}: \"{}\"", line_num, context)),
                    rule: Some(".devin/rules/react-hooks-patterns-rules.md - Secao 3.1".to_string()),
                    suggestion: Some("Mova todos os hooks para o topo do componente, antes de qualquer condicional. Hooks nunca podem ser chamados dentro de if/else/ternary/early-return.".to_string()),
                };
            }
        }

        // Verificacao adicional: indentacao inconsistente
        let hook_line_indent = line.chars().take_while(|c| c.is_whitespace()).count();
        let prev_lines_indent: Vec<usize> = lines[std::cmp::max(0, i.saturating_sub(5))..i]
            .iter()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with("//")
            })
            .map(|l| l.chars().take_while(|c| c.is_whitespace()).count())
            .collect();

        if !prev_lines_indent.is_empty() {
            let min_indent = *prev_lines_indent.iter().min().unwrap_or(&0);
            if hook_line_indent > min_indent {
                let prev_text = lines[std::cmp::max(0, i.saturating_sub(3))..i].join("\n");
                if Regex::new(r"\b(if|else|for|while|switch|case|try|catch)\b").unwrap().is_match(&prev_text) {
                    let context = if trimmed.len() > 60 { &trimmed[..60] } else { trimmed };
                    return CodeValidationResult {
                        valid: false,
                        reason: Some(format!("Hook possivelmente dentro de bloco condicional. Linha {}: \"{}\"", i + 1, context)),
                        rule: Some(".devin/rules/react-hooks-patterns-rules.md - Secao 3.1".to_string()),
                        suggestion: Some("Mova todos os hooks para o topo do componente, antes de qualquer estrutura de controle.".to_string()),
                    };
                }
            }
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// REGRA 6: Detecta violacoes de seguranca em route handlers
// Ref: Conformidade.md - Secao 3 (OWASP Security)
//
// Patterns detectados:
//   - Log de credenciais/senhas
//   - Tokens simplificados/sem assinatura
//   - Headers de seguranca removidos
//   - Bypass de autenticacao
//   - Rate limiting desabilitado
// =============================================================================
fn check_security_violations(normalized_path: &str, new_string: &str) -> CodeValidationResult {
    let is_route_handler = normalized_path.contains("/app/api/");
    if !is_route_handler {
        return CodeValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    let credential_patterns = [
        Regex::new(r"console\.log.*password").unwrap(),
        Regex::new(r"console\.log.*senha").unwrap(),
        Regex::new(r"console\.log.*token").unwrap(),
        Regex::new(r"console\.log.*credential").unwrap(),
        Regex::new(r"console\.log.*auth").unwrap(),
    ];

    for pattern in &credential_patterns {
        if pattern.is_match(new_string) {
            return CodeValidationResult {
                valid: false,
                reason: Some("Log de credenciais detectado em route handler. Violacao OWASP A03: Sensitive Data Exposure.".to_string()),
                rule: Some(".devin/rules/Conformidade.md - Secao 3 (OWASP Security)".to_string()),
                suggestion: Some("Remova logs de credenciais. Use logging seguro sem dados sensiveis.".to_string()),
            };
        }
    }

    let token_patterns = [
        Regex::new(r"bypass.*token").unwrap(),
        Regex::new(r"fake.*token").unwrap(),
        Regex::new(r"simplified.*token").unwrap(),
        Regex::new(r"token.*\d{4,}").unwrap(),
        Regex::new(r"token.*test").unwrap(),
    ];

    for pattern in &token_patterns {
        if pattern.is_match(new_string) {
            return CodeValidationResult {
                valid: false,
                reason: Some("Token de autenticacao simplificado ou bypass detectado. Violacao OWASP A07: Identification and Authentication Failures.".to_string()),
                rule: Some(".devin/rules/Conformidade.md - Secao 3 (OWASP Security)".to_string()),
                suggestion: Some("Use tokens JWT properly signed com expiracao adequada. Nunca implemente bypass de autenticacao.".to_string()),
            };
        }
    }

    let security_header_patterns = [
        Regex::new(r"Access-Control-Allow-Origin:\s*\*").unwrap(),
        Regex::new(r"security.*disabled").unwrap(),
        Regex::new(r"CSP.*removed").unwrap(),
        Regex::new(r"headers.*security.*removed").unwrap(),
    ];

    for pattern in &security_header_patterns {
        if pattern.is_match(new_string) {
            return CodeValidationResult {
                valid: false,
                reason: Some("Headers de seguranca removidos ou desabilitados. Violacao OWASP A05: Security Misconfiguration.".to_string()),
                rule: Some(".devin/rules/Conformidade.md - Secao 3 (OWASP Security)".to_string()),
                suggestion: Some("Mantenha headers de seguranca (CSP, CORS, HSTS). Nunca desabilite controles de seguranca.".to_string()),
            };
        }
    }

    let sensitive_data_patterns = [
        Regex::new(r"hashedPassword.*:").unwrap(),
        Regex::new(r"password.*:").unwrap(),
        Regex::new(r"senha.*:").unwrap(),
        Regex::new(r"secret.*:").unwrap(),
        Regex::new(r"debug.*true").unwrap(),
    ];

    for pattern in &sensitive_data_patterns {
        if pattern.is_match(new_string) {
            return CodeValidationResult {
                valid: false,
                reason: Some("Dados sensiveis expostos na resposta. Violacao OWASP A03: Sensitive Data Exposure.".to_string()),
                rule: Some(".devin/rules/Conformidade.md - Secao 3 (OWASP Security)".to_string()),
                suggestion: Some("Remova dados sensiveis (senhas, hashes, secrets) das respostas da API.".to_string()),
            };
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// REGRA 7: Detecta violacoes de arquitetura BFF
// Ref: API-convention.md - Backend-for-Frontend Pattern
//
// Patterns detectados:
//   - Chamadas diretas para API externa em componentes
//   - Uso de axios/fetch direto sem BFF
//   - Componentes fazendo integracao externa
// =============================================================================
fn check_bff_violations(normalized_path: &str, new_string: &str) -> CodeValidationResult {
    let is_component = normalized_path.contains("/components/");
    if !is_component {
        return CodeValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    let direct_api_patterns = [
        Regex::new(r#"axios\.(get|post|put|delete)\s*\(\s*['"]https?://"#).unwrap(),
        Regex::new(r#"fetch\s*\(\s*['"]https?://"#).unwrap(),
        Regex::new(r"api\.\w+.*https?://").unwrap(),
        Regex::new(r"http\.(get|post|put|delete)").unwrap(),
    ];

    for pattern in &direct_api_patterns {
        if pattern.is_match(new_string) {
            return CodeValidationResult {
                valid: false,
                reason: Some("Chamada direta para API externa detectada em componente. Violacao do padrao BFF (Backend-for-Frontend).".to_string()),
                rule: Some(".devin/rules/API-convention.md - Secao 2 (BFF Pattern)".to_string()),
                suggestion: Some("Use route handlers em src/app/api/ para integracoes externas. Componentes devem consumir apenas o BFF.".to_string()),
            };
        }
    }

    let storage_patterns = [
        Regex::new(r"localStorage\.").unwrap(),
        Regex::new(r"sessionStorage\.").unwrap(),
        Regex::new(r"window\.localStorage").unwrap(),
        Regex::new(r"window\.sessionStorage").unwrap(),
    ];

    for pattern in &storage_patterns {
        if pattern.is_match(new_string) {
            return CodeValidationResult {
                valid: false,
                reason: Some("Uso de storage direto detectado em componente. Violacao da separacao de responsabilidades.".to_string()),
                rule: Some(".devin/rules/API-convention.md - Secao 3 (Layer Architecture)".to_string()),
                suggestion: Some("Use hooks/context para gerenciamento de estado e storage. Componentes nao devem acessar storage diretamente.".to_string()),
            };
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// REGRA 8: Detecta variaveis de ambiente expostas
// Ref: Conformidade.md - Secao 3.3 (Sensitive Data Protection)
//
// Patterns detectados:
//   - NEXT_PUBLIC_* em componentes
//   - Variaveis sensiveis no client-side
//   - Exposicao de secrets/configs
// =============================================================================
fn check_environment_variables(new_string: &str) -> CodeValidationResult {
    let public_env_patterns = [
        Regex::new(r"NEXT_PUBLIC_[A-Z_]+").unwrap(),
        Regex::new(r"process\.env\.NEXT_PUBLIC_[A-Z_]+").unwrap(),
    ];

    let mut matches = Vec::new();
    for pattern in &public_env_patterns {
        for cap in pattern.find_iter(new_string) {
            matches.push(cap.as_str().to_string());
        }
    }

    if !matches.is_empty() {
        let unique_vars: Vec<String> = matches
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        return CodeValidationResult {
            valid: false,
            reason: Some(format!("Variaveis de ambiente publicas detectadas: {}. Violacao OWASP A03: Sensitive Data Exposure.", unique_vars.join(", "))),
            rule: Some(".devin/rules/Conformidade.md - Secao 3.3 (Sensitive Data Protection)".to_string()),
            suggestion: Some("Mova variaveis de ambiente para route handlers (server-side). Nunca exponha configs sensiveis no client-side.".to_string()),
        };
    }

    let secret_patterns = [
        Regex::new(r#"api[_-]?key['"]?\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]"#).unwrap(),
        Regex::new(r#"secret['"]?\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]"#).unwrap(),
        Regex::new(r#"token['"]?\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]"#).unwrap(),
    ];

    for pattern in &secret_patterns {
        if pattern.is_match(new_string) {
            return CodeValidationResult {
                valid: false,
                reason: Some("Possivel secret ou API key hardcoded detectado. Violacao OWASP A02: Cryptographic Failures.".to_string()),
                rule: Some(".devin/rules/Conformidade.md - Secao 3.3 (Sensitive Data Protection)".to_string()),
                suggestion: Some("Use variaveis de ambiente server-side para secrets. Nunca hardcode credenciais no codigo.".to_string()),
            };
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// REGRA 9: Detecta storage direto em hooks
// Ref: API-convention.md - Secao 3 (Layer Architecture)
// =============================================================================
fn check_storage_in_hooks(normalized_path: &str, new_string: &str) -> CodeValidationResult {
    let is_hook = normalized_path.ends_with(".hook.ts") || normalized_path.contains("/hooks/");
    if !is_hook {
        return CodeValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    let storage_patterns = [
        Regex::new(r"localStorage\.").unwrap(),
        Regex::new(r"sessionStorage\.").unwrap(),
        Regex::new(r"window\.localStorage").unwrap(),
        Regex::new(r"window\.sessionStorage").unwrap(),
        Regex::new(r"\.getItem\(").unwrap(),
        Regex::new(r"\.setItem\(").unwrap(),
        Regex::new(r"\.removeItem\(").unwrap(),
        Regex::new(r"\.clear\(").unwrap(),
    ];

    for pattern in &storage_patterns {
        if pattern.is_match(new_string) {
            return CodeValidationResult {
                valid: false,
                reason: Some("Uso de storage direto detectado em hook. Violacao da arquitetura BFF.".to_string()),
                rule: Some(".devin/rules/API-convention.md - Secao 3 (Layer Architecture)".to_string()),
                suggestion: Some("Use context providers ou hooks de mais alto nivel para gerenciamento de storage.".to_string()),
            };
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// REGRA 10: Detecta chamadas HTTP diretas em hooks
// Ref: API-convention.md - Secao 2 (BFF Pattern)
// =============================================================================
fn check_http_in_hooks(normalized_path: &str, new_string: &str) -> CodeValidationResult {
    let is_hook = normalized_path.ends_with(".hook.ts") || normalized_path.contains("/hooks/");
    if !is_hook {
        return CodeValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    let http_patterns = [
        Regex::new(r#"fetch\s*\(\s*['"]https?://"#).unwrap(),
        Regex::new(r#"axios\.(get|post|put|delete|patch)\s*\(\s*['"]https?://"#).unwrap(),
        Regex::new(r"api\.\w+.*https?://").unwrap(),
        Regex::new(r"http\.(get|post|put|delete|patch)").unwrap(),
        Regex::new(r"XMLHttpRequest").unwrap(),
    ];

    for pattern in &http_patterns {
        if pattern.is_match(new_string) {
            return CodeValidationResult {
                valid: false,
                reason: Some("Chamada HTTP direta detectada em hook. Violacao do padrao BFF.".to_string()),
                rule: Some(".devin/rules/API-convention.md - Secao 2 (BFF Pattern)".to_string()),
                suggestion: Some("Use route handlers em src/app/api/ para chamadas HTTP. Hooks devem consumir apenas o BFF.".to_string()),
            };
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// REGRA 11: Detecta styled-jsx e CSS manual
// Ref: design-system-convention.md - Secao 5
// =============================================================================
fn check_styled_jsx(new_string: &str) -> CodeValidationResult {
    let styled_jsx_patterns = [
        Regex::new(r"<style\s+jsx>").unwrap(),
        Regex::new(r"<style\s+jsx\s+global>").unwrap(),
        Regex::new(r"</style\s*jsx>").unwrap(),
        Regex::new(r"</style\s*jsx\s*global>").unwrap(),
        Regex::new(r"style jsx").unwrap(),
        Regex::new(r"styled-jsx").unwrap(),
    ];

    for pattern in &styled_jsx_patterns {
        if pattern.is_match(new_string) {
            return CodeValidationResult {
                valid: false,
                reason: Some("styled-jsx detectado. Proibido por design-system-convention.md.".to_string()),
                rule: Some(".devin/rules/design-system-convention.md - Secao 5".to_string()),
                suggestion: Some("Use classes Tailwind definidas no tailwind.config.ts. styled-jsx e CSS manual sao proibidos.".to_string()),
            };
        }
    }

    let css_patterns = [
        Regex::new(r#"<link\s+rel=["']stylesheet["']"#).unwrap(),
        Regex::new(r"@import\s+url").unwrap(),
        Regex::new(r"cssText\s*:").unwrap(),
    ];

    for pattern in &css_patterns {
        if pattern.is_match(new_string) {
            return CodeValidationResult {
                valid: false,
                reason: Some("CSS manual detectado. Proibido por design-system-convention.md.".to_string()),
                rule: Some(".devin/rules/design-system-convention.md - Secao 5".to_string()),
                suggestion: Some("Use classes Tailwind definidas no tailwind.config.ts. CSS manual e proibido.".to_string()),
            };
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// REGRA 12: Bloquear insercao manual de bypass eslint pelos modelos IA
// Ref: origin-rules.md - Secao 7 (Comportamento IA e Limitacoes Tecnicas)
// =============================================================================
fn check_bypass_insertion(new_string: &str) -> CodeValidationResult {
    let lines: Vec<&str> = new_string.lines().collect();

    for line in &lines {
        let trimmed = line.trim();

        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("*") {
            continue;
        }

        let bypass_patterns = [
            (Regex::new(r"eslint-disable-next-line").unwrap(), "eslint-disable-next-line"),
            (Regex::new(r"eslint-disable").unwrap(), "eslint-disable"),
            (Regex::new(r"@ts-ignore").unwrap(), "@ts-ignore"),
            (Regex::new(r"@ts-nocheck").unwrap(), "@ts-nocheck"),
            (Regex::new(r"@ts-expect-error").unwrap(), "@ts-expect-error"),
        ];

        for (pattern, name) in &bypass_patterns {
            if pattern.is_match(line) {
                return CodeValidationResult {
                    valid: false,
                    reason: Some(format!("Tentativa de inserir bypass manual detectada: \"{}\". Modelos IA nao tem autorizacao para adicionar bypass de regras.", name)),
                    rule: Some(".devin/rules/origin-rules.md - Secao 7 (Autorizacao de Bypass)".to_string()),
                    suggestion: Some("Apenas usuarios podem adicionar bypass quando nao ha solucao tecnica. Remova o bypass ou encontre solucao alternativa.".to_string()),
                };
            }
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// REGRA 13: Bloquear insercao manual de smart component pelos modelos IA
// Ref: ui-separation-convention.md - Secao 9 (Smart Components)
// =============================================================================
fn check_smart_component_insertion(new_string: &str) -> CodeValidationResult {
    let lines: Vec<&str> = new_string.lines().collect();

    for line in &lines {
        let smart_component_patterns = [
            Regex::new(r"//\s*SMART\s*COMPONENT").unwrap(),
            Regex::new(r"/\*\s*SMART\s*COMPONENT").unwrap(),
            Regex::new(r"\*\s*SMART\s*COMPONENT").unwrap(),
        ];

        for pattern in &smart_component_patterns {
            if pattern.is_match(line) {
                return CodeValidationResult {
                    valid: false,
                    reason: Some("Designacao de smart component nao pode ser feita manualmente. Apenas o sistema Nemesis pode marcar componentes como smart via smart-components.json.".to_string()),
                    rule: Some(".devin/rules/ui-separation-convention.md - Secao 9 (Designacao de Smart Components)".to_string()),
                    suggestion: Some("Para designar um smart component: (1) Leia .nemesis/smart-components.json para ver os ja designados. (2) Solicite ao usuario que execute: bun nemesis:smart add NomeDoComponente. (3) Nunca insira comentarios de designacao manualmente no codigo.".to_string()),
                };
            }
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// =============================================================================
// ADDED: gap-analysis-2026-02-23
// Funcoes adicionadas abaixo
// =============================================================================

// REGRA 14: Detecta variaveis declaradas e nunca referenciadas
fn check_unused_vars(new_string: &str) -> CodeValidationResult {
    let lines: Vec<&str> = new_string.lines().collect();
    let mut declared_vars: Vec<String> = Vec::new();

    for line in &lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }

        let decl_match = Regex::new(r"^(?:export\s+)?(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*[=:]").unwrap();
        if let Some(caps) = decl_match.captures(trimmed) {
            declared_vars.push(caps[1].to_string());
        }
    }

    let full_text = new_string;

    for var_name in &declared_vars {
        let usage_pattern = Regex::new(&format!(r"\b{}\b", regex::escape(var_name))).unwrap();
        let all_matches: Vec<_> = usage_pattern.find_iter(full_text).collect();
        if all_matches.len() <= 1 && !var_name.starts_with('_') {
            return CodeValidationResult {
                valid: false,
                reason: Some(format!("Variavel possivelmente nao utilizada: \"{}\". Possivel violacao ESLint no-unused-vars.", var_name)),
                rule: Some(".devin/rules/typescript-typing-convention.md - Secao 7".to_string()),
                suggestion: Some("Remova variaveis nao utilizadas ou use prefixo underscore (_varName) para indicar uso intencional.".to_string()),
            };
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// REGRA 15: Detecta imports de tipos sem keyword 'type'
fn check_consistent_type_imports(new_string: &str) -> CodeValidationResult {
    for line in new_string.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.contains("import type") {
            continue;
        }

        let import_match = Regex::new(r#"^import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]"#).unwrap();
        if let Some(caps) = import_match.captures(trimmed) {
            let imported_items: Vec<&str> = caps[1]
                .split(',')
                .map(|s| s.trim().split(" as ").next().unwrap_or("").trim())
                .collect();

            let type_name_pattern = Regex::new(r"(Props|Type|Config|Interface|Options|Enum|Schema|Shape)$").unwrap();
            let type_items: Vec<&str> = imported_items
                .iter()
                .filter(|item| type_name_pattern.is_match(item))
                .copied()
                .collect();

            if !type_items.is_empty() {
                return CodeValidationResult {
                    valid: false,
                    reason: Some(format!("Import de tipo sem 'type' keyword: {}. Violacao ESLint consistent-type-imports.", type_items.join(", "))),
                    rule: Some(".devin/rules/typescript-typing-convention.md - Secao 4".to_string()),
                    suggestion: Some(format!("Use: import type {{ {} }} from '{}';", type_items.join(", "), &caps[2])),
                };
            }
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// REGRA 16: Detecta require() em arquivos TypeScript
fn check_no_var_requires(new_string: &str) -> CodeValidationResult {
    let require_pattern = Regex::new(r#"\brequire\s*\(\s*['"][^'"]+['"]\s*\)"#).unwrap();

    if require_pattern.is_match(new_string) {
        let lines: Vec<&str> = new_string.lines().collect();
        let match_line = lines.iter().find(|l| require_pattern.is_match(l));
        let context = match_line.map(|l| l.trim()).unwrap_or("");
        let context_short = if context.len() > 80 { &context[..80] } else { context };

        return CodeValidationResult {
            valid: false,
            reason: Some(format!(r#"require() detectado em arquivo TypeScript: \"{}\". Violacao ESLint no-var-requires."#, context_short)),
            rule: Some(".devin/rules/typescript-typing-convention.md - Secao 7".to_string()),
            suggestion: Some("Use import ES6: import module from 'module'; ou import { named } from 'module';".to_string()),
        };
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// REGRA 17: Detecta import de Head from next/head em arquivos _document
fn check_no_head_import_in_document(normalized_path: &str, new_string: &str) -> CodeValidationResult {
    let is_document_file = Regex::new(r"_document\.(tsx?|jsx?)$").unwrap().is_match(normalized_path);
    if !is_document_file {
        return CodeValidationResult {
            valid: true,
            reason: None,
            rule: None,
            suggestion: None,
        };
    }

    let head_import_pattern = Regex::new(r#"import.*\bHead\b.*from\s+['"]next/head['"]"#).unwrap();
    if head_import_pattern.is_match(new_string) {
        return CodeValidationResult {
            valid: false,
            reason: Some("Import de Head from 'next/head' detectado em arquivo _document. Violacao ESLint no-head-import-in-document.".to_string()),
            rule: Some(".devin/rules/Conformidade.md - Secao 3 (Next.js Security)".to_string()),
            suggestion: Some("Em _document, importe de 'next/document', nao de 'next/head'.".to_string()),
        };
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// REGRA 18: Detecta reatribuicao de variavel module (CommonJS)
fn check_no_assign_module_variable(new_string: &str) -> CodeValidationResult {
    let module_assign_pattern = Regex::new(r"\bmodule\.(exports|[a-zA-Z_$][\w$]*)\s*=").unwrap();

    if module_assign_pattern.is_match(new_string) {
        let lines: Vec<&str> = new_string.lines().collect();
        let match_line = lines.iter().find(|l| module_assign_pattern.is_match(l));
        let context = match_line.map(|l| l.trim()).unwrap_or("");
        let context_short = if context.len() > 80 { &context[..80] } else { context };

        return CodeValidationResult {
            valid: false,
            reason: Some(format!("Reatribuicao de module detectada: \"{}\". Violacao ESLint no-assign-module-variable.", context_short)),
            rule: Some(".devin/rules/Conformidade.md - Secao 3 (Module Security)".to_string()),
            suggestion: Some("Use export statements ES6: export default ou export const.".to_string()),
        };
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// REGRA 19: Detecta assinaturas de overload nao adjacentes
fn check_adjacent_overload_signatures(new_string: &str) -> CodeValidationResult {
    let lines: Vec<&str> = new_string.lines().collect();
    let mut overload_map: std::collections::HashMap<String, Vec<usize>> = std::collections::HashMap::new();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }

        let overload_match = Regex::new(r"^(?:export\s+)?function\s+(\w+)\s*\([^)]*\)\s*:\s*[^{;]+;\s*$")
            .unwrap();
        if let Some(caps) = overload_match.captures(trimmed) {
            let fn_name = caps[1].to_string();
            overload_map.entry(fn_name).or_default().push(i);
        }
    }

    for (fn_name, line_numbers) in &overload_map {
        if line_numbers.len() < 2 {
            continue;
        }

        for i in 1..line_numbers.len() {
            if line_numbers[i] - line_numbers[i - 1] > 3 {
                return CodeValidationResult {
                    valid: false,
                    reason: Some(format!("Overloads da funcao \"{}\" nao sao adjacentes. Violacao ESLint adjacent-overload-signatures.", fn_name)),
                    rule: Some(".devin/rules/typescript-typing-convention.md - Secao 7".to_string()),
                    suggestion: Some(format!("Agrupe todas as assinaturas de overload de \"{}\" juntas, antes da implementacao.", fn_name)),
                };
            }
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}

// REGRA 20: Detecta useEffect com array de dependencias vazio e corpo nao-trivial
fn check_exhaustive_deps_basic(new_string: &str) -> CodeValidationResult {
    let lines: Vec<&str> = new_string.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }

        if Regex::new(r"\buseEffect\s*\(").unwrap().is_match(line) {
            let context_block = lines[i..std::cmp::min(i + 15, lines.len())].join("\n");

            let empty_deps_pattern = Regex::new(r"useEffect\s*\(\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{[\s\S]*?\}\s*,\s*\[\s*\]").unwrap();
            if empty_deps_pattern.is_match(&context_block) {
                let body_match = Regex::new(r"useEffect\s*\(\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{([\s\S]*?)\}\s*,\s*\[\s*\]").unwrap()
                    .captures(&context_block);
                if let Some(caps) = body_match {
                    if !caps[1].trim().is_empty() {
                        return CodeValidationResult {
                            valid: false,
                            reason: Some("useEffect com array de dependencias vazio [] e corpo nao-trivial detectado. Possivel violacao ESLint exhaustive-deps.".to_string()),
                            rule: Some(".devin/rules/react-hooks-patterns-rules.md - Secao 3.2".to_string()),
                            suggestion: Some("Adicione todas as variaveis usadas no useEffect ao array de dependencias.".to_string()),
                        };
                    }
                }
            }
        }
    }

    CodeValidationResult {
        valid: true,
        reason: None,
        rule: None,
        suggestion: None,
    }
}
