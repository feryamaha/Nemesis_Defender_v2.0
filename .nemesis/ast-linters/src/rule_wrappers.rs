/// Wrappers para visitors existentes implementando o trait LintRule.
///
/// Este módulo adapta os visitantes existentes para o novo sistema dinâmico
/// de regras, permitindo que sejam ativados/desativados dinamicamente.

use crate::lint_rule::{LintRule, Severity, Context, Violation, RuleCategory};
use crate::parser::ParsedTree;
use crate::visitors;

/// Wrapper para any_via_alias visitor.
pub struct AnyViaAliasRule;

impl LintRule for AnyViaAliasRule {
    fn name(&self) -> &str {
        "any-via-alias"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Suspicious
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::any_via_alias::visit(tree, ctx.source)
    }

    fn supported_languages(&self) -> &[crate::language::Language] {
        &[
            crate::language::Language::TypeScript,
            crate::language::Language::TypeScriptReact,
        ]
    }
}

/// Wrapper para conditional_hooks visitor.
pub struct ConditionalHooksRule;

impl LintRule for ConditionalHooksRule {
    fn name(&self) -> &str {
        "conditional-hooks"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Correctness
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::conditional_hooks::visit(tree, ctx.source)
    }

    fn supported_languages(&self) -> &[crate::language::Language] {
        &[
            crate::language::Language::TypeScriptReact,
            crate::language::Language::JavaScriptReact,
        ]
    }
}

/// Wrapper para fetch_in_component visitor.
pub struct FetchInComponentRule;

impl LintRule for FetchInComponentRule {
    fn name(&self) -> &str {
        "fetch-in-component"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Suspicious
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::fetch_in_component::visit(tree, ctx.source)
    }

    fn supported_languages(&self) -> &[crate::language::Language] {
        &[
            crate::language::Language::TypeScriptReact,
            crate::language::Language::JavaScriptReact,
        ]
    }
}

/// Wrapper para exhaustive_deps visitor.
pub struct ExhaustiveDepsRule;

impl LintRule for ExhaustiveDepsRule {
    fn name(&self) -> &str {
        "exhaustive-deps"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Correctness
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::exhaustive_deps::visit(tree, ctx.source)
    }

    fn supported_languages(&self) -> &[crate::language::Language] {
        &[
            crate::language::Language::TypeScriptReact,
            crate::language::Language::JavaScriptReact,
        ]
    }
}

/// Wrapper para unused_vars visitor.
pub struct UnusedVarsRule;

impl LintRule for UnusedVarsRule {
    fn name(&self) -> &str {
        "unused-vars"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Correctness
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::unused_vars::visit(tree, ctx.source)
    }

    fn supported_languages(&self) -> &[crate::language::Language] {
        &[
            crate::language::Language::TypeScript,
            crate::language::Language::TypeScriptReact,
            crate::language::Language::JavaScript,
            crate::language::Language::JavaScriptReact,
        ]
    }
}

/// Wrapper para no_floating_promises visitor.
pub struct NoFloatingPromisesRule;

impl LintRule for NoFloatingPromisesRule {
    fn name(&self) -> &str {
        "no-floating-promises"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Correctness
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_floating_promises::visit(tree, ctx.source)
    }

    fn supported_languages(&self) -> &[crate::language::Language] {
        &[
            crate::language::Language::TypeScript,
            crate::language::Language::TypeScriptReact,
            crate::language::Language::JavaScript,
            crate::language::Language::JavaScriptReact,
        ]
    }
}

/// Wrapper para no_unsafe_assignment visitor.
pub struct NoUnsafeAssignmentRule;

impl LintRule for NoUnsafeAssignmentRule {
    fn name(&self) -> &str {
        "no-unsafe-assignment"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Suspicious
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_unsafe_assignment::visit(tree, ctx.source)
    }

    fn supported_languages(&self) -> &[crate::language::Language] {
        &[
            crate::language::Language::TypeScript,
            crate::language::Language::TypeScriptReact,
        ]
    }
}

/// Wrapper para jsx_no_target_blank visitor.
pub struct JsxNoTargetBlankRule;

impl LintRule for JsxNoTargetBlankRule {
    fn name(&self) -> &str {
        "jsx-no-target-blank"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Security
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::jsx_no_target_blank::visit(tree, ctx.source)
    }

    fn supported_languages(&self) -> &[crate::language::Language] {
        &[
            crate::language::Language::TypeScriptReact,
            crate::language::Language::JavaScriptReact,
        ]
    }
}

/// Wrapper para no_console visitor.
pub struct NoConsoleRule;

impl LintRule for NoConsoleRule {
    fn name(&self) -> &str {
        "no-console"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Style
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_console::visit(tree, ctx.source)
    }

    fn supported_languages(&self) -> &[crate::language::Language] {
        &[
            crate::language::Language::TypeScript,
            crate::language::Language::TypeScriptReact,
            crate::language::Language::JavaScript,
            crate::language::Language::JavaScriptReact,
        ]
    }
}

/// Wrapper para prefer_readonly visitor.
pub struct PreferReadonlyRule;

impl LintRule for PreferReadonlyRule {
    fn name(&self) -> &str {
        "prefer-readonly"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Style
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::prefer_readonly::visit(tree, ctx.source)
    }

    fn supported_languages(&self) -> &[crate::language::Language] {
        &[
            crate::language::Language::TypeScript,
            crate::language::Language::TypeScriptReact,
        ]
    }
}

// ===== SECURITY =====

pub struct NoDangerouslySetInnerHtmlRule;

impl LintRule for NoDangerouslySetInnerHtmlRule {
    fn name(&self) -> &str { "no-dangerously-set-inner-html" }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_dangerously_set_inner_html::visit(tree, ctx.source)
    }
    fn supported_languages(&self) -> &[crate::language::Language] {
        &[crate::language::Language::TypeScriptReact, crate::language::Language::JavaScriptReact]
    }
}

pub struct NoGlobalEvalRule;

impl LintRule for NoGlobalEvalRule {
    fn name(&self) -> &str { "no-global-eval" }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_global_eval::visit(tree, ctx.source)
    }
}

pub struct NoSecretsRule;

impl LintRule for NoSecretsRule {
    fn name(&self) -> &str { "no-secrets" }
    fn category(&self) -> RuleCategory { RuleCategory::Security }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_secrets::visit(tree, ctx.source)
    }
}

// ===== SUSPICIOUS =====

pub struct NoAssignInExpressionsRule;

impl LintRule for NoAssignInExpressionsRule {
    fn name(&self) -> &str { "no-assign-in-expressions" }
    fn category(&self) -> RuleCategory { RuleCategory::Suspicious }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_assign_in_expressions::visit(tree, ctx.source)
    }
}

pub struct NoFallthroughSwitchClauseRule;

impl LintRule for NoFallthroughSwitchClauseRule {
    fn name(&self) -> &str { "no-fallthrough-switch-clause" }
    fn category(&self) -> RuleCategory { RuleCategory::Suspicious }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_fallthrough_switch_clause::visit(tree, ctx.source)
    }
}

pub struct NoDoubleEqualsRule;

impl LintRule for NoDoubleEqualsRule {
    fn name(&self) -> &str { "no-double-equals" }
    fn category(&self) -> RuleCategory { RuleCategory::Suspicious }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_double_equals::visit(tree, ctx.source)
    }
}

pub struct NoDuplicateCaseRule;

impl LintRule for NoDuplicateCaseRule {
    fn name(&self) -> &str { "no-duplicate-case" }
    fn category(&self) -> RuleCategory { RuleCategory::Suspicious }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_duplicate_case::visit(tree, ctx.source)
    }
}

pub struct NoAsyncPromiseExecutorRule;

impl LintRule for NoAsyncPromiseExecutorRule {
    fn name(&self) -> &str { "no-async-promise-executor" }
    fn category(&self) -> RuleCategory { RuleCategory::Suspicious }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_async_promise_executor::visit(tree, ctx.source)
    }
}

pub struct NoDebuggerRule;

impl LintRule for NoDebuggerRule {
    fn name(&self) -> &str { "no-debugger" }
    fn category(&self) -> RuleCategory { RuleCategory::Suspicious }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_debugger::visit(tree, ctx.source)
    }
}

pub struct NoTemplateCurlyInStringRule;

impl LintRule for NoTemplateCurlyInStringRule {
    fn name(&self) -> &str { "no-template-curly-in-string" }
    fn category(&self) -> RuleCategory { RuleCategory::Suspicious }
    fn default_severity(&self) -> Severity { Severity::Warning }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_template_curly_in_string::visit(tree, ctx.source)
    }
}

pub struct NoDuplicateJsxPropsRule;

impl LintRule for NoDuplicateJsxPropsRule {
    fn name(&self) -> &str { "no-duplicate-jsx-props" }
    fn category(&self) -> RuleCategory { RuleCategory::Suspicious }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_duplicate_jsx_props::visit(tree, ctx.source)
    }
    fn supported_languages(&self) -> &[crate::language::Language] {
        &[crate::language::Language::TypeScriptReact, crate::language::Language::JavaScriptReact]
    }
}

pub struct NoEmptyBlockStatementsRule;

impl LintRule for NoEmptyBlockStatementsRule {
    fn name(&self) -> &str { "no-empty-block-statements" }
    fn category(&self) -> RuleCategory { RuleCategory::Suspicious }
    fn default_severity(&self) -> Severity { Severity::Warning }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_empty_block_statements::visit(tree, ctx.source)
    }
}

pub struct NoVarRule;

impl LintRule for NoVarRule {
    fn name(&self) -> &str { "no-var" }
    fn category(&self) -> RuleCategory { RuleCategory::Suspicious }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_var::visit(tree, ctx.source)
    }
}

// ===== CORRECTNESS =====

pub struct NoConstantConditionRule;

impl LintRule for NoConstantConditionRule {
    fn name(&self) -> &str { "no-constant-condition" }
    fn category(&self) -> RuleCategory { RuleCategory::Correctness }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_constant_condition::visit(tree, ctx.source)
    }
}

pub struct NoUnsafeFinallyRule;

impl LintRule for NoUnsafeFinallyRule {
    fn name(&self) -> &str { "no-unsafe-finally" }
    fn category(&self) -> RuleCategory { RuleCategory::Correctness }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_unsafe_finally::visit(tree, ctx.source)
    }
}

pub struct NoSwitchDeclarationsRule;

impl LintRule for NoSwitchDeclarationsRule {
    fn name(&self) -> &str { "no-switch-declarations" }
    fn category(&self) -> RuleCategory { RuleCategory::Correctness }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_switch_declarations::visit(tree, ctx.source)
    }
}

pub struct NoEmptyPatternRule;

impl LintRule for NoEmptyPatternRule {
    fn name(&self) -> &str { "no-empty-pattern" }
    fn category(&self) -> RuleCategory { RuleCategory::Correctness }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_empty_pattern::visit(tree, ctx.source)
    }
}

pub struct NoUnsafeOptionalChainingRule;

impl LintRule for NoUnsafeOptionalChainingRule {
    fn name(&self) -> &str { "no-unsafe-optional-chaining" }
    fn category(&self) -> RuleCategory { RuleCategory::Correctness }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_unsafe_optional_chaining::visit(tree, ctx.source)
    }
}

pub struct NoVoidTypeReturnRule;

impl LintRule for NoVoidTypeReturnRule {
    fn name(&self) -> &str { "no-void-type-return" }
    fn category(&self) -> RuleCategory { RuleCategory::Correctness }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_void_type_return::visit(tree, ctx.source)
    }
    fn supported_languages(&self) -> &[crate::language::Language] {
        &[crate::language::Language::TypeScript, crate::language::Language::TypeScriptReact]
    }
}

// ===== COMPLEXITY =====

pub struct NoExtraBooleanCastRule;

impl LintRule for NoExtraBooleanCastRule {
    fn name(&self) -> &str { "no-extra-boolean-cast" }
    fn category(&self) -> RuleCategory { RuleCategory::Suspicious }
    fn default_severity(&self) -> Severity { Severity::Warning }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_extra_boolean_cast::visit(tree, ctx.source)
    }
}

// ===== PERFORMANCE =====

pub struct NoAwaitInLoopsRule;

impl LintRule for NoAwaitInLoopsRule {
    fn name(&self) -> &str { "no-await-in-loops" }
    fn category(&self) -> RuleCategory { RuleCategory::Suspicious }
    fn default_severity(&self) -> Severity { Severity::Error }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_await_in_loops::visit(tree, ctx.source)
    }
}

// ===== REACT (SEMANTIC-AWARE) =====

pub struct NoSetStateInEffectRule;

impl LintRule for NoSetStateInEffectRule {
    fn name(&self) -> &str { "no-set-state-in-effect" }
    fn category(&self) -> RuleCategory { RuleCategory::Correctness }
    fn default_severity(&self) -> Severity { Severity::Warning }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_set_state_in_effect::visit(tree, ctx.source)
    }
    fn supported_languages(&self) -> &[crate::language::Language] {
        &[crate::language::Language::TypeScriptReact, crate::language::Language::JavaScriptReact]
    }
}

pub struct NoImpureInRenderRule;

impl LintRule for NoImpureInRenderRule {
    fn name(&self) -> &str { "no-impure-in-render" }
    fn category(&self) -> RuleCategory { RuleCategory::Correctness }
    fn default_severity(&self) -> Severity { Severity::Warning }
    fn visit(&self, tree: &ParsedTree, ctx: &Context) -> Vec<Violation> {
        visitors::no_impure_in_render::visit(tree, ctx.source)
    }
    fn supported_languages(&self) -> &[crate::language::Language] {
        &[crate::language::Language::TypeScriptReact, crate::language::Language::JavaScriptReact]
    }
}

/// Registra todas as regras padrão no RuleRegistry.
pub fn register_default_rules(registry: &mut crate::rule_registry::RuleRegistry) {
    registry.register(Box::new(AnyViaAliasRule));
    registry.register(Box::new(ConditionalHooksRule));
    registry.register(Box::new(FetchInComponentRule));
    registry.register(Box::new(ExhaustiveDepsRule));
    registry.register(Box::new(UnusedVarsRule));
    registry.register(Box::new(NoFloatingPromisesRule));
    registry.register(Box::new(NoUnsafeAssignmentRule));
    registry.register(Box::new(JsxNoTargetBlankRule));
    registry.register(Box::new(NoConsoleRule));
    registry.register(Box::new(PreferReadonlyRule));
    // Security
    registry.register(Box::new(NoDangerouslySetInnerHtmlRule));
    registry.register(Box::new(NoGlobalEvalRule));
    registry.register(Box::new(NoSecretsRule));
    // Suspicious
    registry.register(Box::new(NoAssignInExpressionsRule));
    registry.register(Box::new(NoFallthroughSwitchClauseRule));
    registry.register(Box::new(NoDoubleEqualsRule));
    registry.register(Box::new(NoDuplicateCaseRule));
    registry.register(Box::new(NoAsyncPromiseExecutorRule));
    registry.register(Box::new(NoDebuggerRule));
    registry.register(Box::new(NoTemplateCurlyInStringRule));
    registry.register(Box::new(NoDuplicateJsxPropsRule));
    registry.register(Box::new(NoEmptyBlockStatementsRule));
    registry.register(Box::new(NoVarRule));
    // Correctness
    registry.register(Box::new(NoConstantConditionRule));
    registry.register(Box::new(NoUnsafeFinallyRule));
    registry.register(Box::new(NoSwitchDeclarationsRule));
    registry.register(Box::new(NoEmptyPatternRule));
    registry.register(Box::new(NoUnsafeOptionalChainingRule));
    registry.register(Box::new(NoVoidTypeReturnRule));
    // Complexity
    registry.register(Box::new(NoExtraBooleanCastRule));
    // Performance
    registry.register(Box::new(NoAwaitInLoopsRule));
    // React (semantic-aware)
    registry.register(Box::new(NoSetStateInEffectRule));
    registry.register(Box::new(NoImpureInRenderRule));
}
