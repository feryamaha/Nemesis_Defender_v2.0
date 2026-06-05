/// Visitors de validação semântica.
///
/// Cada visitor percorre a árvore tree-sitter e detecta um tipo específico
/// de violação. Todos os visitors seguem a mesma interface:
///
/// ```ignore
/// fn visit(tree: &tree_sitter::Tree, content: &str) -> Vec<Violation>;
/// ```

pub mod any_via_alias;
pub mod conditional_hooks;
pub mod fetch_in_component;
pub mod exhaustive_deps;
pub mod unused_vars;
pub mod no_floating_promises;
pub mod no_unsafe_assignment;
pub mod jsx_no_target_blank;
pub mod no_console;
pub mod prefer_readonly;

// Security
pub mod no_dangerously_set_inner_html;
pub mod no_global_eval;
pub mod no_secrets;

// Suspicious
pub mod no_assign_in_expressions;
pub mod no_fallthrough_switch_clause;
pub mod no_double_equals;
pub mod no_duplicate_case;
pub mod no_async_promise_executor;
pub mod no_debugger;
pub mod no_template_curly_in_string;
pub mod no_duplicate_jsx_props;
pub mod no_empty_block_statements;
pub mod no_var;

// Correctness
pub mod no_constant_condition;
pub mod no_unsafe_finally;
pub mod no_switch_declarations;
pub mod no_empty_pattern;
pub mod no_unsafe_optional_chaining;
pub mod no_void_type_return;

// Complexity
pub mod no_extra_boolean_cast;

// Performance
pub mod no_await_in_loops;

// React (semantic-aware)
pub mod no_set_state_in_effect;
pub mod no_impure_in_render;
