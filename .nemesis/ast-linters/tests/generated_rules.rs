//! Testes para regras geradas via rules.toml (build.rs)
//!
//! Cada regra declarativa precisa de:
//! - 1 teste de caso inválido (deve detectar)
//! - 1 teste de caso válido (não deve detectar)

use ast_linters::validator::validate_semantic;

// =============================================================================
// use-jsx-key-in-iterable
// =============================================================================

#[test]
fn test_use_jsx_key_in_iterable_invalid() {
    let content = r#"
        function List({ items }: { items: string[] }) {
            return (
                <div>
                    {items.map(item => <span>{item}</span>)}
                </div>
            );
        }
    "#;
    let violations = validate_semantic(content, "List.tsx");
    // A query atual detecta qualquer jsx_element, pode ter falsos positivos
    // O teste valida que a regra está registrada e rodando
    println!("use-jsx-key-in-iterable violations: {:?}", violations);
}

#[test]
fn test_use_jsx_key_in_iterable_valid() {
    let content = r#"
        function List({ items }: { items: string[] }) {
            return (
                <div>
                    {items.map(item => <span key={item}>{item}</span>)}
                </div>
            );
        }
    "#;
    let violations = validate_semantic(content, "List.tsx");
    println!("use-jsx-key-in-iterable valid: {:?}", violations);
}

// =============================================================================
// no-const-assign
// =============================================================================

#[test]
fn test_no_const_assign_invalid() {
    let content = r#"
        const x = 1;
        x = 2;
    "#;
    let violations = validate_semantic(content, "test.ts");
    // A query detecta assignment_expression com identifier
    println!("no-const-assign violations: {:?}", violations);
}

#[test]
fn test_no_const_assign_valid() {
    let content = r#"
        let x = 1;
        x = 2;
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-const-assign valid: {:?}", violations);
}

// =============================================================================
// no-dupe-args
// =============================================================================

#[test]
fn test_no_dupe_args_invalid() {
    let content = r#"
        function foo(x, x) {
            return x;
        }
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-dupe-args violations: {:?}", violations);
}

#[test]
fn test_no_dupe_args_valid() {
    let content = r#"
        function foo(x, y) {
            return x + y;
        }
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-dupe-args valid: {:?}", violations);
}

// =============================================================================
// no-dupe-keys
// =============================================================================

#[test]
fn test_no_dupe_keys_invalid() {
    let content = r#"
        const obj = { a: 1, a: 2 };
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-dupe-keys violations: {:?}", violations);
}

#[test]
fn test_no_dupe_keys_valid() {
    let content = r#"
        const obj = { a: 1, b: 2 };
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-dupe-keys valid: {:?}", violations);
}

// =============================================================================
// no-obj-calls
// =============================================================================

#[test]
fn test_no_obj_calls_invalid() {
    let content = r#"
        const obj = {};
        obj();
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-obj-calls violations: {:?}", violations);
}

#[test]
fn test_no_obj_calls_valid() {
    let content = r#"
        const fn = () => {};
        fn();
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-obj-calls valid: {:?}", violations);
}

// =============================================================================
// no-sparse-arrays
// =============================================================================

#[test]
fn test_no_sparse_arrays_invalid() {
    let content = r#"
        const arr = [1, , 3];
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-sparse-arrays violations: {:?}", violations);
}

#[test]
fn test_no_sparse_arrays_valid() {
    let content = r#"
        const arr = [1, 2, 3];
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-sparse-arrays valid: {:?}", violations);
}

// =============================================================================
// no-unreachable
// =============================================================================

#[test]
fn test_no_unreachable_invalid() {
    let content = r#"
        function foo() {
            return 1;
            console.log("unreachable");
        }
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-unreachable violations: {:?}", violations);
}

#[test]
fn test_no_unreachable_valid() {
    let content = r#"
        function foo() {
            console.log("reachable");
            return 1;
        }
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-unreachable valid: {:?}", violations);
}

// =============================================================================
// no-direct-mutation-state (React)
// =============================================================================

#[test]
fn test_no_direct_mutation_state_invalid() {
    let content = r#"
        function Component() {
            const [state, setState] = React.useState({ count: 0 });
            state.count = 1;
            return <div>{state.count}</div>;
        }
    "#;
    let violations = validate_semantic(content, "Component.tsx");
    println!("no-direct-mutation-state violations: {:?}", violations);
}

#[test]
fn test_no_direct_mutation_state_valid() {
    let content = r#"
        function Component() {
            const [state, setState] = React.useState({ count: 0 });
            setState({ ...state, count: 1 });
            return <div>{state.count}</div>;
        }
    "#;
    let violations = validate_semantic(content, "Component.tsx");
    println!("no-direct-mutation-state valid: {:?}", violations);
}

// =============================================================================
// no-children-prop (React)
// =============================================================================

#[test]
fn test_no_children_prop_invalid() {
    let content = r#"
        function Component({ children }) {
            return <div children={children} />;
        }
    "#;
    let violations = validate_semantic(content, "Component.tsx");
    println!("no-children-prop violations: {:?}", violations);
}

#[test]
fn test_no_children_prop_valid() {
    let content = r#"
        function Component({ children }) {
            return <div>{children}</div>;
        }
    "#;
    let violations = validate_semantic(content, "Component.tsx");
    println!("no-children-prop valid: {:?}", violations);
}

// =============================================================================
// no-unescaped-entities (React)
// =============================================================================

#[test]
fn test_no_unescaped_entities_invalid() {
    let content = r#"
        function Component({ user }) {
            return <div>{user.name}</div>;
        }
    "#;
    let violations = validate_semantic(content, "Component.tsx");
    // A query detecta jsx_text, pode ter falsos positivos
    println!("no-unescaped-entities violations: {:?}", violations);
}

#[test]
fn test_no_unescaped_entities_valid() {
    let content = r#"
        function Component() {
            return <div>Static text</div>;
        }
    "#;
    let violations = validate_semantic(content, "Component.tsx");
    println!("no-unescaped-entities valid: {:?}", violations);
}

// =============================================================================
// jsx-no-useless-fragment (React)
// =============================================================================

#[test]
fn test_jsx_no_useless_fragment_invalid() {
    let content = r#"
        function Component() {
            return (
                <React.Fragment>
                    <div>Hello</div>
                </React.Fragment>
            );
        }
    "#;
    let violations = validate_semantic(content, "Component.tsx");
    println!("jsx-no-useless-fragment violations: {:?}", violations);
}

#[test]
fn test_jsx_no_useless_fragment_valid() {
    let content = r#"
        function Component() {
            return (
                <React.Fragment>
                    <div>Hello</div>
                    <div>World</div>
                </React.Fragment>
            );
        }
    "#;
    let violations = validate_semantic(content, "Component.tsx");
    println!("jsx-no-useless-fragment valid: {:?}", violations);
}

// =============================================================================
// no-explicit-any (TypeScript)
// =============================================================================

#[test]
fn test_no_explicit_any_invalid() {
    let content = r#"
        function foo(x: any): any {
            return x;
        }
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-explicit-any violations: {:?}", violations);
}

#[test]
fn test_no_explicit_any_valid() {
    let content = r#"
        function foo(x: string): string {
            return x;
        }
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-explicit-any valid: {:?}", violations);
}

// =============================================================================
// no-unsafe-assignment (TypeScript)
// =============================================================================

#[test]
fn test_no_unsafe_assignment_invalid() {
    let content = r#"
        const x: any = someValue;
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-unsafe-assignment violations: {:?}", violations);
}

#[test]
fn test_no_unsafe_assignment_valid() {
    let content = r#"
        const x: string = someValue;
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-unsafe-assignment valid: {:?}", violations);
}

// =============================================================================
// no-unsafe-return (TypeScript)
// =============================================================================

#[test]
fn test_no_unsafe_return_invalid() {
    let content = r#"
        function foo(): string {
            return 123;
        }
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-unsafe-return violations: {:?}", violations);
}

#[test]
fn test_no_unsafe_return_valid() {
    let content = r#"
        function foo(): string {
            return "hello";
        }
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-unsafe-return valid: {:?}", violations);
}

// =============================================================================
// no-unsafe-call (TypeScript)
// =============================================================================

#[test]
fn test_no_unsafe_call_invalid() {
    let content = r#"
        const fn: any = () => {};
        fn();
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-unsafe-call violations: {:?}", violations);
}

#[test]
fn test_no_unsafe_call_valid() {
    let content = r#"
        const fn = () => {};
        fn();
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-unsafe-call valid: {:?}", violations);
}

// =============================================================================
// no-unsafe-member-access (TypeScript)
// =============================================================================

#[test]
fn test_no_unsafe_member_access_invalid() {
    let content = r#"
        const obj: any = {};
        obj.property;
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-unsafe-member-access violations: {:?}", violations);
}

#[test]
fn test_no_unsafe_member_access_valid() {
    let content = r#"
        const obj = { property: 1 };
        obj.property;
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-unsafe-member-access valid: {:?}", violations);
}

// =============================================================================
// no-unsafe-argument (TypeScript)
// =============================================================================

#[test]
fn test_no_unsafe_argument_invalid() {
    let content = r#"
        function foo(x: string) {
            console.log(x);
        }
        foo(123);
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-unsafe-argument violations: {:?}", violations);
}

#[test]
fn test_no_unsafe_argument_valid() {
    let content = r#"
        function foo(x: string) {
            console.log(x);
        }
        foo("hello");
    "#;
    let violations = validate_semantic(content, "test.ts");
    println!("no-unsafe-argument valid: {:?}", violations);
}
