# NEMESIS FRAMEWORK v2.0 — Repositorio Rust

## Identidade do Projeto

Este repositorio contem o codigo fonte do **Nemesis Framework v2.0**.
Linguagem: **100% Rust** (edition 2021). Build: **cargo workspace**.

Nemesis e um sistema de enforcement semantico que protege pipelines CI/CD,
repositorios de codigo, e desenvolvimento colaborativo atraves de:

- **AST Linters**: Analise semantica via tree-sitter
- **eBPF Kernel Enforcement**: Bloqueio de operacoes perigosas no kernel Linux
- **Pretool Hub**: Entry point universal para validacoes pre-commit
- **Supply Chain Defense**: Iron Dome scanner para dependencias e binarios
- **Workflow Enforcement**: Validacao de deny-lists e policies

## Regras Absolutas

1. **Linguagem**: Somente Rust (.rs). Nenhum arquivo .ts, .js, .py, .sh em .nemesis/
2. **Build**: `cd .nemesis && cargo build --release --workspace` (unico comando)
3. **Binarios**: Salvos em `.nemesis/target/release/` (NUNCA copiar para outro path)
4. **Git Operations**: APENAS Fernando executa git commit/push. Claude NUNCA faz operacoes git write.
5. **Testes**: `cd .nemesis && cargo test --workspace`

6. **Verificacao Pre-Commit**: SEMPRE validar com `cargo check` antes de submeter / Commit/push somente usuario humano Fernando pode executar.

## Estrutura do Projeto

```
Nemesis_Rust_v2.0/
  .nemesis/                         ← Codigo fonte Rust (workspace cargo)
    ast-linters/                    ← Validacao semantica (tree-sitter visitors)
    ebpf-kernel/                    ← Enforcement kernel Linux (eBPF LSM hooks)
    hooks/                          ← Entry points pretool (unix/windows)
    nemesis-defender/               ← Iron Dome supply chain scanner
    workflow-enforcement/           ← Pretool hub, deny-list, harvest
    nemesis-install/                ← Scripts instalacao e check
    Cargo.toml                      ← Workspace manifest
    Cargo.lock                      ← Lock das dependencias
  
  .claude/                          ← Configuracao Claude Code
    agents/nemesis-implementer.md   ← Agente para tarefas Rust
    skills/                         ← Skills Nemesis SDD Pipeline
  
  .devin/                        ← Configuracao Devin
    skills/                         ← Replica de skills
    workflows/                      ← Workflows orchestracao
  
  .agents/                          ← Configuracao Codex
    skills/                         ← Replica de skills
  
  .codex/                           ← Configuracao Codex editor
  .openclaude/                      ← Configuracao OpenClaude
    skills/                         ← Replica de skills
  
  Feature-Documentation/            ← Especificacoes, planos, PRs
    SPECS/                          ← Especificacoes tecnicas (SPEC_NNN_*.md)
    PLANS/                          ← Planos de implementacao (PLAN_NNN_*.md)
    PR/                             ← Propostas de pull request (PR_NNN_*.md)
```

## Convencoes de Nomeclatura

| Tipo | Formato | Exemplo |
|------|---------|---------|
| Modulos Rust | snake_case | `ast_linters`, `workflow_enforcement` |
| Arquivos Rust | kebab-case.rs | `tree-sitter-visitor.rs`, `ebpf-lsm-hook.rs` |
| Estruturas/Traits | PascalCase | `AstValidator`, `RuleEnforcer` |
| Funcoes/Metodos | snake_case | `validate_source_tree`, `check_deny_list` |
| Constantes | UPPER_SNAKE_CASE | `MAX_RULE_DEPTH`, `DEFAULT_TIMEOUT_MS` |
| Commits | Fernando apenas | Sem clausula Co-Authored-By |
| Especificacoes | SPEC_NNN_descricao.md | SPEC_001_ast-linter-tree-sitter.md |
| Planos | PLAN_NNN_descricao.md | PLAN_001_ast-linter-tree-sitter.md |
| PRs | PR_NNN_descricao.md | PR_001_ast-linter-tree-sitter.md |

## Stack de Dependencias

- **Rust**: edition 2021, MSRV >= 1.70
- **tree-sitter**: Parsing e analise AST
- **notify**: Filesystem watching
- **serde/serde_json**: Serializacao/deserializacao
- **regex**: Pattern matching
- **base64**: Decodificacao
- **libc**: eBPF/cgroup syscalls
- **clap**: CLI argument parsing
- **log/env_logger**: Logging
- **thiserror**: Error handling

## Crates do Workspace

| Crate | Proposito | Entry Point |
|-------|-----------|-------------|
| `ast-linters` | Analise semantica via tree-sitter | lib.rs |
| `ebpf-kernel` | Enforcement eBPF LSM para kernel Linux | lib.rs |
| `workflow-enforcement` | Pretool hub, deny-list, harvest | lib.rs |
| `nemesis-defender` | Iron Dome supply chain scanner | bin/main.rs |
| `hooks` | Entry point pretool (binario nemesis) | bin/main.rs |

## O Que Este Projeto NAO E

- NAO e um projeto frontend (TypeScript, React, Next.js, Tailwind, etc.)
- NAO e o projeto Dental UNI ou Portal-dash-DentalUNI
- NAO tem package.json, node_modules, bun, npm
- NAO tem tsconfig.json, eslint.config.js, prettier.config.js
- NAO usa bun run, npm install ou package managers JS
- As deny-lists DENTRO do Nemesis protegem OUTROS projetos (como Dental UNI),
  nao este repositorio em si

## Fluxo de Desenvolvimento (Nemesis SDD Pipeline)

1. **nemesis-specification-design**: Converter request informal em especificacao tecnica estruturada
2. **pre-writing-rule-control**: Validar plano contra regras Nemesis antes da escrita
3. **nemesis-writing-plans**: Decompor especificacao em tarefas atomicas
4. **nemesis-subagent-driven-development**: Executar tarefas com verificacao continua (usa nemesis-implementer)
5. **nemesis-finishing-branch**: Finalizar, gerar PR documentada (Fernando faz commit/push)

**Regras de Fluxo:**
- NUNCA escrever codigo antes do design ser aprovado por Fernando
- NUNCA executar antes do plano ser aprovado por Fernando
- Cada fase tem HARD-GATE de aprovacao humana
- Se uma fase falhar: STOP naquela fase, reportar erro, aguardar Fernando
- Execucao continua entre tarefas (nao pause para "posso continuar?")
- Sempre usar git diff real — NUNCA fabricar evidencias

## Comandos de Validacao

```bash
# Type checking
cd .nemesis && cargo check --workspace

# Testes
cd .nemesis && cargo test --workspace

# Build release
cd .nemesis && cargo build --release --workspace

# Lint (if clippy rules configured)
cd .nemesis && cargo clippy --workspace -- -D warnings

# Formato (if rustfmt rules configured)
cd .nemesis && cargo fmt --all --check
```

## Enforcement Ativo

O Nemesis enforcement (AST + eBPF + pretool + deny-list) esta **ATIVO**.
Ele bloqueia anti-padroes no nivel do kernel Linux.

**Confie nele para qualidade de codigo** — foque em fluxo e metodo.

## Permissoes Claude Code

A maioria de operacoes em .nemesis/ sao **read-only**. Operacoes write require aprovacao:
- **PERMITIDO**: Read, grep, cargo check, cargo test
- **REQUIRE APROVACAO**: Write em .nemesis/, cargo build --release
- **BLOQUEADO**: git add, git commit, git push, rm -rf, cargo build --release sem autorizacao

## Contato

**Mantainer**: Fernando Moreira (fmoreirayamaha@gmail.com)
**Repositorio**: Nemesis_Rust_v2.0
**Framework**: Nemesis v2.0 SDD
