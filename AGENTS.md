# AGENTS.md

## Project: Portal-dash-DentalUNI

Next.js | React | TypeScript | Tailwind | Nemesis Framework v10

## Nemesis SDD Pipeline

Este projeto usa o Nemesis Framework para Specification-Driven Development.
O pipeline consiste em 5 skills sequenciais:

### Skills Disponiveis

| Skill | Proposito | Localizacao |
|-------|-----------|-------------|
| `nemesis-specification-design` | Converter request informal em especificacao tecnica | `.devin/skills/nemesis-specification-design/SKILL.md` |
| `pre-writing-rule-control` | Validar plano contra regras Nemesis antes da escrita | `.devin/skills/pre-writing-rule-control/SKILL.md` |
| `nemesis-writing-plans` | Criar plano de implementacao com tarefas atomicas | `.devin/skills/nemesis-writing-plans/SKILL.md` |
| `nemesis-subagent-driven-development` | Executar plano via subagentes com two-stage review | `.devin/skills/nemesis-subagent-driven-development/SKILL.md` |
| `nemesis-finishing-branch` | Finalizar, gerar PR, apresentar opcoes de branch | `.devin/skills/nemesis-finishing-branch/SKILL.md` |

### Agentes Disponiveis

| Agent | Proposito | Localizacao |
|-------|-----------|-------------|
| `nemesis-implementer` | Executar tarefa atomica com verificacao | `.agents/nemesis-implementer.md` |

### Fluxo Padrao

1. Usuario descreve necessidade → `nemesis-specification-design`
2. Design aprovado → `pre-writing-rule-control` (validação contra regras)
3. Validação aprovada → `nemesis-writing-plans`
4. Plano aprovado → `nemesis-subagent-driven-development` (usa `nemesis-implementer`)
5. Implementacao concluida → `nemesis-finishing-branch`

### Regras Fundamentais

- NUNCA escreva codigo antes do design ser aprovado
- NUNCA execute antes do plano ser aprovado
- Use subagentes para tarefas de implementacao
- Verificacao: tsc + lint + build (sem TDD - projeto sem infraestrutura de testes)
- Execucao continua entre tarefas — nao pare para perguntar "posso continuar?"
- Use git diff real para gerar PRs — nunca fabrique evidencias
- Responda sempre em PT-BR

### Enforcement

O Nemesis enforcement (AST + eBPF + pretool + deny-list) esta ativo.
Ele bloqueia anti-padroes no nivel do kernel. Confie nele para qualidade
de codigo — foque em fluxo e metodo.

