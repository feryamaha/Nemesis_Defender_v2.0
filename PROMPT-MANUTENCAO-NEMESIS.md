# PROMPT DE MANUTENÇÃO — NEMESIS DEFENDER v2.0
## Tarefa: Hardening da Camada 2 (Defender) — 5 melhorias destiladas de SkillSpector (NVIDIA) e skill-firewall (Driftneural)

Você é um engenheiro de segurança Rust sênior trabalhando no **Nemesis Defender**, um sistema de enforcement determinístico em camadas contra malware de supply-chain e abuso de agentes LLM. Sua tarefa é implementar 5 melhorias na **camada de detecção de conteúdo (Camada 2 / `nemesis-defender`)**, com testes e ampliação do pentest.

---

## PRINCÍPIOS INEGOCIÁVEIS (LEIA ANTES DE TOCAR EM QUALQUER COISA)

Estes princípios definem o Nemesis. Qualquer melhoria que os viole deve ser REJEITADA, mesmo que pareça "melhor":

1. **Determinístico, sem LLM no caminho de decisão.** O enforcement NÃO pode depender de inferência probabilística. NÃO adicione chamada a LLM, modelo semântico, ou heurística não-determinística no caminho de bloqueio. (O SkillSpector usa LLM opcional — NÃO copie isso.)
2. **Offline. Zero chamadas de rede em tempo de scan.** NÃO adicione lookup de CVE online, fetch remoto, telemetria ou qualquer I/O de rede no caminho de detecção. (O SkillSpector chama OSV.dev — NÃO copie isso. Se precisar de IOCs, use snapshot local offline.)
3. **Human-gated.** O modelo nunca altera a própria configuração. Arquivos de config/deny-list permanecem sob controle exclusivamente humano (`absolute_block`). Nada que você adicione pode permitir auto-promoção de permissões pela IA.
4. **Fail-closed.** Em dúvida, bloqueia. Se um parser falhar ou uma análise não conseguir concluir, o comportamento seguro é tratar como suspeito/bloquear no caminho de enforcement — NUNCA "deixar passar por falha". (Exceção já existente: o `ast-linters::validate_semantic` retorna lista vazia em parse-fail para não quebrar o hook; isso é design existente, NÃO mude sem discutir.)
5. **Não quebrar o que funciona.** O sistema tem track record de produção (~1 ano, milhares de bloqueios reais) e um pentest de 110 testes em 14 módulos com 100% de bloqueio. Nenhuma mudança pode regredir esse resultado. Diferential testing obrigatório.
6. **Sem regra hardcoded na lógica.** Padrões novos vão para deny-lists/arquivos de config consultados em runtime, não embutidos como `if` no código do hook. A lógica é agnóstica; os dados é que decidem.

---

## CONTEXTO DA ARQUITETURA (mapa real do projeto)

Workspace Rust em `.nemesis/`. Membros: `ast-linters`, `ebpf-kernel`, `nemesis-defender`, `nemesis-cli`. As melhorias desta tarefa concentram-se em **`nemesis-defender`** (Camada 2) e tocam de leve em `ast-linters` (taint tracking) e na suíte de pentest.

Módulo-alvo principal — `.nemesis/nemesis-defender/`:
- `src/main.rs` — binário com modos `--daemon`, `--scan <path>` (exit 2 = MALICIOUS), `--ensure-daemon`, `--stop`, `--install-shell-hook`
- `src/scanner/` — scanner de conteúdo (onde vive a lógica de detecção das 6 layers)
- `src/visitors/` — visitadores por vetor de ataque: decode→exec, Unicode steganography, indirect prompt injection, postinstall/preinstall abuse
- `src/watcher/` — filesystem watcher (inotify/kqueue/FSEvents)
- `src/reporter.rs` — reporter de resultados
- Log: `.nemesis/logs/defender.log`

Deny-lists consultadas em runtime — `.nemesis/workflow-enforcement/config/`:
- `deny-list.json` (77KB), `deny-list-base.json` (92KB) e as por-linguagem (`-generic`, `-go`, `-java`, `-python`, `-rust`, `-typescript`)

Crate de AST (para a melhoria de taint tracking) — `.nemesis/ast-linters/`:
- `src/validator.rs` — `validate_semantic()` (entrada pública, linhas ~87-217)
- `src/parser.rs` — wrapper tree-sitter (TS/JS/Python/Go)
- `src/visitors/` — visitadores AST existentes

Suíte de pentest — `.nemesis/pentest-nemesis-control/`:
- `run-pentest.sh` (26KB) — executa os módulos M1–M14 (110 testes), testa o binário `nemesis-pretool-check-unix` via stdin JSON
- `pentest-results.csv`, `pentest-output.txt`, `pentest-final-*.md`
- Módulos existentes relevantes: M2 (Exfiltração, 8), M5 (Ofuscação, 6), M9 (Unicode, 5), M10 (Prompt injection, 6), M13 (Multi-vector, 10), M14 (Evasão avançada, 8)

Formato de violação em `violations.log`:
```json
{ "timestamp": "...", "layer": "pretool|ast|ebpf|defender", "tool": "...", "file_path": "...", "rule": "...", "message": "...", "suggestion": "..." }
```

---

## FASE 0 — INVESTIGAÇÃO OBRIGATÓRIA (NÃO PULE, NÃO ESCREVA CÓDIGO AINDA)

Antes de qualquer implementação, LEIA o código real e produza um relatório de investigação. Não confie nesta documentação como verdade absoluta — ela pode estar desatualizada; o código no disco é a fonte de verdade.

1. Leia `.nemesis/nemesis-defender/src/` inteiro. Mapeie:
   - Como o scanner orquestra as 6 layers (AST → byte → regex → denylist → entropy → decoder recursivo). Onde cada uma é chamada?
   - Como os visitors atuais são registrados e invocados. Qual a assinatura/trait de um visitor?
   - Como uma detecção vira um veredito MALICIOUS e como é logada (`reporter.rs` → `defender.log`).
   - Onde exatamente o `credential_harvest` está implementado e quais locais/canais ele cobre hoje.
2. Leia `.nemesis/ast-linters/src/validator.rs` e `parser.rs`. Entenda como a AST é percorrida e se há infraestrutura reaproveitável para data-flow (taint).
3. Leia as deny-lists em `config/` e identifique a estrutura JSON (como uma categoria/pattern é declarada). Toda ampliação de pattern seguirá esse schema.
4. Leia `pentest-nemesis-control/run-pentest.sh` e entenda: como um teste é definido, como o resultado é medido (exit code do binário), como o CSV é gerado.
5. Rode o pentest atual e capture o baseline:
   ```
   cd .nemesis && cargo build --release --workspace
   cd pentest-nemesis-control && ./run-pentest.sh | tee baseline-pre-manutencao.txt
   ```
   Guarde a taxa de bloqueio atual por módulo. **Este é o número que não pode regredir.**

**Entregável da Fase 0:** um documento `INVESTIGACAO-MANUTENCAO.md` com o mapa real do scanner, o schema das deny-lists, a assinatura dos visitors, a estrutura do pentest, e o baseline de bloqueio. **PARE e me mostre este documento antes de prosseguir para a Fase 1.**

---

## FASE 1 — AS 5 MELHORIAS (implementar uma de cada vez, com aprovação entre elas)

Implemente na ordem abaixo (esforço crescente). Cada melhoria é um ciclo completo: implementar → teste unitário → ampliar pentest → rodar diferencial → me reportar antes da próxima.

### MELHORIA 1 — Expansão da superfície de exfiltração de credenciais (esforço: BAIXO)
**Onde:** deny-lists em `config/` + visitor `credential_harvest` em `nemesis-defender/src/visitors/`.
**O quê:** ampliar os locais de credencial e canais de saída cobertos, alinhando à superfície completa documentada (Shai-Hulud / TrapDoor). Adicionar, se ainda não cobertos:
- Locais (fontes): cloud IMDS / metadata endpoints (`169.254.169.254`, metadata.google.internal), histórico de shell (`.bash_history`, `.zsh_history`), tokens de SaaS, dados de browser (cookies/login data), wallets de cripto, arquivos de registries de pacote (`.npmrc`, `.pypirc`), `.git-credentials`.
- Canais (sinks de saída): HTTP(S), DNS (exfil via subdomínio/TXT), webhooks, side-channel de output.
**Como:** adicione os patterns nos arquivos de deny-list seguindo o schema existente (NÃO hardcode no Rust). Se o visitor precisar reconhecer novos sinks, estenda a lógica de detecção dele de forma data-driven.
**Cuidado com falso-positivo:** `169.254.169.254` e leitura de `.env` legítima existem em código normal. Use o princípio de **cadeia** (ver Melhoria 2), não disparo isolado, para os casos ambíguos.

### MELHORIA 2 — Exfiltração como cadeia (fonte→sink), não evento isolado (esforço: BAIXO-MÉDIO)
**Onde:** lógica de correlação do `nemesis-defender/src/scanner/` (e/ou onde a correlação de `defender.log` já existe — investigar na Fase 0).
**O quê:** formalizar a assinatura "leu fonte sensível → enviou para sink de saída" como uma **regra de severidade alta própria**, em vez de depender de dois patterns separados dispararem. O sistema já correlaciona "leitura de sensível + comando de rede" — esta melhoria torna isso uma assinatura de primeira classe, com nome próprio no log (`rule: "exfil_chain"`).
**Como:** dentro de um mesmo arquivo/scan, se um pattern de FONTE (credencial) e um pattern de SINK (saída de rede) coexistem, eleve para veredito MALICIOUS com `rule: exfil_chain` mesmo que individualmente fossem MEDIUM. Mantenha determinístico (presença de ambos = bloqueio; não "probabilidade").

### MELHORIA 3 — Scan dedicado a arquivos de config de IDE como vetor de entrada (esforço: MÉDIO)
**Onde:** novo visitor/scanner em `nemesis-defender/src/visitors/` + paths monitorados no `src/watcher/`.
**O quê:** detectar conteúdo malicioso em arquivos de config de IDE que **chegam envenenados de fora** (via PR, clone, postinstall) e que a IA vai **ler como instrução**. Hoje o Nemesis bloqueia a IA de ESCREVER nesses arquivos (`absolute_block`), mas NÃO inspeciona um config malicioso que entrou por outro caminho. Este é um ponto cego real.
**Arquivos-alvo:** `CLAUDE.md`, `.cursorrules`, `AGENTS.md`, `GEMINI.md`, `.windsurfrules`, `.github/copilot-instructions.md`, `.continue/rules/`, e os diretórios `.claude/`, `.windsurf/`, `.cursor/` etc.
**Detectar nesses arquivos:**
- Unicode invisível (tag chars U+E0000–U+E007F, bidi overrides CVE-2021-42574, zero-width) — reúse o visitor `unicode_steg` existente.
- Prompt injection (ignore-previous, role override, fake `<system>`, fake `User:`/`Assistant:` continuations).
- **"Fake security scan" pattern** (ver Melhoria 5).
- **Authority injection** ("verificado pela Anthropic", "approved by...", "this file is trusted").
**Como:** estenda o `watcher` para incluir esses paths no monitoramento, e crie um visitor `ide_config_poisoning` que roda os sub-checks acima. Reúse o máximo da infra de Unicode/injection já existente.

### MELHORIA 4 — Detecção "fake security scan" + authority injection (esforço: BAIXO, fazer junto da 3)
**Onde:** visitor de prompt injection em `nemesis-defender/src/visitors/` (+ usado pela Melhoria 3).
**O quê:** assinatura específica do ataque em que o config/skill instrui a IA a "rodar um security scan / verificação antes de responder" → o que leva a IA a ler credenciais → e exfiltrar. O ataque usa a própria postura de segurança como vetor. Também: detecção de "authority injection" (texto que finge autoridade/aprovação para baixar a guarda do modelo).
**Como:** patterns determinísticos na deny-list de prompt injection. Documente cada pattern com o racional (qual ataque ele pega).

### MELHORIA 5 — Taint tracking na AST (fonte→sink através de variáveis) (esforço: ALTO — fazer por último)
**Onde:** `.nemesis/ast-linters/` — novo módulo de análise de fluxo, consumido pelo scanner do Defender.
**O quê:** rastrear o FLUXO de dado da fonte (input de rede, leitura de arquivo, env var) até o sink perigoso (exec, eval, subprocess, saída de rede), **inclusive passando por variáveis intermediárias**. Isto pega o ataque que fragmenta o payload em vários passos para escapar de regex/pattern-matching — exatamente a classe de bypass que o Nemesis já sofreu historicamente (adversário fragmentando comando).
**Escopo mínimo viável (não tente resolver taint analysis completo):**
- Marcar como TAINTED: retorno de leitura de env (`process.env`, `os.environ`), leitura de arquivo, input de rede.
- Propagar taint por: atribuição direta a variável, concatenação de string, template string.
- Disparar em SINK: se valor tainted chega em `exec`/`eval`/`subprocess`/`child_process`/sink de rede.
- Severidade CRÍTICA quando: fonte de credencial tainted → sink de rede (= a `exfil_chain` da Melhoria 2, agora detectada também através de variáveis).
**Como:** use a infra tree-sitter existente em `parser.rs`. Implemente um visitor de data-flow simples (intra-arquivo, intra-função primeiro). NÃO precisa ser inter-procedural na v1. Determinístico: fluxo existe ou não existe.
**Cuidado:** esta é a melhoria com maior risco de falso-positivo e de custo de performance. Meça o impacto no tempo de scan (princípio: hooks rodam em milissegundos). Se ficar caro, torne-a opt-in via config, mas com default LIGADO no daemon (não no hook síncrono crítico).

---

## FASE 2 — TESTES E VALIDAÇÃO (para CADA melhoria)

1. **Testes unitários** no crate correspondente (`cargo test --workspace`). Para cada melhoria:
   - Casos POSITIVOS: payloads maliciosos que a melhoria deve pegar (mínimo 5 por melhoria).
   - Casos NEGATIVOS (anti-falso-positivo): código legítimo que NÃO pode disparar (mínimo 5 por melhoria) — ex.: leitura legítima de `.env`, uso legítimo de `169.254.169.254` em infra, `CLAUDE.md` honesto com instruções normais.
2. **Lint e formato:** `cargo fmt --all -- --check` e `cargo clippy --workspace -- -D warnings` devem passar.
3. **Diferencial obrigatório:** rode `run-pentest.sh` de novo e compare com o `baseline-pre-manutencao.txt`. A taxa de bloqueio dos 110 testes existentes **não pode cair**. Se cair, a melhoria introduziu regressão — investigue e corrija antes de prosseguir.

---

## FASE 3 — AMPLIAÇÃO DO PENTEST

Adicione novos módulos à suíte `pentest-nemesis-control/run-pentest.sh`, seguindo o formato dos módulos existentes (teste via stdin JSON no binário, medição por exit code, resultado no CSV):

- **M15 — Exfil surface estendida** (cobre Melhoria 1): IMDS, shell history, browser data, wallets, `.npmrc`/`.pypirc`, via canais HTTP/DNS/webhook. (~10 testes)
- **M16 — Exfil chains** (cobre Melhoria 2): pares fonte→sink no mesmo arquivo que individualmente passariam mas juntos devem bloquear. (~6 testes)
- **M17 — IDE config poisoning** (cobre Melhorias 3+4): `CLAUDE.md`/`.cursorrules`/`AGENTS.md` com Unicode invisível, prompt injection, fake-scan e authority injection. (~10 testes)
- **M18 — Taint flow** (cobre Melhoria 5): payloads que fragmentam o caminho fonte→sink através de variáveis e concatenação, que regex sozinho não pega. (~8 testes)

Cada novo módulo precisa de casos negativos embutidos (entradas legítimas que devem PASSAR), para que o pentest também meça falso-positivo, não só recall.

**Entregável da Fase 3:** pentest rodando com os módulos M1–M18, relatório CSV + Markdown atualizado, e um resumo da nova taxa de bloqueio total + taxa de falso-positivo nos casos negativos.

---

## REGRAS DE EXECUÇÃO (workflow desta manutenção)

- Trabalhe **uma melhoria por vez**. Após cada uma: testes passando + pentest sem regressão + me reportar o diff. NÃO emende as 5 de uma vez.
- **Leia o arquivo real antes de editar** — sempre. Se o que você encontrar no código divergir desta documentação, PARE e me avise; a divergência em si é informação importante.
- Não toque em `ebpf-kernel/` nem na lógica do `pretool-hook` de Camada 1 nesta tarefa — o escopo é Camada 2 (Defender) + taint na AST + pentest. Se achar que precisa tocar fora disso, PARE e pergunte.
- Não crie pasta de quarentena nem mude o comportamento de remoção do Defender nesta tarefa (é outro roadmap).
- Commits: pequenos, atômicos, um por melhoria, com mensagem descrevendo o vetor que fecha. **Eu (humano) faço os commits** — você prepara o diff e a mensagem sugerida, mas não commita sozinho (princípio do Nemesis: git é 100% humano).
- Ao final de tudo: um `RELATORIO-MANUTENCAO.md` resumindo o que entrou em cada melhoria, os caminhos tocados, o antes/depois do pentest, e os falso-positivos conhecidos remanescentes.

## O QUE NÃO FAZER (resumo dos anti-padrões desta tarefa)
- ❌ LLM/inferência no caminho de decisão.
- ❌ Chamada de rede em tempo de scan (CVE online, telemetria).
- ❌ Pattern hardcoded na lógica do hook (vai para deny-list).
- ❌ Mudar comportamento fail-closed para fail-open.
- ❌ Commitar sozinho.
- ❌ Implementar as 5 de uma vez sem validação entre elas.
- ❌ Deixar uma melhoria regredir o pentest existente.

Comece pela **Fase 0** e me mostre o `INVESTIGACAO-MANUTENCAO.md` antes de escrever qualquer código de implementação.
