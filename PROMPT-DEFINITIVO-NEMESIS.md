# PROMPT ÚNICO E DEFINITIVO — NEMESIS DEFENDER v2.0
## Ratificação de arquitetura + validação executada + calibração de falso-positivo

Você é o engenheiro de segurança Rust responsável pela Camada 2 (Defender) do **Nemesis Defender**. Cinco melhorias já foram implementadas e o pentest reporta 144/144. Antes de qualquer commit, esta tarefa precisa **corrigir um erro de arquitetura, rodar a validação que nunca foi executada, e calibrar um falso-positivo confirmado**. Três modelos diferentes já tentaram partes disto e os três cometeram o mesmo erro de localização de módulo — leia a Seção 0 com atenção, porque ela existe para impedir que isso aconteça pela quarta vez.

---

## SEÇÃO 0 — RATIFICAÇÃO DE ARQUITETURA (LEIA ANTES DE TUDO — ERRO RECORRENTE)

O Nemesis tem **dois módulos diferentes com visitors, e eles NÃO se misturam**:

- **`.nemesis/ast-linters/`** → módulo de **QUALIDADE DE CÓDIGO**. Os visitors aqui detectam anti-padrões de qualidade (any via alias, hooks condicionais, fetch em componente, deps incompletas, vars não usadas). **NADA de segurança/malicious entra aqui. NUNCA.**
- **`.nemesis/nemesis-defender/`** → módulo de **DETECÇÃO DE MALICIOUS / SUPPLY-CHAIN**. TODOS os visitors de segurança vivem aqui: `decode_exec`, `credential_harvest`, `url_in_exec`, `unicode_steg`, `prompt_injection`, `exfil_chain`, `ide_config_poisoning`, `taint_tracker`, etc.

**ERRO COMETIDO PELOS MODELOS ANTERIORES (corrigir se presente):** o `taint_tracker` (Melhoria 5) é um detector de **malicious** (fonte de credencial → sink de exec/rede). Ele pertence a **`.nemesis/nemesis-defender/src/visitors/taint_tracker.rs`** e deve ser chamado pelo scanner do **nemesis-defender**, NÃO pelo crate `ast-linters`. Se você encontrar qualquer lógica de taint/segurança dentro de `.nemesis/ast-linters/`, **mova-a para `nemesis-defender/src/visitors/` e remova do ast-linters**. O `ast-linters` permanece exclusivamente sobre qualidade.

**Tarefa 0.1 — Auditoria de localização (faça primeiro, reporte antes de prosseguir):**
```
# Confirme onde cada visitor de segurança realmente está
grep -rl "taint" .nemesis/ast-linters/src/ 2>/dev/null   # DEVE retornar vazio
ls .nemesis/nemesis-defender/src/visitors/                # taint_tracker.rs DEVE estar aqui
```
Se houver QUALQUER visitor de segurança (`taint_tracker`, `ide_config_poisoning`, `credential_harvest`, etc.) dentro de `ast-linters/`, isso é um bug de arquitetura: mova para `nemesis-defender/src/visitors/`, ajuste os `mod.rs` e os pontos de chamada, e confirme que `ast-linters` voltou a conter só qualidade. Reporte o que encontrou.

---

## CONTEXTO OPERACIONAL (como você trabalha aqui)

- Com o **pretool conectado**, nenhum modelo lê `.nemesis/`. Sem binários em `target/release`, o fallback bloqueia tudo (fail-closed). Por isso o workflow autorizado pelo Fernando é: **pretool desconectado + binários compilados, validação completa de uma vez.** NÃO peça reconexão a cada passo — queima tokens sem ganho.
- **Git é 100% humano.** Você prepara diff + mensagem; o Fernando commita. Nunca commite.
- Se o ambiente do Claude Code te bloquear (hook/eBPF), **entregue o comando pronto para o Fernando rodar no terminal dele** e peça o output. Não tente furar o próprio hook.
- Princípios inegociáveis: determinístico, offline, human-gated, fail-closed, sem LLM no caminho de decisão, sem pattern hardcoded na lógica (vai para deny-list/config). **Corrigir o falso-positivo NÃO pode reduzir recall** — a meta é distinguir prosa de código, não cegar o detector.

---

## FASE A — VALIDAÇÃO QUE NUNCA FOI EXECUTADA

A manutenção marcou os testes como ✅ tendo apenas *escrito* os casos, sem rodar `cargo test` (só `cargo check`). Isso não vale. "Escrevi o teste" ≠ "o teste passou".

**A.1 — Rode os testes unitários de verdade:**
```
cd .nemesis && cargo test --workspace 2>&1 | tee cargo-test-output.txt
```
Reporte, POR ARQUIVO de teste (`m1_credential_harvest_extended`, `m2_exfil_chain`, `m3_m4_ide_config_poisoning`, `m5_taint_tracking`):
- quantos casos POSITIVOS passaram (deve pegar ataque real),
- quantos casos NEGATIVOS passaram (anti-falso-positivo — deve deixar passar o legítimo).
Qualquer negativo que falhe é um falso-positivo confirmado para a Fase B.
Se `cargo test` for bloqueado no seu ambiente, entregue o comando ao Fernando e peça o output.

**A.2 — Reproduza o falso-positivo confirmado.** O Defender bloqueou a escrita do próprio `RELATORIO-MANUTENCAO.md` (log mostrou `credential_exfiltration_comment` e `credential_harvest` disparando contra documentação em prosa). Reproduza de forma controlada:
```
.nemesis/target/release/nemesis-defender --scan <doc-legitimo.md>
```
Use um markdown que descreve vetores em prosa técnica honesta (como um SECURITY.md real): menciona "credential harvesting", "IMDS / 169.254.169.254", "shell history", "exfiltration" — **sem nenhum código executável que leia+envie**. Resultado correto: CLEAN (ou no máximo SUSPICIOUS), NUNCA MALICIOUS. Documente o que retorna hoje.

**Entregável Fase A:** auditoria da Seção 0 + output real do `cargo test` (positivos e negativos por arquivo) + reprodução do falso-positivo. **PARE e mostre ao Fernando antes de calibrar.**

---

## FASE B — CALIBRAÇÃO DA CAUSA-RAIZ DO FALSO-POSITIVO

Causa-raiz: regras das Melhorias 1 e 4 (`credential_harvest`, `credential_exfiltration_comment`, `cloud_imds_access`, `fake_security_scan`, `authority_injection`) disparam MALICIOUS por **menção isolada de palavra-chave em texto/comentário/markdown**, sem exigir **sink real de execução ou rede**. Isso é a mesma classe de erro que já apagou 24 arquivos neste projeto. Documentação de segurança fala desses termos por natureza — tratar a MENÇÃO como o ATAQUE é uma regra quebrada.

A correção segue o princípio que a Melhoria 2 (`exfil_chain`) já acertou: **fonte sozinha não é ataque; ataque é fonte + sink juntos, em código que executa.**

**B.1 — Distinção código vs. prosa (determinística, sem heurística probabilística).** Menção de credencial/IMDS/exfil que aparece em comentário (`//`, `#`, `/* */`, `<!-- -->`), string literal de documentação, ou corpo de `.md`/`.txt`/linguagem natural **NÃO é MALICIOUS por si só**. Só vira MALICIOUS se houver sink executável real (chamada de rede/exec efetiva) no mesmo arquivo. Reescreva `credential_exfiltration_comment` — principal suspeita — para exigir co-ocorrência com sink real, não a mera presença das palavras. Use sinais concretos: extensão do arquivo, se a menção está em nó de comentário/string na AST, presença/ausência de sink.

**B.2 — Documentação pura retorna CLEAN.** Arquivos `.md`, `.txt`, `.rst`, `README`, `SECURITY`, `CONTRIBUTING`, `CHANGELOG`, `LICENSE` contendo só prosa (sem bloco de código executável com fonte→sink) → CLEAN. O relatório técnico que *descreve* vetores é documentação legítima.

**B.3 — NÃO criar buraco no IDE-config (Melhoria 3 intacta).** `CLAUDE.md`, `.cursorrules`, `AGENTS.md`, `.windsurfrules`, etc. CONTINUAM sendo inspecionados como instrução acionável — ali o texto É o comando que a IA executa. A distinção é: **markdown de documentação humana = prosa inofensiva; markdown de config de IDE = instrução acionável.** Relaxe só a prosa de documentação comum; mantenha o scan de IDE-config 100% ativo. Não confunda os dois.

**B.4 — Comentário/doc com IMDS → CLEAN.** `cloud_imds_access` e fontes da Melhoria 1 já são SUSPICIOUS isoladas (viram MALICIOUS só via `exfil_chain`). Quando a menção está em comentário/doc, deve ser CLEAN — não poluir documentação com avisos.

**B.5 — Comentário-guia obrigatório no código da regra:** `// Detectamos a AÇÃO (ler credencial E enviar para fora, em código que executa), não a MENÇÃO (a palavra 'credential' em texto). Prosa que descreve um ataque não é o ataque.`

---

## FASE C — PROVAR (testes executados, não escritos)

**C.1 — Casos negativos novos, executados de verdade (esperado CLEAN):** mínimo 8, incluindo:
- o próprio `RELATORIO-MANUTENCAO.md` (deve passar a escrever sem bloqueio),
- um `SECURITY.md` realista descrevendo os vetores em prosa,
- um README com "exfiltration"/"credential"/"IMDS" em contexto educacional,
- código com leitura legítima de `.env` (config de app) SEM sink de rede,
- uso legítimo de `169.254.169.254` em comentário de infra.
Rode e cole o resultado (CLEAN em todos).

**C.2 — Regressão de recall obrigatória:**
```
cd /home/fernando/devproj/Nemesis_Defender_v2.0
bash .nemesis/pentest-nemesis-control/run-pentest.sh .nemesis/target/release/nemesis-pretool-check-unix | tee pentest-pos-calibracao.txt
```
Os 144 (M1–M24) continuam 144/144. Em especial M22 (exfil chains) e M24 (taint flow) — que dependem de fonte+sink em código real — continuam 100%. Se algum cair, a calibração relaxou demais: ela deve parar de pegar PROSA, não CÓDIGO MALICIOSO.

**C.3 — Novo módulo M25 — FALSO-POSITIVO (deve PASSAR), no `run-pentest.sh`.** Diferente dos outros, aqui o esperado é **exit 0 (PASSA)**, não exit 2. Inclua: SECURITY.md legítimo, README com termos de segurança, leitura legítima de `.env`, comentário de infra com IMDS. Inverta a lógica de PASS só para esse bloco (passou = NÃO bloqueou) e ajuste o relatório. Isso faz o pentest medir falso-positivo além de recall, daqui pra frente.

**Entregável Fase C:** negativos executados (CLEAN), pentest 144/144 mantido, M25 medindo falso-positivo.

---

## FASE D — RELATÓRIO E COMMITS

1. Atualize `RELATORIO-MANUTENCAO.md` com a seção "Ratificação + Calibração (follow-up)": o erro de localização do taint_tracker (se encontrado e corrigido), o falso-positivo (bloqueio do próprio relatório), a causa-raiz, a correção (código vs. prosa), e a evidência (cargo test executado + negativos CLEAN + pentest mantido + M25).
   - Critério de sucesso explícito: **este relatório, descrevendo o ataque em prosa, deve ser escrito SEM bloqueio.** Se o Defender bloquear de novo, a calibração falhou — investigue, não contorne reescrevendo abstrato.
2. Corrija a afirmação anterior do relatório que marcava testes como ✅ sem execução — agora com números reais do `cargo test`.
3. Prepare diffs + mensagens de commit sugeridas (uma por correção). **NÃO commite.**

---

## RESUMO DO QUE NÃO FAZER
- ❌ Colocar visitor de segurança em `ast-linters/` (é módulo de QUALIDADE). Segurança vive em `nemesis-defender/src/visitors/`.
- ❌ Reduzir recall para silenciar o falso-positivo (distinguir prosa de código, não cegar o detector).
- ❌ Relaxar o scan de IDE-config (CLAUDE.md/.cursorrules continuam instrução acionável → MALICIOUS).
- ❌ Marcar teste como ✅ sem EXECUTAR `cargo test`.
- ❌ Contornar o bloqueio do relatório reescrevendo abstrato — isso esconde o bug.
- ❌ Heurística probabilística para "é doc?" — use sinais determinísticos (extensão, nó AST de comentário/string, presença de sink).
- ❌ Commitar sozinho.

Comece pela **Seção 0** (auditoria de localização) e pela **Fase A** (cargo test + reprodução do falso-positivo). Mostre ao Fernando antes de calibrar qualquer regra.
