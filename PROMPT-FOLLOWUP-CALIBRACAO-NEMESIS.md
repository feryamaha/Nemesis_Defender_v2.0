# PROMPT FOLLOW-UP — NEMESIS DEFENDER v2.0
## Calibração de falso-positivo + validação de testes (pós-manutenção das 5 melhorias)

Você é o engenheiro de segurança Rust que acabou de implementar 5 melhorias na Camada 2 (Defender) do **Nemesis Defender**. As melhorias passaram em recall (144/144 no pentest, zero regressão), MAS uma falha de calibração apareceu e precisa ser corrigida ANTES dos commits: **o Defender bloqueou a escrita do próprio `RELATORIO-MANUTENCAO.md`** — um arquivo de documentação legítimo — porque as regras novas casaram com menções textuais de "credential", "IMDS", "shell history" em prosa, sem nenhum sink de execução real.

Isso é um **falso-positivo de severidade alta**. É exatamente a classe de erro que já custou 24 arquivos apagados neste projeto no passado. Documentação de segurança (SECURITY.md, README, advisories, este próprio relatório) menciona esses termos por natureza. Uma regra que trata "texto que descreve um ataque" como "o ataque" é uma regra quebrada — vai bloquear arquivos legítimos de qualquer projeto sério e destruir a credibilidade do Nemesis.

Sua tarefa: rodar a validação que faltou, corrigir a causa-raiz do falso-positivo, e provar (com teste executado, não só escrito) que conteúdo legítimo passa.

---

## CONTEXTO OPERACIONAL (LEIA — define como você trabalha aqui)

Restrições reais deste ambiente, confirmadas pelo Fernando:
- Com o **pretool conectado**, nenhum modelo consegue ler arquivos de `.nemesis/`. Com os **binários ausentes** de `target/release`, o hook de fallback bloqueia tudo (fail-closed).
- Por isso, o workflow autorizado é: **pretool desconectado + binários compilados**, e você executa a validação completa de uma vez. NÃO peça para reconectar/desconectar o pretool a cada passo — isso queima tokens do Fernando sem ganho.
- **Git é 100% humano.** Você prepara o diff e a mensagem; o Fernando commita. Nunca commite.
- **Você prepara comandos que o Fernando roda no terminal dele quando precisar de algo que o ambiente do Claude Code bloqueia.** Não fique tentando furar o próprio hook — se algo te bloquear, entregue o comando pronto para o Fernando colar.

Princípios inegociáveis (os mesmos da manutenção): determinístico, offline, human-gated, fail-closed, sem LLM no caminho de decisão, sem pattern hardcoded na lógica (vai para deny-list/config). A correção do falso-positivo **NÃO pode** reduzir o recall — não é para enfraquecer a detecção de ataque real, é para parar de confundir prosa com payload.

---

## FASE A — VALIDAÇÃO QUE FALTOU (executar primeiro, antes de calibrar)

1. **Rode os testes unitários** (não foram executados na manutenção — só `cargo check`):
   ```
   cd .nemesis && cargo test --workspace 2>&1 | tee cargo-test-output.txt
   ```
   Reporte o resultado real de CADA arquivo de teste novo:
   `tests/m1_credential_harvest_extended.rs`, `tests/m2_exfil_chain.rs`, `tests/m3_m4_ide_config_poisoning.rs`, `tests/m5_taint_tracking.rs`.
   Quero ver, por arquivo: quantos casos POSITIVOS passaram e — crucialmente — quantos casos NEGATIVOS (anti-falso-positivo) passaram. Se algum negativo falhar, ele é um falso-positivo confirmado a corrigir na Fase B.
   Se `cargo test` for bloqueado pelo seu ambiente, entregue o comando para o Fernando rodar e peça o output.

2. **Reproduza o falso-positivo do relatório de forma controlada.** Crie um arquivo de teste de documentação legítima e rode o scanner contra ele:
   ```
   .nemesis/target/release/nemesis-defender --scan <arquivo-doc-legitimo>
   ```
   Use como corpo de teste um markdown que descreve os vetores em prosa técnica honesta (igual a um SECURITY.md real): menciona "credential harvesting", "IMDS / 169.254.169.254", "shell history", "exfiltration" — mas **sem nenhum código executável que leia+envie**. O resultado correto seria CLEAN ou no máximo SUSPICIOUS, NUNCA MALICIOUS. Documente o que o scanner retorna hoje.

**Entregável da Fase A:** o output real do `cargo test` (positivos e negativos por arquivo) + a reprodução do falso-positivo no markdown. **PARE e me mostre antes de calibrar.**

---

## FASE B — CALIBRAÇÃO DA CAUSA-RAIZ (o coração desta tarefa)

O problema central: regras das Melhorias 1 e 4 (`credential_harvest`, `credential_exfiltration_comment`, `cloud_imds_access`, `fake_security_scan`, `authority_injection`) estão disparando MALICIOUS por **menção isolada de palavra-chave em texto/comentário/markdown**, sem exigir a presença de um **sink real de execução ou rede**.

A correção segue o princípio que a própria Melhoria 2 (`exfil_chain`) já acertou: **fonte sozinha não é ataque; ataque é fonte + sink juntos, em código executável.**

Implemente a calibração assim:

1. **Distinção contexto-código vs. contexto-texto.** Uma menção de credencial/IMDS/exfil que aparece em:
   - comentário de código (`//`, `#`, `/* */`, `<!-- -->`),
   - string literal de documentação,
   - corpo de markdown (`.md`), texto (`.txt`), ou linguagem natural,
   
   NÃO deve ser MALICIOUS por si só. No máximo SUSPICIOUS, e idealmente CLEAN se não houver nenhum sink executável real no mesmo arquivo. A regra `credential_exfiltration_comment` é a principal suspeita — ela está tratando comentário/doc como execução. Reescreva-a para exigir co-ocorrência com um sink real (chamada de rede/exec efetiva), não só a presença das palavras.

2. **Arquivos de documentação pura** (`.md`, `.txt`, `.rst`, `CHANGELOG`, `LICENSE`, `README`, `SECURITY`, `CONTRIBUTING`) que contêm apenas prosa — sem bloco de código executável com fonte→sink — devem retornar CLEAN. Atenção ao caso real que falhou: um relatório técnico que *descreve* vetores de ataque é documentação legítima.
   - CUIDADO para não criar um buraco: a Melhoria 3 (`ide_config_poisoning`) PRECISA continuar inspecionando `CLAUDE.md`, `.cursorrules`, `AGENTS.md` etc., porque ali o "texto" É a instrução que a IA executa. A distinção é: **markdown de documentação humana = prosa inofensiva; markdown de config de IDE = instrução acionável.** Mantenha o scan de IDE-config intacto; relaxe apenas a interpretação de prosa em documentação comum. Não confunda os dois.

3. **`cloud_imds_access` e as fontes da Melhoria 1**: já estão (corretamente) marcadas como SUSPICIOUS isoladas e só viram MALICIOUS via `exfil_chain`. Confirme que isso vale também quando a menção está em comentário/doc — lá deve ser CLEAN, não SUSPICIOUS, para não poluir documentação com avisos.

4. **Princípio-guia da calibração (escreva isso como comentário no código da regra):** "Detectamos a AÇÃO (ler credencial E enviar para fora, em código que executa), não a MENÇÃO (a palavra 'credential' em texto). Prosa que descreve um ataque não é o ataque."

Tudo determinístico. Nada de "provavelmente é doc" via heurística probabilística — use sinais concretos: extensão do arquivo, se a menção está dentro de nó de comentário/string na AST, presença ou ausência de sink executável real no arquivo.

---

## FASE C — PROVAR QUE A CALIBRAÇÃO FUNCIONA (testes executados, não escritos)

A manutenção anterior marcou a Fase de testes como ✅ tendo apenas *escrito* os casos negativos sem *executá-los*. Aqui isso não vale. Para cada correção:

1. **Casos negativos novos** (devem retornar CLEAN), executados de verdade:
   - O próprio `RELATORIO-MANUTENCAO.md` (o arquivo que falhou) → deve passar a escrever sem bloqueio.
   - Um `SECURITY.md` realista descrevendo os vetores em prosa.
   - Um README mencionando "exfiltration", "credential", "IMDS" em contexto educacional.
   - Código com leitura legítima de `.env` (config de app) SEM sink de rede.
   - Uso legítimo de `169.254.169.254` em comentário de infra.
   Mínimo 8 casos negativos. Rode-os e cole o resultado (CLEAN esperado em todos).

2. **Regressão de recall obrigatória** — a calibração NÃO pode abrir buraco. Rode o pentest completo de novo:
   ```
   cd /home/fernando/devproj/Nemesis_Defender_v2.0
   bash .nemesis/pentest-nemesis-control/run-pentest.sh .nemesis/target/release/nemesis-pretool-check-unix | tee pentest-pos-calibracao.txt
   ```
   Os 144 testes (M1–M24) precisam continuar 144/144. Em especial, confirme que M22 (exfil chains) e M24 (taint flow) — que dependem de fonte+sink em código real — continuam bloqueando 100%. Se algum cair, a calibração relaxou demais: ela deve parar de pegar PROSA, não parar de pegar CÓDIGO MALICIOSO.

3. **Adicione um módulo de casos negativos ao pentest** (`run-pentest.sh`), ex. **M25 — FALSO-POSITIVO (deve PASSAR)**. Diferente dos outros módulos, aqui o resultado esperado é **exit code 0 (PASSA)**, não exit 2. Inclua: SECURITY.md legítimo, README com termos de segurança, leitura legítima de `.env`, comentário de infra com IMDS. Ajuste a contagem do relatório para tratar esse módulo como "passou se NÃO bloqueou" (inverta a lógica de PASS para esse bloco). Isso faz o pentest medir, daqui pra frente, falso-positivo além de recall — e impede regressão futura nesse eixo.

**Entregável da Fase C:** output executado dos casos negativos (todos CLEAN), pentest pós-calibração 144/144 mantido, e o novo M25 medindo falso-positivo.

---

## FASE D — RELATÓRIO E COMMITS

1. Atualize o `RELATORIO-MANUTENCAO.md` com uma seção "Calibração de falso-positivo (follow-up)" registrando: o falso-positivo encontrado (bloqueio do próprio relatório), a causa-raiz (regra casando menção textual sem sink), a correção (distinção código-executável vs. prosa), e a evidência (testes negativos executados + pentest mantido).
   - Se o próprio Defender bloquear a escrita deste relatório de novo, isso agora é um TESTE: significa que a calibração ainda não funcionou. Investigue em vez de contornar reescrevendo abstrato. O relatório descrevendo o ataque deve passar — esse é o critério de sucesso.
2. Prepare os diffs e mensagens de commit sugeridas (uma por correção). **NÃO commite — o Fernando faz.**

---

## RESUMO DO QUE NÃO FAZER
- ❌ Reduzir recall para silenciar o falso-positivo. (A meta é distinguir prosa de código, não cegar o detector.)
- ❌ Relaxar o scan de IDE-config (CLAUDE.md/.cursorrules como instrução acionável continua MALICIOUS).
- ❌ Marcar teste como ✅ sem EXECUTAR (`cargo test` tem que rodar de verdade).
- ❌ Contornar o bloqueio do relatório reescrevendo de forma abstrata — isso esconde o bug. O relatório legítimo tem que passar.
- ❌ Heurística probabilística para decidir "é doc?". Use sinais determinísticos (extensão, nó AST de comentário/string, presença de sink).
- ❌ Commitar sozinho.

Comece pela **Fase A** e me mostre o output real do `cargo test` + a reprodução do falso-positivo antes de calibrar qualquer regra.
