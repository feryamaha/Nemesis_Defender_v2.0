# Nemesis Defender

> Enforcement determinístico contra comandos destrutivos e malware de supply-chain em fluxos de desenvolvimento assistido por agentes LLM. Escrito em Rust.

[![Licença: AGPL-3.0](https://img.shields.io/badge/Licen%C3%A7a-AGPL--3.0-blue.svg)](LICENSE)
[![Versão](https://img.shields.io/badge/vers%C3%A3o-0.x-00B4D8.svg)](#)
[![Testado](https://img.shields.io/badge/testado-Linux%20%C2%B7%20macOS-success.svg)](#suporte-por-plataforma)
[![Windows](https://img.shields.io/badge/Windows-best--effort%20(n%C3%A3o%20validado)-yellow.svg)](#suporte-por-plataforma)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange.svg)](#requisitos)

Documentação conceitual completa (o que é, por que existe, modelo de ameaça): **[feryamaha.github.io/Nemesis_Defender_v0](https://feryamaha.github.io/Nemesis_Defender_v0/)**

Este README é o documento **técnico e operacional**: como instalar, configurar e usar. Para entender a filosofia e a arquitetura em profundidade, leia o site acima.

---

## ⚠️ Leia antes de instalar

O Nemesis existe para conter a **autonomia do agente de IA** — o alvo é o modelo LLM, não você. Ele intercepta, **no momento em que tentam executar**, as operações que o agente dispara (escrever arquivos, rodar comandos) e barra as destrutivas ou maliciosas. O comando em si não é o inimigo; a invocação **autônoma** pelo modelo é.

A **instalação é automática**: detecta a sua IDE e configura os hooks sozinha. A partir daí o enforcement fica ativo no runtime: o pretool barra a escrita/execução hostil e o daemon (Iron Dome) vigia o filesystem. Ao **confirmar** hostilidade (por corroboração de sinais independentes, para não mover código legítimo por engano) ele **move para quarentena** (não deleta) e segura a sessão até a sua revisão; é **reversível** via `restore` ou `purge`. No Linux há ainda a camada **eBPF** opcional (opt-in) como rede no kernel caso o pretool seja contornado.

As regras de **bloqueio são embutidas no binário** (tamper-proof): o agente não consegue enfraquecê-las editando arquivos. A **única** superfície que você (humano) edita é a **allowlist** (`.nemesis/denylist-customers/allowlist-customers.jsonc`): um override absoluto, **por sua conta e risco**, para liberar o que a sua stack precisa. O Nemesis é calibrado para frontend (Next/React/TS), então **backend e DevSecOps** tendem a relaxar mais por ali. E tudo é removível: a desinstalação é um comando (`nemesis-uninstall.sh`).

---

## Índice

- [O que o Nemesis faz](#o-que-o-nemesis-faz)
- [Arquitetura em camadas](#arquitetura-em-camadas)
- [Suporte por plataforma](#suporte-por-plataforma)
- [Decisões de design (e não-objetivos)](#decisões-de-design-e-não-objetivos)
- [Modelo de detecção e severidade](#modelo-de-detecção-e-severidade)
- [Vetores de ataque cobertos](#vetores-de-ataque-cobertos)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Desinstalação](#desinstalação)
- [Nemesis Doctor](#nemesis-doctor)
- [Configuração do Pretool por IDE](#configuração-do-pretool-por-ide)
- [Configuração da camada eBPF (Linux)](#configuração-da-camada-ebpf-linux)
- [Controle de paths](#controle-de-paths)
- [Uso no dia a dia](#uso-no-dia-a-dia)
- [Verificação e diagnóstico](#verificação-e-diagnóstico)
- [Relaxar ou customizar regras](#relaxar-ou-customizar-regras)
- [Solução de problemas](#solução-de-problemas)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Contribuição](#contribuição)
- [Segurança e disclosure](#segurança-e-disclosure)
- [Licença](#licença)

---

## O que o Nemesis faz

O Nemesis intercepta e bloqueia, **antes da execução**, comandos destrutivos e padrões de malware de supply-chain em ambientes onde um agente LLM opera sobre o código. Ele se acopla aos **hooks de pre-tool** que as IDEs/agentes modernos já expõem, e adiciona, no Linux, uma camada de kernel (eBPF) como rede de contenção independente.

Não é um linter genérico nem substitui ESLint, Biome, SAST ou CI/CD. É uma **barreira de bloqueio em tempo de execução** complementar a essas ferramentas, focada no caso de uso específico: impedir que um agente, por engano ou por manipulação, rode um `rm -rf` no lugar errado ou execute um pacote malicioso.

A premissa técnica: instrução em texto (`"não rode comandos destrutivos"`) é probabilística e o modelo pode ignorá-la; **enforcement determinístico via exit code é categórico** - não importa se o modelo foi enganado ou apenas errou, a camada bloqueia.

---

## Arquitetura em camadas

| Camada | Onde atua | Mecanismo | SO |
|--------|-----------|-----------|-----|
| **Pretool / Posttool Hook** | Antes do `Bash.run()` / file-write | Deny-list JSON + exit code 2 | Linux · macOS · Windows\* |
| **Nemesis Defender** (scanner) | Em file-write e em comandos | 6 layers: AST, byte, regex, denylist, entropia, decoder | Linux · macOS · Windows\* |
| **eBPF Kernel LSM** | Syscalls no kernel | BPF LSM: `bprm_check_security` (exec) + `socket_connect` (egress allowlist), retorna `-EPERM` | **Linux apenas** |

**A defesa principal são as camadas 1 e 2 (Pretool + Defender) — completas e idênticas em Linux e macOS (as plataformas validadas).** O Pretool intercepta a ação do agente antes da execução; o Defender escaneia o conteúdo. Em Windows elas rodam em princípio, mas **sem validação** — veja [Suporte por plataforma](#suporte-por-plataforma).

A camada **eBPF (camada 3) é um reforço de kernel EXCLUSIVO do Linux** — não é a defesa principal nem um requisito para o Nemesis funcionar. Ela cobre **um cenário específico**: se o Pretool for desligado ou contornado, o kernel ainda segura comandos destrutivos. Por isso o eBPF é o *backstop* — ele existe **justamente para o caso de o pretool falhar**, não o contrário.

> **Rodar em macOS/Windows com 2 camadas é o design, não uma lacuna.** O eBPF é um bônus de profundidade **onde o SO o oferece** (Linux); não é algo que "falta" onde não existe. A proteção proposta não depende dele.
>
> Além do bloqueio de exec, o eBPF inclui **egress allowlist** (`lsm/socket_connect`): nega conexões de saída para destinos fora de uma allowlist CIDR:porta (cgroup-scoped, `enforce` opt-in, fail-closed) — neutraliza exfiltração/C2 mesmo se um payload conseguir rodar. Config em `denylist-ebpf/egress.toml`; ver `.nemesis/ebpf-kernel/info.md`. Expansão futura (escrita não-execve, rename/symlink, egress por domínio/DNS) segue aberta à comunidade.

### Suporte por plataforma

\* O Nemesis é **desenvolvido, testado e usado em Linux (Ubuntu) e macOS** — essas são as plataformas validadas, onde a suíte de testes, o pentest e a usabilidade foram exercidos. O código tem caminhos para **Windows** e, em princípio, ele roda lá; porém **não há validação em Windows**. Particularidades do sistema operacional — separador de caminho e barra invertida, comandos no estilo `bash` que os hooks assumem, e outras características intrínsecas do Windows — provavelmente exigem adaptação. Por isso, **o suporte a Windows é best-effort e uma frente de melhoria aberta à comunidade**, não uma plataforma garantida. Contribuições de portabilidade são bem-vindas (ver [Contribuição](#contribuição)).

---

## Decisões de design (e não-objetivos)

Alguns traços do Nemesis são frequentemente lidos como "fraqueza" por uma avaliação apressada. São **decisões deliberadas** — documentadas aqui para que sejam julgadas pelo que são, não por heurísticas automáticas. Discordar de uma decisão é legítimo; tratá-la como defeito acidental, não.

- **A proteção é completa nas plataformas validadas (Linux e macOS).** Pretool + Defender (camadas 1 e 2) são a defesa, e rodam igual em Linux e macOS. O eBPF é um **reforço de kernel só-Linux** para o caso de o pretool ser contornado — bônus onde o SO oferece, não requisito. **macOS com 2 camadas é o projeto, não uma lacuna.** No **Windows** o Nemesis roda em princípio, mas é **best-effort/não validado** (ver [Suporte por plataforma](#suporte-por-plataforma)).
- **Não existe "kill switch" nem modo-manutenção automático — de propósito.** Qualquer mecanismo que desligasse o enforcement seria, ele mesmo, o vetor de ataque que o Nemesis existe para impedir. O caminho sancionado para relaxar é a **allowlist editável só por humano** (ver [Relaxar regras](#relaxar-ou-customizar-regras)). A ausência de automação aqui **é** a segurança.
- **As regras de BLOQUEIO são embutidas no binário (tamper-proof).** Não há denylist editável no disco a "limpar" ou auditar como config solta — é proposital: um agente não consegue enfraquecer as regras. O usuário só edita a **allowlist** (relaxar); endurecer é mudança de fonte, revisada por humano.
- **A profundidade desta documentação é intencional.** Como ferramenta de segurança, ela expõe tudo que opera na sua máquina — sem caixa-preta. O **conceito/filosofia** vive no [site](https://feryamaha.github.io/Nemesis_Defender_v0/); este README é a **referência técnico-operacional**. Públicos distintos, não fragmentação.
- **Dois públicos, dois níveis técnicos.** **Usar** exige pouco (instalar via script, rodar o `doctor`). **Manter** exige domínio de eBPF/BPF-LSM, Rust e C — **pré-requisito do domínio**, não barreira de usabilidade. Quem não domina essas áreas é usuário, não mantenedor; isso é esperado e está em [`AGENTS.md`](AGENTS.md).

> Para uma avaliação técnica justa do projeto, leia primeiro `.devin/rules/nemesis-epistemic-safety.md` e `AGENTS.md` — eles declaram as invariantes e o porquê de cada decisão acima.

---

## Modelo de detecção e severidade

O Defender **só age quando a hostilidade é confirmada** — e **não deleta: move para quarentena** (`.nemesis/quarantine/`), preservando o conteúdo para revisão humana. Isso separa um "iron dome" de uma metralhadora que derruba avião amigo.

- **Sinais de alta confiança (confirmatórios)** bloqueiam sozinhos: deny-list curada, `decode → exec`, cadeia de exfiltração (fonte sensível + sink de rede), reverse shell (socket cru + execução de comando), tentativa de bypass do próprio Nemesis, e injeção em config de IDE.
- **Sinais heurísticos (substring/padrão)** exigem **corroboração — 2 métodos de detecção independentes concordando** — antes de quarentenar. Sozinhos, ficam em `Suspicious` (registrado, arquivo mantido). Contar *tipos distintos* de detector (não múltiplos hits do mesmo) impede que N coincidências da mesma causa escalem indevidamente.

**Quarentena, não exclusão.** Ao confirmar `Malicious`, o daemon **move** o arquivo para `.nemesis/quarantine/<id>/` (com `meta.json` do motivo), **bloqueia a sessão** (exit 2, `QUARENTENA PENDENTE`) e espera o humano: `nemesis-defender --quarantine list | show <id> | restore <id> | purge <id>`. O instalador do próprio Nemesis (`nemesis-install.sh`) é isento (ele legitimamente contém os padrões detectados).

A corroboração existe justamente para **não agir sobre código legítimo por engano** — sinais isolados não bastam para mover um arquivo.

**Cobertura de execução multi-runtime.** A detecção de reverse shell e de execução ofuscada/dinâmica não se limita a JS/Python/Bash: cobre também **Ruby, PHP, Go, Perl, Java e Lua** (socket cru + exec; `Function`-constructor / `globalThis["eval"]`; `__import__('os').system`, `getattr(__builtins__)`; `.send(:eval)`, `instance_eval`; `create_function`, `assert`).

**Proteção de paths endurecida** contra ofuscação: glob que expande para alvo protegido (em qualquer componente, inclusive o diretório — `.de*/hooks.json`), `cd`/`pushd` para dentro de diretório protegido, e indireção por variável ou `$(<arquivo)`.

**Propriedades estruturais.** O hook é **fail-closed**: qualquer panic vira `exit 2` (bloqueia). O motor de regex é de **tempo linear** (sem backtracking), então não há ReDoS — entrada patológica não trava nem força fail-open.

> Estas regras nasceram de uma campanha de **red-team com agente real** (engenharia social reversa, ao vivo): cada vetor de evasão encontrado foi fechado na origem e validado com a suíte de pentest sem regressão. Nenhum vetor que *neutralize* a proteção foi encontrado. Bypasses continuam **bem-vindos** — ver [Segurança e disclosure](#segurança-e-disclosure).

---

## Vetores de ataque cobertos

A proteção do Nemesis é um **coeficiente**: a soma de camadas independentes, não a contagem de uma feature isolada. Um *visitor* é um **método de detecção** (análise semântica AST), não a unidade de cobertura, visitor é feature, não produto. A cobertura real é a soma das superfícies que operam juntas: a deny-list embutida do Defender (**dezenas de categorias, centenas de patterns**), os visitors AST, as heurísticas de scanner (byte, entropia, regex, manifest, decoder), as deny-lists de comando do pretool e o eBPF no Linux. A prova empírica é a suíte de pentest (classes de ataque validadas como gate de CI). **Vetores fora do que foi antecipado podem não ser detectados**, e isso é declarado abertamente.

A tabela abaixo é **exemplificativa por método de detecção** (não é a contagem da proteção, nem uma lista 1:1 de visitors): mostra classes de ataque cobertas e onde a detecção mora. A enumeração completa e rastreável está em **re-auditoria forense** (ver `Feature-Documentation/ISSUE`).

| # | Detector (camada/método) | Alvo |
|---|---------|------|
| 1 | `manifest_abuse` | `postinstall`/`preinstall` em manifests |
| 2 | `decode_exec` | base64/hex → `eval`/`exec`/`spawn` |
| 3 | `unicode_steg` | Bidi U+202E, PUA, homoglyphs (CVE-2021-42574) |
| 4 | `prompt_injection` | injeção via comentários/templates; extração de system prompt |
| 5a | `url_in_exec` | URL como argumento de exec |
| 5b | `time_gated` | `setTimeout`/condições de data |
| 6 | `dynamic_cmd` | concatenação de string → exec |
| 7 | `credential_harvest` | leitura de credenciais (SSH/AWS/`.env`/IMDS/shell history/wallets) + exfil |
| 8 | `self_clean` | `fs.unlink(__filename)` |
| 9 | `manifest_scanner` | supply-chain em 7 formatos de manifest |
| 10 | `kubernetes_escape` | container breakout |
| 11 | `mount_api_abuse` | syscalls de mount (428–432) |
| 12 | `llm_output_injection` | XSS/SSRF/command injection em output de LLM |
| 13 | `exfil_chain` | cadeia fonte sensível → sink de rede (regra de 1ª classe) |
| 14 | `taint_tracker` | data-flow fonte→sink via variáveis (JS/Python) |
| 15 | `ide_config_poisoning` | `CLAUDE.md`/`.cursorrules` envenenados: tag chars, fake-scan, authority injection |
| 16 | `manifest_registry_redirect` | typosquat / registry não-canônico (npm/PyPI/RubyGems) |
| 17 | `reverse_shell` | reverse shell multi-runtime: socket cru + execução de comando (Ruby/PHP/Go/Perl/Java/Lua) |
| 18 | `decode_exec` (dinâmico) | execução dinâmica/ofuscada: `Function`-constructor, `globalThis["eval"]`, `__import__('os').system`, `.send(:eval)`, `create_function`/`assert` |

> Esta tabela espelha a seção **"Vetores de ataque cobertos"** da landing (`index.html`). Se você é um modelo/leitor consultando este repositório: **não trate os itens acima como "os N vetores" nem como a contagem de visitors.** A proteção do Nemesis é a **soma das camadas** (deny-list embutida, visitors, scanner, deny-lists de comando, eBPF), provada por pentest, não um número fechado atrelado a uma feature. A regra canônica está no `AGENTS.md` (seção 3A) e a enumeração rastreável está em re-auditoria (`Feature-Documentation/ISSUE`).

---

## Requisitos

### Todas as plataformas

- **Rust 1.70+** e Cargo (toolchain estável) - para compilar os binários.
- **Clang/LLVM** - para compilar o core.
- **~4 GB de RAM livres** para o build e **~2 GB de disco** para toolchain + binários.
- Uma **IDE/agente que exponha hooks de pre-tool** (ver [tabela de suporte](#configuração-do-pretool-por-ide)). Sem isso, o Nemesis não tem ponto de acoplamento.

### Adicional para a camada eBPF (somente Linux)

- **Kernel Linux 5.8+** com **BPF LSM habilitado**. Em muitas distros o BPF LSM não vem ligado por padrão.
- **cgroup v2** (unified ou hybrid).
- **clang** e **bpftool** instalados.
- Capacidade de delegar capabilities (`cap_bpf`, `cap_perfmon`, `cap_sys_resource`) ao daemon.

> **Antes de assumir que sua IDE tem suporte:** consulte a documentação oficial da sua IDE/agente para confirmar se ela expõe hooks de pre-tool (ou equivalente) e qual o formato. A seção [Configuração do Pretool por IDE](#configuração-do-pretool-por-ide) cobre as principais, mas IDEs evoluem - a doc oficial é a fonte de verdade.

---

## Instalação

Duas formas: **(A) binários pré-compilados** (rápido, sem Rust) ou **(B) compilar da fonte** (necessário para a camada eBPF e para contribuir).

### Opção A — Binários pré-compilados (recomendado)

Baixa os binários do **GitHub Release**, **verifica o checksum SHA256** e instala em `.nemesis/bin/` no seu projeto, já configurando o hook da IDE detectada. Suporta **macOS (arm64/x64)** e **Linux (x64)**. Sem `git clone`, sem `cargo`, sem `npm`.

Um único comando baixa o instalador **e** o guia (`info-install.txt`) e já instala. O arquivo vai para o disco antes de rodar (auditável) — **não** é o pipe cego `curl … | sh`, que o Nemesis bloqueia como vetor de ataque. Copie o bloco inteiro:

**A partir da RAIZ do seu projeto:**
```bash
curl -fsSLO https://raw.githubusercontent.com/feryamaha/Nemesis_Defender_v0/main/.nemesis/install/nemesis-install.sh \
     -O      https://raw.githubusercontent.com/feryamaha/Nemesis_Defender_v0/main/.nemesis/install/info-install.txt \
  && bash nemesis-install.sh
```

O `info-install.txt` fica na raiz do seu projeto com o passo a passo pós-install (doctor + pentest). O instalador faz **só o essencial** (baixar, verificar checksum, extrair, scaffold do hook) — **não roda validação nem sobe o daemon**, que é manual, no [mapa de instalação](#mapa-de-instalação-resumo) abaixo. Quer inspecionar antes de rodar? Baixe sem o `&& bash …` e leia com `less nemesis-install.sh`.

O instalador detecta SO/arch, baixa o tarball da release, **confere o SHA256 antes de extrair** (aborta se não bater), instala os binários e as deny-lists, e **detecta a(s) IDE(s) presente(s) e escreve o hook no formato CORRETO de cada uma** (nome de arquivo + schema próprios), sem sobrescrever config existente:

| IDE | Arquivo | Formato |
|-----|---------|---------|
| **Claude Code / OpenClaude** | `.claude/settings.json` · `.openclaude/settings.json` | `PreToolUse`/`PostToolUse` + `matcher` + `hooks[]` |
| **OpenAI Codex** | `.codex/hooks.json` | `matcher: ".*"` + `timeout` |
| **Cursor** (1.7+) | `.cursor/hooks.json` | `version:1`, `preToolUse`/`postToolUse` (camelCase) + `failClosed` |
| **Devin** | `.devin/hooks.json` | eventos `pre_write_code`/`pre_run_command`/`pre_read_code`/`pre_mcp_tool_use` (+ `post_*`) |
| **Gemini / Agents** | `.gemini/hooks.json` · `.agents/hooks.json` | objetos `nemesis-pretool-hook`/`nemesis-posttool-hook` com `enabled` |
| **VS Code / GitHub Copilot** | `.github/hooks/nemesis-pretool-hook.json` (+ `.vscode/settings.json` aponta para ele) | caminho relativo `./.nemesis/bin/...` |

Caminho absoluto para os binários (relativo no caso do GitHub/VS Code). Versão fixa: `NEMESIS_VERSION=v0.1.0 bash nemesis-install.sh`.

> A **camada eBPF (Linux)** NÃO vem nos binários: depende de `libbpf`/`clang` e de um objeto BPF compatível com o seu kernel. É **opt-in**, construída da fonte (Opção B). O core (pretool + Defender) protege em macOS e Linux sem ela.

#### Mapa de instalação (resumo)

Fluxo completo, **na ordem**, agnóstico de SO (macOS/Linux) — todos os comandos a partir da **raiz do seu projeto**:

Cada passo é **um comando** para copiar inteiro:

| # | Passo | Comando (copie inteiro) |
|---|-------|---------|
| 1 | **Baixar e instalar** | `curl -fsSLO …/main/.nemesis/install/nemesis-install.sh -O …/main/.nemesis/install/info-install.txt && bash nemesis-install.sh` |
| 2 | **Reiniciar a IDE** (hooks entram em vigor) | — |
| 3 | **Diagnóstico** (siga as ações que ele indicar) | `.nemesis/bin/nemesis-doctor --quick` |
| 4 | **Nível 1 — validação estática** (binário auto-detectado) | `bash .nemesis/pentest-nemesis-control/nemesis-defender/run-pentest.sh` |
| 5 | **Nível 2 — validação prática** (cole no agente) | conteúdo de `.nemesis/pentest-nemesis-control/nemesis-defender/pentest-final-amplificado-portal-dental.md` |

O **doctor** (passo 4) imprime, em cada verificação que falha, a **ação exata** já no caminho do seu layout (ex.: se o **G6** indicar daemon parado, rode `.nemesis/bin/nemesis-defender --ensure-daemon` e rode o doctor de novo). O passo a passo detalhado está em **`info-install.txt`** (raiz) e em `.nemesis/pentest-nemesis-control/nemesis-defender/info.md`.

### Opção B — Compilar da fonte

Necessário para a camada **eBPF** ou para **contribuir**.

```bash
# Binários gerados em .nemesis/target/release/
git clone https://github.com/feryamaha/Nemesis_Defender_v0.git
cd Nemesis_Defender_v0/.nemesis
cargo build --release --workspace
```

A compilação leva alguns minutos e exige os ~4 GB de RAM mencionados nos requisitos. Ao final, confirme que os binários existem:

```bash
ls -la .nemesis/target/release/ | grep nemesis
```

### 2. Apontar os hooks da IDE para o binário

Este é o passo que efetivamente liga o Nemesis. Cada IDE tem seu formato - ver a próxima seção. O ponto comum: o hook de pre-tool precisa apontar para o **caminho absoluto** do binário do Nemesis no seu projeto.

> **Caminho errado ou ausente = o Nemesis não roda.** A IDE simplesmente não invoca o hook, e você fica desprotegido sem perceber. Sempre confirme que o caminho no `command` aponta para o binário real (`nemesis-pretool-check-unix`) no seu projeto.

> **Manual de operações unificado:** para instruções completas de compilação por módulo, configuração do eBPF, operação do daemon, pentest e checklist de instalação em nova máquina, consulte [`.nemesis/nemesis-doctor/NEMESIS-OPERATIONS.md`](.nemesis/nemesis-doctor/NEMESIS-OPERATIONS.md).

---

## Desinstalação

Rode na **raiz do projeto**, no seu **terminal nativo**. O script reverte o `nemesis-install.sh`: para o daemon, desabilita o serviço eBPF (se você ativou, opt-in), remove os hooks de IDE criados pelo Nemesis e a pasta `.nemesis/`, e imprime um **checklist final** para você confirmar que não sobrou nada.

**Self-contained** (funciona em qualquer instalação — baixa o script e roda, espelhando o install):

## Desinstalar com confirmação interativa:
```bash
curl -fsSLO https://raw.githubusercontent.com/feryamaha/Nemesis_Defender_v0/main/.nemesis/install/nemesis-uninstall.sh \
  && bash nemesis-uninstall.sh
```

## Desinstalar sem confirmação interativa:
```bash
curl -fsSLO https://raw.githubusercontent.com/feryamaha/Nemesis_Defender_v0/main/.nemesis/install/nemesis-uninstall.sh \
  && NEMESIS_YES=1 bash nemesis-uninstall.sh
```

O instalador também deixa uma cópia local; se ela existir, basta :
```bash
bash .nemesis/install/nemesis-uninstall.sh.
```

**O que é automático e o que é manual.** O script remove com segurança os arquivos de hook que são **só do Nemesis** (`.codex`/`.cursor`/`.devin`/`.gemini`/`.agents/hooks.json` e `.github/hooks/`). Os settings **compartilhados** (`.claude/settings.json`, `.openclaude/settings.json`, `.vscode/settings.json`) podem conter **configuração sua**, então ele **não os apaga** — apenas os **lista** para você tirar a entrada do Nemesis à mão (preservando o resto). É importante limpar isso: um hook órfão apontando para um binário que não existe mais faz a IDE/TUI reclamar a cada sessão.

O **checklist final** ainda te dá os comandos para confirmar que nada ficou rodando ou órfão:

## procurar QUALQUER resquício de hook do Nemesis (ideal: nada):

```bash
grep -rIl 'nemesis-pretool\|nemesis-posttool\|\.nemesis/bin\|chat.hookFilesLocations' \
  .claude .openclaude .codex .cursor .devin .gemini .agents .github .vscode 2>/dev/null
```
## para confirmar que o daemon parou (vazio = ok) e, se preciso, finalizar:
```bash
pgrep -fl nemesis-defender
```
## para desativar o PID do nemesis-defender
```bash
pkill -f nemesis-defender
```

## (Linux, só se ativou o eBPF opt-in) confirmar/parar o serviço de kernel:
```bash
systemctl is-active nemesis-ebpf
```

## para desativar o ebpf
```bash
sudo systemctl disable --now nemesis-ebpf
```

Reinicie a IDE depois para ela parar de carregar os hooks e apague manualmente qualquer resíduo restante.

> 💬 **Um pedido.** Se você desinstalar, me mande um email contando o **motivo** — feedback positivo ou negativo é muito valioso para o projeto. E se algo der errado na desinstalação, escreva também: **feryamaha@hotmail.com** (eu dou suporte).

---

## Nemesis Doctor

O **Nemesis Doctor** é o diagnóstico automatizado de saúde do framework. Ele executa 7 verificações estruturadas e emite um veredito global (`SAUDAVEL`, `ATENCAO` ou `CRITICO`).

### Como executar

```bash
cd .nemesis && cargo build --release -p nemesis-doctor
./target/release/nemesis-doctor
```

Modo rápido (pula compilação, testes e pentest):
```bash
./target/release/nemesis-doctor --quick
```

### O que ele verifica

| Grupo | O que verifica |
|-------|----------------|
| **G1** | Compilação (`cargo check --workspace`) — 0 erros, 0 warnings |
| **G2** | Testes unitários (`cargo test --workspace`) — pass/fail |
| **G3** | Inventário de binários em `target/release/` (11 esperados) |
| **G4** | Scaffold da IDE — hooks pretool/posttool configurados |
| **G5** | eBPF Kernel LSM (Linux) — BPF LSM ativo, capabilities, cgroup |
| **G6** | Daemon `nemesis-defender` — PID vivo, inotify ativo |
| **G7** | Pentest Red-Team — taxa de bloqueio contra 184 casos de ataque |

### Vereditos

- **SAUDAVEL** — todos os grupos OK. Sistema pronto.
- **ATENCAO** — um ou mais grupos com WARN (ex.: capabilities ausentes). Funciona, mas merece atenção.
- **CRITICO** — erro bloqueante (compilação falhou, daemon morto, ou pentest **REPROVADO**: algum ataque passou ou houve falso-positivo). Corrija antes de confiar na proteção.

> **Regra:** após qualquer recompilação que afete o `nemesis-ebpf-daemon`, **reaplique as capabilities** (`setcap`) — elas se perdem quando o inode do binário é recriado.

---

## Configuração do Pretool por IDE

A biblioteca Rust (`nemesis-defender`) é agnóstica de IDE. O que muda entre IDEs é **onde** você declara o hook e **qual o formato** do payload. Sempre confirme na doc oficial da sua IDE.

### Suporte por IDE (verificado na documentação oficial)

| IDE / Agente | Hook de pre-tool | Onde declarar |
|--------------|------------------|---------------|
| **Claude Code** | `PreToolUse` / `PostToolUse` | `.claude/settings.json` (projeto) ou `~/.claude/settings.json` (global) |
| **OpenAI Codex** | `PreToolUse` / `PostToolUse` | `.codex/hooks.json` |
| **Cursor** (1.7+) | `preToolUse`, `postToolUse` | `.cursor/hooks.json` |
| **GitHub Copilot** | `preToolUse` | `.github/hooks/` |
| **VS Code** (agent, preview) | eventos de hook | `.github/hooks/` |
| **Devin / Devin** (Cognition) | `pre_write_code`, `pre_run_command`, `pre_read_code`, `pre_mcp_tool_use` (+ `post_*`) | `.devin/hooks.json` |

> **Regra de ouro do enforcement:** o bloqueio só acontece com **exit code 2**. Exit code 1 é tratado como erro não-bloqueante e a ação prossegue. Todo hook de segurança precisa terminar em exit 2 para barrar de fato.

### Claude Code

Edite `.claude/settings.json` (no projeto) ou `~/.claude/settings.json` (global). O hook de pre-tool aponta para o binário do Nemesis com caminho absoluto:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Write|Edit|MultiEdit|Bash|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "/caminho/absoluto/.nemesis/target/release/nemesis-pretool-check-unix"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Read|Write|Edit|MultiEdit|Bash|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "/caminho/absoluto/.nemesis/target/release/nemesis-posttool-check-unix"
          }
        ]
      }
    ]
  }
}
```

O hook recebe o contexto da ferramenta via **stdin como JSON** (campos como `tool_name`, `tool_input.command`, `tool_input.file_path`). O binário real do hook é `nemesis-pretool-check-unix` (e `nemesis-posttool-check-unix` para o pós). Ele lê esse JSON, valida contra as deny-lists, e retorna exit 2 para bloquear.

> Use **caminhos absolutos** para os binários - caminhos relativos falham dependendo do diretório de trabalho da IDE. Hooks de projeto (`.claude/settings.json`) têm precedência sobre os globais.

### Cursor (1.7+)

Configuração real em `.cursor/hooks.json`. O Cursor usa `preToolUse`/`postToolUse` com um `matcher` amplo e a flag `failClosed`:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "matcher": "Shell|Read|Write|StrReplace|Glob|Grep|Delete|EditNotebook|Task|SemanticSearch|WebFetch|TabRead|TabWrite",
        "command": "/caminho/absoluto/.nemesis/target/release/nemesis-pretool-check-unix",
        "failClosed": false
      }
    ],
    "postToolUse": [
      {
        "matcher": "Shell|Read|Write|StrReplace|Glob|Grep|Delete|EditNotebook|Task|SemanticSearch|WebFetch",
        "command": "/caminho/absoluto/.nemesis/target/release/nemesis-posttool-check-unix",
        "failClosed": false
      }
    ]
  }
}
```

### GitHub Copilot / VS Code (agent)

Configuração real em `.github/hooks/nemesis-pretool-hook.json` (caminho relativo ao projeto):

```json
{
  "hooks": {
    "PreToolUse": [
      { "type": "command", "command": "./.nemesis/target/release/nemesis-pretool-check-unix" }
    ],
    "PostToolUse": [
      { "type": "command", "command": "./.nemesis/target/release/nemesis-posttool-check-unix" }
    ]
  }
}
```

**Atenção** (alerta da própria doc do VS Code): se o agente tem permissão para editar o script do hook, ele pode reescrevê-lo durante a execução. Mantenha os scripts de hook sob `absolute_block` (ver [Controle de paths](#controle-de-paths)).

### OpenAI Codex

Configuração real em `.codex/hooks.json`, com `matcher` curinga e `timeout`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          { "type": "command", "command": "/caminho/absoluto/.nemesis/target/release/nemesis-pretool-check-unix", "timeout": 30 }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          { "type": "command", "command": "/caminho/absoluto/.nemesis/target/release/nemesis-posttool-check-unix", "timeout": 30 }
        ]
      }
    ]
  }
}
```

> **Atenção:** confirme que o caminho no `command` aponta para o diretório real do seu projeto. Um caminho errado faz o hook não rodar e o Codex fica desprotegido.

### Devin / Devin (Cognition)

Onde o Nemesis nasceu nativamente. Configuração real em `.devin/hooks.json`, que usa eventos próprios (`pre_write_code`, `pre_run_command`, `pre_read_code`, `pre_mcp_tool_use`, e os `post_*` equivalentes):

```json
{
  "hooks": {
    "pre_write_code": [
      { "command": "/caminho/absoluto/.nemesis/target/release/nemesis-pretool-check-unix", "show_output": true }
    ],
    "pre_run_command": [
      { "command": "/caminho/absoluto/.nemesis/target/release/nemesis-pretool-check-unix", "show_output": true }
    ],
    "pre_read_code": [
      { "command": "/caminho/absoluto/.nemesis/target/release/nemesis-pretool-check-unix", "show_output": true }
    ],
    "pre_mcp_tool_use": [
      { "command": "/caminho/absoluto/.nemesis/target/release/nemesis-pretool-check-unix", "show_output": true }
    ],
    "post_write_code": [
      { "command": "/caminho/absoluto/.nemesis/target/release/nemesis-posttool-check-unix", "show_output": true }
    ]
  }
}
```

Os eventos `post_run_command`, `post_read_code` e `post_mcp_tool_use` seguem o mesmo padrão do `post_write_code`.

---

## Configuração da camada eBPF (Linux)

Esta camada é **opcional** e específica de Linux. Ela é a rede de contenção mínima para comandos destrutivos caso o pretool seja desligado. Se você não usa Linux ou não precisa dessa camada extra, pule esta seção - o Nemesis funciona sem ela via pretool.

**Instruções completas de instalação e operação:** consulte [`.nemesis/ebpf-kernel/info.md`](.nemesis/ebpf-kernel/info.md)

### Pré-requisitos

- Linux kernel ≥ 5.7
- BPF LSM ativo no boot (`cat /sys/kernel/security/lsm` deve conter `bpf`)
- clang e bpftool instalados
- Capacidade de delegar capabilities (`cap_bpf`, `cap_perfmon`, `cap_sys_resource`)

### Compilação

```bash
cargo build -p nemesis-ebpf-kernel
```

**Nota sobre bloqueio de build:** Se o BPF LSM estiver ativo e bloqueando o build (erro "Operation not permitted" no `rm` do make), pare o daemon eBPF antes de compilar:

```bash
# Verificar se o daemon está rodando
ps aux | grep nemesis-ebpf-daemon

# Parar o daemon
sudo systemctl stop nemesis-ebpf  # se estiver como serviço
# ou mate o processo manualmente
kill <PID_DO_DAEMON>

# Tentar compilar novamente
cargo build -p nemesis-ebpf-kernel
```

Se mesmo após parar o daemon o build falhar, o programa BPF LSM pode estar carregado no kernel. Nesse caso, reinicie o sistema para descarregá-lo, pois programas BPF não podem ser removidos dinamicamente.

### Delegar capabilities

```bash
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+eip \
  .nemesis/target/release/nemesis-ebpf-daemon
```

### Iniciar o daemon

```bash
.nemesis/target/release/nemesis-ebpf-daemon --start
```

O daemon cria/usa o cgroup `/sys/fs/cgroup/nemesis-agent`, carrega o programa BPF LSM e fica em modo epoll (consumo próximo de zero em idle). Apenas processos do agente movidos para esse cgroup são verificados - IDE, terminal e processos do sistema passam sem verificação.

### Modo sandbox sem root (Landlock)

Se você não pode delegar capabilities, o daemon opera em modo degradado via Landlock, que protege apenas a árvore de processos do filho:

```bash
.nemesis/target/release/nemesis-ebpf-daemon --sandbox
```

### O que faz

A camada eBPF opera no nível do kernel via BPF LSM (`bprm_check_security`), bloqueando execuções destrutivas (comandos em `denylist-ebpf/commands.toml`) apenas para processos dentro do cgroup `/sys/fs/cgroup/nemesis-agent`. Processos do IDE, terminal e sistema passam sem verificação.

### Arquivos de configuração

- `denylist-ebpf/commands.toml` - Binários bloqueados por basename
- `denylist-ebpf/paths.toml` - Paths de escrita bloqueados
- `nemesis-ebpf.service` - Serviço systemd para ativação automática
- `install-service.sh` - Script de instalação do serviço

---

## Controle de paths

Após a instalação, o que o agente pode tocar é definido em `denylist-folder-files.json`, sob controle **exclusivamente humano**, em três níveis:

- **`absolute_block`** - bloqueio total (leitura + escrita + deleção). Inclui `.env`, `.ssh/id_rsa`, `.bashrc`/`.zshrc`, os settings/hooks de cada IDE (`.claude/`, `.cursor/`, `.devin/`) e o próprio `.nemesis/`.
- **`write_block`** - leitura permitida, escrita/edição bloqueada. Inclui `package.json`, `next.config.js`, `eslint.config.mjs`, `.gitignore` e os logs.
- **`allowed_exceptions`** - o scaffold liberado (ex.: `/src/`), onde o agente escreve e edita livremente.

**Estes arquivos passam a ser responsabilidade de edição manual humana.** O agente de IA não os edita nem exclui. Comando destrutivo (deletar, sobrescrever fora do escopo, reset) permanece **sempre proibido para a IA**, independentemente de qualquer permissão de leitura/escrita.

---

## Uso no dia a dia

Com os hooks configurados, o Nemesis opera de forma transparente: ele só se manifesta quando bloqueia algo. Comandos e escritas legítimas passam sem fricção.

```bash
# Escanear um arquivo manualmente
nemesis-defender --scan /caminho/arquivo.rs

# Iniciar / parar o daemon de filesystem
nemesis-defender --ensure-daemon
nemesis-defender --stop

# Ver bloqueios recentes (ledger único de TODAS as camadas, JSONL)
tail -20 .nemesis/logs/nemesis-violations.log | jq .

# Telemetria local: total + por camada + por tipo + por dia
nemesis-defender --log-stats
```

> **Registro 100% local.** Todo log e telemetria do Nemesis fica em `.nemesis/` dentro do seu próprio projeto. **Nada é enviado, exfiltrado ou telemetrado para fora** da sua máquina — não há servidor, coleta remota nem "phone home". Os bloqueios das camadas (pretool, posttool, nemesis-defender, eBPF) vão todos para um **ledger único** `.nemesis/logs/nemesis-violations.log`; o histórico antigo fica arquivado em `.nemesis/logs/log-legado/`. O estado de correlação comportamental (que o daemon usa para detecção multi-turn) fica em `.nemesis/runtime/session-events.jsonl` — também local.

### Mensagens de bloqueio

Quando algo é barrado, o Nemesis emite uma de seis mensagens categorizadas, para que você (e o agente) saiba exatamente por quê:

| Categoria | Mensagem |
|-----------|----------|
| Comando bloqueado | `NEMESIS SEC - COMANDO NAO PERMITIDO` |
| Escrita em arquivo protegido | `NEMESIS SEC - ACESSO NEGADO - ARQUIVO PROTEGIDO` |
| Leitura de arquivo protegido | `NEMESIS SEC - LEITURA NEGADA - ARQUIVO PROTEGIDO` |
| Conteúdo malicioso | `NEMESIS SEC - CONTEUDO MALICIOSO DETECTADO` |
| Escrita fora do escopo | `NEMESIS SEC - ESCRITA FORA DO ESCOPO PERMITIDO` |
| Violação de padrão de código | `NEMESIS QUALITY - PADRAO DE CODIGO NAO PERMITIDO ANALISAR REGRAS!` |

No terminal sob eBPF, o kernel emite a mensagem padrão do sistema (`Operação não permitida`) com exit code 126 - o registro padronizado fica no ledger `.nemesis/logs/nemesis-violations.log` (camada `ebpf-kernel`).

---

## Verificação e diagnóstico

```bash
# Escanear o conteúdo de um arquivo manualmente (mesma engine do daemon/hook)
.nemesis/target/release/nemesis-defender --scan /caminho/arquivo.js

# Diagnóstico da camada eBPF (Linux)
.nemesis/target/release/nemesis-ebpf-daemon --doctor
.nemesis/target/release/nemesis-ebpf-daemon --print-status

# Bloqueios da camada de kernel (eBPF) no ledger único
grep '"layer":"ebpf-kernel"' .nemesis/logs/nemesis-violations.log
```

**Nota:** O binário `nemesis-ebpf-daemon` precisa ser compilado com `cargo build -p nemesis-ebpf-kernel`. Se o BPF LSM estiver ativo e bloqueando o build, pare o daemon eBPF antes de compilar.

Para confirmar que o pretool está realmente ativo, force um comando que deve ser bloqueado em um arquivo de teste descartável e verifique se aparece no log. Se nada acontecer, o hook provavelmente não está apontando para o caminho certo.

---

## Relaxar ou customizar regras

### O Nemesis foi calibrado para frontend

O detector foi calibrado contra a realidade **frontend** (Next.js / React / TypeScript), onde o falso-positivo (FP) fica **abaixo de ~1%**. Frontend praticamente não gera código "scriptado" (sudo, `sed -i`, exec dinâmico, manipulação de PATH); para essa stack, esses comandos são hostis e desnecessários, então bloqueá-los é correto.

Stacks de **backend / DevSecOps** (e múltiplas linguagens) têm um coeficiente de FP **mais alto** — elas legitimamente usam comandos que para frontend seriam hostis. Isso é uma **limitação conhecida** do Nemesis e a razão de existir a allowlist (abaixo). Estimativa **por setor** (a partir de medição empírica em codebases open-source reais, com margem conservadora):

| Setor | Stack típica | FP estimado |
|---|---|---|
| **Frontend** | Next.js / React / TypeScript | **< 1%** |
| **Backend** | Python / Node / múltiplas linguagens | **~3–6%** |
| **DevSecOps / IaC / Shell** | Ansible, installers, scripts, exec remoto | **a partir de ~7%** |

São estimativas com margem de erro; o FP cresce quanto mais "scriptado" é o stack. Ferramentas intrinsecamente ofensivas (ex.: bibliotecas de exploit/shellcode) acendem por **design** — é o teto esperado, não fogo amigo, e confirma que a detecção real está viva.

> **Leitura:** FP baixo em frontend (e em Rust real); cresce em backend/devops/shell por usarem comandos intrínsecos à stack. Não é o detector "quebrando" — é a calibração frontend encontrando código legítimo de outra natureza. Esses ambientes devem **relaxar via allowlist**.

### A allowlist (única superfície editável)

As deny-lists de **bloqueio** são **embutidas no binário** (tamper-proof) — não há arquivo no disco para editar, e isso é intencional: um agente não consegue enfraquecer o Nemesis editando regras. A **única** superfície que você edita após instalar é:

```
.nemesis/denylist-customers/allowlist-customers.jsonc
```

É um **override humano absoluto**: tudo que você listar passa, sobrescrevendo **qualquer** bloqueio (denylist de comando, defender, visitors) — no pretool e no daemon. Efeito imediato ao salvar (sem rebuild). É assim que backend/DevSecOps **relaxam** o Nemesis para a realidade da própria stack:

```jsonc
{
  // allow_commands: casa por SUBSTRING; allow_patterns: casa por REGEX (sem lookahead)
  "allow_commands": ["sudo systemctl restart nginx", "rm -rf ./dist"],
  "allow_patterns": ["^cp\\s+-r\\s+"]
}
```

> **Aviso de responsabilidade.** A allowlist é absoluta: se você liberar `rm -rf`, o Nemesis deixa de bloquear `rm -rf`. Você **devolve ao modelo o poder de decidir** sobre o que liberou — por sua conta e risco. O arquivo é editável **só por humano** (o agente nunca escreve nele — `absolute_block`); essa é a garantia que faz o override não ser auto-sabotagem. Edite no seu terminal nativo.

### Duas camadas, duas allowlists (importante para Linux)

A `allowlist-customers.jsonc` relaxa o **pretool + o defender/daemon** — onde vivem os falsos-positivos de comando/conteúdo do agente. Vale em Linux e macOS (plataformas validadas); no Windows, best-effort (ver [Suporte por plataforma](#suporte-por-plataforma)).

A camada **eBPF** (kernel, Linux, opt-in) tem uma denylist **própria e separada** (`denylist-ebpf/commands.toml`) que a allowlist acima **não** controla. Em Linux, comandos como `rm`/`chmod` só **executam de fato** se você também os listar na allowlist do eBPF — assim você relaxa o kernel **sem editar a lista oficial**:

```
.nemesis/denylist-customers/allowlist-ebpf.toml
```
```toml
# nome EXATO do comando (basename do exec); por sua conta e risco
allowed_commands = ["rm", "chmod", "tar"]
```

O loader do eBPF **remove** esses comandos do bloqueio ao subir o daemon (recarrega ao reiniciar). Em macOS/Windows não há eBPF: a `allowlist-customers.jsonc` sozinha já libera. Os **visitors do Defender** continuam sendo código Rust (ampliá-los exige Rust).

---


## Solução de problemas

| Sintoma | Causa provável | Ação |
|---------|----------------|------|
| O Nemesis não bloqueia nada | Hook não aponta para o caminho absoluto certo | Revise o `settings.json`/`hooks.json` da IDE |
| `enforcement_level` é `landlock` | BPF LSM não ativo ou sem capabilities | Refaça os passos 1-2 da [config eBPF](#configuração-da-camada-ebpf-linux) |
| eBPF não bloqueia comando destrutivo | Processo do agente não está no cgroup | Mova o PID para `/sys/fs/cgroup/nemesis-agent/cgroup.procs` |
| Build falha por falta de memória | Menos de ~4 GB de RAM livres | Libere memória ou compile com menos paralelismo |

---

## Módulos pausados

O Nemesis possui funcionalidades presentes no código mas atualmente inativas:

**ast-linters** (`ast-linters/`). Camada de qualidade de código com visitors tree-sitter focados na stack frontend Next/React/TypeScript. Detecta anti-padrões como `any` explícito, hooks condicionais, CSS inline, promises não tratadas e segredos hardcoded. O módulo está **silenciado** — presente no código mas sem enforcement ativo.

---

## Estrutura do projeto

Layout base do repositório (pastas e arquivos-chave; `bin/`, `target/`, `runtime/` são gerados e **não** versionados):

```text
Nemesis_Defender_v0/
├─ README.md  AGENTS.md  CLAUDE.md            # docs canônicos (AGENTS = agente mantenedor)
├─ index.html                                 # landing page / documentação
├─ SECURITY.md  CONTRIBUTING.md  CODE_OF_CONDUCT.md  NOTICE  LICENSE
├─ .gitignore  config.yml  PULL_REQUEST_TEMPLATE.md
│
├─ .github/                                   # governança + CI/CD
│  ├─ workflows/release.yml                   # build + attestation (SLSA) + release (draft)
│  ├─ workflows/self-audit.yml               # gate: pentest + cargo audit + pin-check
│  ├─ CODEOWNERS                              # revisão obrigatória nos paths trust-critical
│  └─ ISSUE_TEMPLATE/  hooks/  settings.json
│
├─ .nemesis/                                  # núcleo: workspace Rust + runtime
│  ├─ Cargo.toml  Cargo.lock                  # workspace (lockfile COMMITADO)
│  ├─ nemesis-defender/                       # scanner "Iron Dome" (lib + daemon)
│  │  ├─ src/                                 # visitors + 6 layers de scan + severidade
│  │  ├─ config/denylist-defender.json        # segurança de conteúdo (EMBUTIDA no binário)
│  │  └─ tests/
│  ├─ nemesis-doctor/                         # diagnóstico G1–G7 + NEMESIS-OPERATIONS.md
│  ├─ ebpf-kernel/                            # camada de kernel (Linux, opt-in)
│  │  ├─ src/                                 # loader, config, landlock (sandbox sem root)
│  │  ├─ ebpf/  include/  denylist-ebpf/      # programa BPF + allowlists (egress/landlock)
│  │  └─ Makefile
│  ├─ ast-linters/                            # qualidade de código (pausado)
│  ├─ hooks/                                  # pretool/posttool (.rs) + fallback fail-closed
│  ├─ denylist/                               # deny-lists EDITÁVEIS (comando/qualidade/pastas)
│  ├─ install/                                # nemesis-install.sh + info-install.txt (curl)
│  ├─ pentest-nemesis-control/                # suíte red-team (run-pentest.sh + cenários)
│  ├─ forensics/                              # auditoria de conteúdo externo (scan-incoming.sh)
│  ├─ scripts/  lsp/                          # build/caps + LSP
│  ├─ bin/ · target/                          # binários (distro · build da fonte) — gerados
│  └─ runtime/ · quarantine/                  # PID/lock do daemon · arquivos quarentenados
│
└─ .claude/ .devin/ .cursor/ .codex/ .gemini/ .agents/ .openclaude/   # scaffolds de hook por IDE
```

---

## Contribuição

Contribuições são bem-vindas - código, novos vetores de deny-list, e especialmente **relatos de bypass**. Veja [`CONTRIBUTING.md`](CONTRIBUTING.md).

Para **manter o Nemesis** (em qualquer IDE/TUI), o ponto de partida é o [`AGENTS.md`](AGENTS.md) - o agente mantenedor canônico (invariantes de segurança, disciplina epistêmica, mapa do repositório, boas práticas de Rust) - e o manual de operação [`.nemesis/nemesis-doctor/NEMESIS-OPERATIONS.md`](.nemesis/nemesis-doctor/NEMESIS-OPERATIONS.md) (build, lifecycle de daemon/pretool/eBPF, logs, checklist).

O projeto adota o **Developer Certificate of Origin (DCO)**: assine seus commits com `git commit -s`.

A camada eBPF, em particular, é um campo aberto: ela hoje cobre execução de binários destrutivos (execve). Estender para escrita não-execve (hooks `file_open`/`inode_unlink`), matching por inode em vez de basename, e seccomp no modo `--start` são melhorias mapeadas e disponíveis para quem quiser contribuir.

---

## Segurança e disclosure

Bypasses e vetores não cobertos são **esperados** e **bem-vindos**. Se você contornar qualquer camada, **não abra uma issue pública** - siga o [`SECURITY.md`](SECURITY.md) e reporte em privado para `feryamaha@hotmail.com`. Pesquisadores são creditados publicamente (salvo se preferirem anonimato).

---

## Licença

Distribuído sob a **GNU AGPL v3.0** (veja [`LICENSE`](LICENSE)). Você pode usar, estudar, modificar e redistribuir livremente - mas qualquer derivado ou serviço (inclusive SaaS) deve manter o código aberto sob a mesma licença.

O copyright integral permanece com o autor, que oferece **licença comercial separada** (licenciamento dual) para uso sem as obrigações da AGPL. Contato: **feryamaha@hotmail.com**.

---

**Autor / mantenedor:** [@feryamaha](https://github.com/feryamaha)

**Redes:** [GitHub](https://github.com/feryamaha) · [LinkedIn](https://www.linkedin.com/in/feryamaha) · [X (Twitter)](https://x.com/_feryamaha) · [Email](mailto:feryamaha@hotmail.com)