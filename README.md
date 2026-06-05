# Nemesis Defender

> Enforcement determinístico contra comandos destrutivos e malware de supply-chain em fluxos de desenvolvimento assistido por agentes LLM. Escrito em Rust.

[![Licença: AGPL-3.0](https://img.shields.io/badge/Licen%C3%A7a-AGPL--3.0-blue.svg)](LICENSE)
[![Versão](https://img.shields.io/badge/vers%C3%A3o-2.0-00B4D8.svg)](#)
[![Plataforma](https://img.shields.io/badge/plataforma-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-success.svg)](#requisitos)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange.svg)](#requisitos)

Documentação conceitual completa (o que é, por que existe, modelo de ameaça): **[feryamaha.github.io/Nemesis_Defender_v2.0](https://feryamaha.github.io/Nemesis_Defender_v2.0/)**

Este README é o documento **técnico e operacional**: como instalar, configurar e usar. Para entender a filosofia e a arquitetura em profundidade, leia o site acima.

---

## ⚠️ Leia antes de instalar

O Nemesis **age, não pergunta**. Quando instalado em um projeto que já contém violações (credenciais expostas, comandos destrutivos embutidos, anti-padrões graves), a camada de scanner pode **remover os arquivos infratores na primeira varredura** - em um caso real, removeu 24 arquivos de um projeto que não havia nascido sob o Nemesis.

- **Faça backup do projeto antes de instalar.** Sempre.
- Se o projeto está versionado (Git), os arquivos removidos permanecem recuperáveis no controle de versão.
- Se **não** está versionado, a perda é definitiva.

**Responsabilidade após a instalação:** a partir do momento em que o Nemesis está ativo, vários arquivos passam a ser de **edição manual exclusivamente humana** (ver [Controle de paths](#controle-de-paths)). O agente de IA não pode editá-los nem excluí-los. Você pode relaxar a severidade do Nemesis editando as deny-lists, mas ao fazer isso **devolve ao modelo o poder de decidir o que excluir** - e esse risco passa a ser inteiramente seu. O autor não se responsabiliza por perdas decorrentes de configuração relaxada.

---

## Índice

- [O que o Nemesis faz](#o-que-o-nemesis-faz)
- [Arquitetura em camadas](#arquitetura-em-camadas)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Configuração do Pretool por IDE](#configuração-do-pretool-por-ide)
- [Configuração da camada eBPF (Linux)](#configuração-da-camada-ebpf-linux)
- [Controle de paths](#controle-de-paths)
- [Uso no dia a dia](#uso-no-dia-a-dia)
- [Verificação e diagnóstico](#verificação-e-diagnóstico)
- [Relaxar ou customizar regras](#relaxar-ou-customizar-regras)
- [Solução de problemas](#solução-de-problemas)
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
| **Pretool / Posttool Hook** | Antes do `Bash.run()` / file-write | Deny-list JSON + exit code 2 | Windows, macOS, Linux |
| **Nemesis Defender** (scanner) | Em file-write e em comandos | 6 layers: AST, byte, regex, denylist, entropia, decoder | Windows, macOS, Linux |
| **ast-linters** (qualidade) | Em file-write de código | Visitors tree-sitter + `rules.toml` | Windows, macOS, Linux |
| **eBPF Kernel LSM** | Syscalls no kernel | BPF LSM (`bprm_check_security`), retorna `-EPERM` | **Linux apenas** |

**Tudo parte do Pretool.** Sem o pretool configurado, o Nemesis não roda - as trilhas de segurança (Defender) e de qualidade (ast-linters) são acionadas por ele. A camada **eBPF** é a única independente: opera no kernel como rede de contenção adicional, segurando comandos destrutivos caso o pretool seja desligado ou contornado. Em macOS e Windows, sem eBPF, a defesa se concentra nas trilhas do pretool.

> A camada eBPF é uma **contenção mínima de comandos destrutivos**, não a defesa principal. Ela existe para o cenário em que o pretool é desativado. Sua expansão (cobrir escrita não-execve, rename/symlink) é um ponto aberto para a comunidade.

---

## Requisitos

### Todas as plataformas

- **Rust 1.70+** e Cargo (toolchain estável) - para compilar os binários.
- **Clang/LLVM** - para compilar o core.
- **~4 GB de RAM livres** para o build e **~2 GB de disco** para toolchain + binários.
- Uma **IDE/agente que exponha hooks de pre-tool** (ver [tabela de suporte](#configuração-do-pretool-por-ide)). Sem isso, o Nemesis não tem ponto de acoplamento.
- **Node.js** (opcional) - apenas para o harvest legado em projetos JS/TS.

### Adicional para a camada eBPF (somente Linux)

- **Kernel Linux 5.8+** com **BPF LSM habilitado**. Em muitas distros o BPF LSM não vem ligado por padrão.
- **cgroup v2** (unified ou hybrid).
- **clang** e **bpftool** instalados.
- Capacidade de delegar capabilities (`cap_bpf`, `cap_perfmon`, `cap_sys_resource`) ao daemon.

> **Antes de assumir que sua IDE tem suporte:** consulte a documentação oficial da sua IDE/agente para confirmar se ela expõe hooks de pre-tool (ou equivalente) e qual o formato. A seção [Configuração do Pretool por IDE](#configuração-do-pretool-por-ide) cobre as principais, mas IDEs evoluem - a doc oficial é a fonte de verdade.

---

## Instalação

O Nemesis **não é plug-and-play**. A instalação confiável hoje é manual: compilar os binários e apontar os hooks da IDE para eles.

### 1. Clonar e compilar

```bash
git clone https://github.com/feryamaha/Nemesis_Defender_v2.0.git
cd Nemesis_Defender_v2.0/.nemesis
cargo build --release --workspace
# Binários gerados em .nemesis/target/release/
```

A compilação leva alguns minutos e exige os ~4 GB de RAM mencionados nos requisitos. Ao final, confirme que os binários existem:

```bash
ls -la .nemesis/target/release/ | grep nemesis
```

### 2. Apontar os hooks da IDE para o binário

Este é o passo que efetivamente liga o Nemesis. Cada IDE tem seu formato - ver a próxima seção. O ponto comum: o hook de pre-tool precisa apontar para o **caminho absoluto** do binário do Nemesis no seu projeto.

> **Caminho errado ou ausente = o Nemesis não roda.** A IDE simplesmente não invoca o hook, e você fica desprotegido sem perceber. Sempre confirme que o caminho no `command` aponta para o binário real (`nemesis-pretool-check-unix`) no seu projeto.

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
| **Windsurf / Devin** (Cognition) | `pre_write_code`, `pre_run_command`, `pre_read_code`, `pre_mcp_tool_use` (+ `post_*`) | `.devin/hooks.json` |

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

### Windsurf / Devin (Cognition)

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

- **`absolute_block`** - bloqueio total (leitura + escrita + deleção). Inclui `.env`, `.ssh/id_rsa`, `.bashrc`/`.zshrc`, os settings/hooks de cada IDE (`.claude/`, `.cursor/`, `.windsurf/`) e o próprio `.nemesis/`.
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

# Ver violações recentes
tail -20 .nemesis/logs/violations.log | jq .
```

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

No terminal sob eBPF, o kernel emite a mensagem padrão do sistema (`Operação não permitida`) com exit code 126 - o registro detalhado fica no `violations.log`.

---

## Verificação e diagnóstico

```bash
# Validar um workflow / definir escopo (nemesis-scope usa subcomandos)
nemesis-validate /caminho/workflow
nemesis-scope set /caminho/arquivo.rs   # subcomandos: set | add | add-pattern | show | clear

# Diagnóstico da camada eBPF (Linux)
.nemesis/target/release/nemesis-ebpf-daemon --doctor
.nemesis/target/release/nemesis-ebpf-daemon --print-status

# Logs de violação do kernel (eBPF)
grep '"layer":"ebpf"' .nemesis/logs/violations.log
```

**Nota:** O binário `nemesis-ebpf-daemon` precisa ser compilado com `cargo build -p nemesis-ebpf-kernel`. Se o BPF LSM estiver ativo e bloqueando o build, pare o daemon eBPF antes de compilar.

Para confirmar que o pretool está realmente ativo, force um comando que deve ser bloqueado em um arquivo de teste descartável e verifique se aparece no log. Se nada acontecer, o hook provavelmente não está apontando para o caminho certo.

---

## Relaxar ou customizar regras

Todas as regras são configuráveis por **edição humana** das deny-lists - não há regra hardcoded. Ampliar a cobertura é adicionar uma entrada; relaxar é remover ou comentar.

> **Aviso de responsabilidade.** Relaxar a severidade do Nemesis é legítimo para manutenção, mas tem um custo: ao remover restrições, você **devolve ao modelo o poder de decidir o que excluir ou sobrescrever**. Esse é exatamente o risco que o Nemesis existe para eliminar. Se você relaxa as regras e um agente destrói algo, a responsabilidade é sua. O autor não se responsabiliza por perdas decorrentes de configuração relaxada.

Duas exceções exigem conhecimento mais profundo: a camada **eBPF** tem sua lista de comandos atrelada à arquitetura (no `commands.toml` do módulo), e os **visitors do Defender** são código Rust de análise. As deny-lists JSON, por outro lado, são simples de ajustar.

---

## Solução de problemas

| Sintoma | Causa provável | Ação |
|---------|----------------|------|
| O Nemesis não bloqueia nada | Hook não aponta para o caminho absoluto certo | Revise o `settings.json`/`hooks.json` da IDE |
| `enforcement_level` é `landlock` | BPF LSM não ativo ou sem capabilities | Refaça os passos 1-2 da [config eBPF](#configuração-da-camada-ebpf-linux) |
| eBPF não bloqueia comando destrutivo | Processo do agente não está no cgroup | Mova o PID para `/sys/fs/cgroup/nemesis-agent/cgroup.procs` |
| Build falha por falta de memória | Menos de ~4 GB de RAM livres | Libere memória ou compile com menos paralelismo |

---

## Contribuição

Contribuições são bem-vindas - código, novos vetores de deny-list, e especialmente **relatos de bypass**. Veja [`CONTRIBUTING.md`](CONTRIBUTING.md).

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