# NEMESIS — Manual de Operação Unificado

> **Documento canônico de operação do Nemesis Framework v2.0.**
> Substitui `doc-cargo-compile-binary.md` e `pentest-nemesis-control/instruction-daemon+ebpf-info.md` (obsoletos).
> Todos os caminhos são relativos à raiz do projeto: `/home/fernando/devproj/Nemesis_Defender_v2.0`.

---

## 0. Diagnóstico automático (recomendado)

Antes de qualquer checagem manual, rode o diagnóstico estruturado:

```bash
# Diagnóstico completo (compilação + testes + inventário + scaffold + eBPF + daemon + pentest)
.nemesis/target/release/nemesis-doctor

# Modo rápido (pula G1 compile, G2 testes e G7 pentest)
.nemesis/target/release/nemesis-doctor --quick
```

O `nemesis-doctor` retorna um relatório com 7 grupos e um veredito global
(`SAUDAVEL` / `ATENCAO` / `CRITICO`) e exit code (0 = ok/warn, 1 = crítico).

| Grupo | O que verifica |
|-------|----------------|
| G1 | Compilação (`cargo check --workspace`) |
| G2 | Testes unitários (`cargo test --workspace`) |
| G3 | Inventário de binários em `target/release` |
| G4 | Scaffold da IDE (`hooks.json`/`settings.json` pretool/posttool) |
| G5 | eBPF Kernel LSM (somente Linux) |
| G6 | Daemon `nemesis-defender` (PID + inotify) |
| G7 | Pentest Red-Team (`run-pentest.sh` + parse CSV) |

As seções abaixo são o **checklist manual** para inspeção pontual.

---

## 1. Estrutura do Workspace

Workspace Cargo `nemesis` (v8.2.0) com membros:

```
.nemesis/
├── Cargo.toml          # workspace + pacote raiz (hooks/CLI)
├── ast-linters/        # análise semântica AST (lib, sem binário)
├── ebpf-kernel/        # enforcement eBPF (Linux)
├── nemesis-defender/   # Iron Dome scanner + daemon
└── nemesis-doctor/     # diagnóstico de saúde
```

### Binários esperados (11) em `.nemesis/target/release/`

| Origem | Binários |
|--------|----------|
| pacote `nemesis` | `nemesis-pretool-check`, `nemesis-pretool-check-unix`, `nemesis-pretool-check-windows`, `nemesis-pretool-hook`, `nemesis-posttool-check-unix`, `pre-edit-hook`, `debug-hook-env`, `nemesis-lsp` |
| `nemesis-defender` | `nemesis-defender` |
| `ebpf-kernel` | `nemesis-ebpf-daemon`, `nemesis-cgroup-watcher` |
| `ast-linters` | (lib — sem binário) |
| `nemesis-doctor` | `nemesis-doctor` |

---

## 2. Compilação

### Workspace completo

```bash
cd .nemesis && cargo build --release --workspace
```

> **Linux + eBPF:** prefira o wrapper, que recompila E reaplica as capabilities do
> eBPF (perdidas a cada build, pois `setcap` é por-inode):
> ```bash
> .nemesis/scripts/nemesis-build.sh           # build --workspace + ensure-ebpf-caps
> ```
> Para só reativar as caps sem recompilar: `.nemesis/scripts/ensure-ebpf-caps.sh`
> (idempotente; sudo apenas quando precisa aplicar; no-op em macOS).

### Por módulo

```bash
cd .nemesis && cargo build --release -p nemesis-defender
cd .nemesis && cargo build --release -p nemesis-doctor
cd .nemesis && cargo build --release -p nemesis-ebpf-kernel
cd .nemesis && cargo build --release -p ast-linters
```

### Verificação rápida (sem gerar binário)

```bash
cd .nemesis && cargo check --workspace
```

**O que analisar na saída:**
- `Finished ... profile` => compilou com sucesso.
- `warning:` => não bloqueia, mas deve ser revisado.
- `error[Exxx]:` => **bloqueia o build** — corrija antes de prosseguir.

> Após recompilar o `nemesis-defender`, **reinicie o daemon** (seção 4). Só recompilar
> não basta enquanto o daemon antigo (binário em memória) seguir vivo.

---

## 3. eBPF Kernel LSM (somente Linux)

Camada adicional e independente do pretool. Ativada **uma única vez** na instalação.

### Verificar

```bash
cat /sys/kernel/security/lsm                 # deve conter 'bpf'
getcap .nemesis/target/release/nemesis-ebpf-daemon
ls /sys/fs/cgroup/nemesis-agent/
sudo bpftool prog list
```

### Diagnóstico / iniciar / parar

```bash
sudo .nemesis/target/release/nemesis-ebpf-daemon --doctor
sudo .nemesis/target/release/nemesis-ebpf-daemon --start
sudo killall nemesis-ebpf-daemon 2>/dev/null; echo "PARADO"
```

### Capabilities (uma vez por máquina)

```bash
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+eip \
        .nemesis/target/release/nemesis-ebpf-daemon
```

## Sobe daemon + watcher, reaplica cap, religa no boot:

```bash
sudo bash .nemesis/ebpf-kernel/install-service.sh
```

##  Comandos uteis:
  systemctl status nemesis-ebpf         # ver estado do daemon eBPF
  systemctl status nemesis-cgroup-watcher # ver estado do watcher
  journalctl -u nemesis-ebpf -f         # ver logs em tempo real
  sudo systemctl stop nemesis-ebpf      # parar
  sudo systemctl restart nemesis-ebpf   # reiniciar

> macOS/Windows: eBPF não se aplica — a defesa fica nas trilhas do pretool. O `nemesis-doctor` reporta `NA`.

---

## 4. Daemon nemesis-defender

Scanner em tempo real (inotify). Deveria subir **automaticamente** quando a IDE
dispara o pretool hook (`nemesis-pretool-check-unix` executa `--ensure-daemon`).
Se o scaffold da IDE (seção 5) não estiver configurado, suba manualmente.

### Verificar

```bash
pidof nemesis-defender && echo "ATIVO" || echo "INATIVO"
ls -la /proc/$(pidof nemesis-defender)/fd/ | grep inotify
```

### Iniciar / parar / reiniciar

```bash
# Iniciar (se não estiver rodando)
.nemesis/target/release/nemesis-defender --ensure-daemon

# Parar
pkill -9 -f "nemesis-defender"; pidof nemesis-defender || echo "PARADO"

# Reiniciar (obrigatório após recompilar o defender)
pkill -9 -f "nemesis-defender"; sleep 1; .nemesis/target/release/nemesis-defender --ensure-daemon
```

### Scan manual

```bash
.nemesis/target/release/nemesis-defender --scan /caminho/arquivo.ts
```

---

## 5. Scaffold da IDE (hooks)

Sem o hook **pretool** configurado, a IDE não dispara `nemesis-defender --ensure-daemon`
e o daemon **não sobe sozinho** (no Linux, só o eBPF protege).

Arquivos verificados pelo `nemesis-doctor` (G4):

```
.devin/hooks.json
.claude/settings.json
.cursor/hooks.json
.codex/hooks.json
.github/hooks.json
```

**O que analisar:**
- Arquivo `{}` ou vazio => daemon não sobe automaticamente.
- Deve referenciar `pretool` (ignição do daemon) e, idealmente, `posttool` (scan pós-escrita).
- O binário referenciado deve existir em `.nemesis/target/release/`.

---

## 6. Pentest Red-Team

Suíte automatizada (184 testes, 26 módulos) que injeta comandos/arquivos maliciosos
no binário pretool via stdin (não-destrutivo) e mede a taxa de bloqueio.

```bash
bash .nemesis/pentest-nemesis-control/nemesis-defender/run-pentest.sh \
    .nemesis/target/release/nemesis-pretool-check-unix
```

Requer `bash` + `node`. Gera `pentest-results.csv` e `pentest-results.md`.

**O que analisar:**
- Taxa `>= 95%` => `PRODUCAO-READY`; `90-94%` => `HARDENING`; `< 90%` => `NAO LANCAR`.
- Módulo **M26** usa lógica invertida: bloquear ali = **falso-positivo** (regressão).

---

## 7. Logs e telemetria — registro 100% local

> **Privacidade:** todo o registro do Nemesis é **local** — gravado apenas dentro de
> `.nemesis/` no próprio projeto. **Nada é exfiltrado, enviado nem telemetrado para fora**
> da máquina de quem instala. Não há servidor, coleta remota ou "phone home". Os dados
> existem só para o próprio dev auditar e validar a proteção.

As camadas (pretool, posttool, nemesis-defender, eBPF) registram cada bloqueio numa linha
padronizada num **ledger único**:

```
.nemesis/logs/nemesis-violations.log     # JSONL — UM evento de bloqueio por linha
```

Schema:
```json
{"ts":"2026-06-11T09:25:34-03:00","date":"2026-06-11","time":"09:25:34","layer":"pretool","message":"NEMESIS SEC - LEITURA NEGADA - ARQUIVO PROTEGIDO · .env"}
```
- `layer` ∈ `pretool` | `posttool` | `nemesis-defender` | `ebpf-kernel`
- `message` = mensagem padrão (vocabulário das 6 mensagens), já com o alvo (`· <alvo>`)

### Telemetria local

```bash
.nemesis/target/release/nemesis-defender --log-stats
```

Imprime total de bloqueios, **por camada** (ordem de prioridade — eBPF, a última camada,
deve ter o MENOR volume), **por tipo** (mais incidente primeiro) e **por dia**. Serve para
validar a proteção, ver os vetores mais frequentes e auditar falso-positivo.

### Arquivos em `.nemesis/`

| Arquivo | Função |
|---|---|
| `.nemesis/logs/nemesis-violations.log` | **Único** ledger de bloqueios (todas as camadas) |
| `.nemesis/logs/log-legado/` | Histórico arquivado de logs antigos |
| `.nemesis/runtime/session-events.jsonl` | Estado de runtime (não-log): o pretool grava cada tool-call; o daemon lê para a **correlação comportamental** (multi-turn / escalação). Também 100% local. |

> Após recompilar ou realocar caminhos, reinicie o daemon
> (`pkill -9 -f nemesis-defender` + `--ensure-daemon`) para ele reler o `session-events.jsonl`
> no caminho atual (`runtime/`).

---

## 8. Checklist de instalação (nova máquina)

- [ ] Rust + dependências do sistema instalados (`build-essential`, `libbpf-dev`, `clang`, `bpftool`).
- [ ] `cd .nemesis && cargo build --release --workspace` sem erros.
- [ ] 11 binários presentes em `.nemesis/target/release/` (rode `nemesis-doctor`).
- [ ] eBPF: capabilities + serviço ativo (Linux) — uma vez.
- [ ] Scaffold da IDE com pretool/posttool apontando para os binários corretos.
- [ ] `nemesis-doctor` retorna veredito `SAUDAVEL`.
