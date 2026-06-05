# nemesis-ebpf-kernel — Instruções de Operação

## Pré-requisitos

| Requisito | Verificação |
|---|---|
| Linux kernel ≥ 5.7 | `uname -r` |
| BPF LSM ativo no boot | `cat /sys/kernel/security/lsm` deve conter `bpf` |
| clang instalado | `which clang` |
| bpftool instalado | `which bpftool` |
| Binário compilado | `cargo build -p nemesis-ebpf-kernel` |

---

## 1. Ativar BPF LSM no boot (uma vez, requer reboot)

```bash
sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 lsm=lockdown,capability,landlock,yama,apparmor,bpf"/' /etc/default/grub
sudo update-grub
sudo reboot
```

Verificar após reboot:
```bash
cat /sys/kernel/security/lsm
# esperado: lockdown,capability,landlock,yama,apparmor,bpf
```

---

## 2. Compilar o projeto

```bash
# A partir da raiz do projeto
cargo build -p nemesis-ebpf-kernel
```

**IMPORTANTE - Bloqueio de build pelo BPF LSM:**

Se o BPF LSM estiver ativo e bloqueando o build (erro "Operation not permitted" no `rm` do make durante a compilação do libbpf-sys), siga estes passos:

```bash
# 1. Verificar se o daemon está rodando
ps aux | grep nemesis-ebpf-daemon

# 2. Parar o daemon
sudo systemctl stop nemesis-ebpf  # se estiver como serviço
# ou mate o processo manualmente
kill <PID_DO_DAEMON>

# 3. Tentar compilar novamente
cargo build -p nemesis-ebpf-kernel
```

Se mesmo após parar o daemon o build falhar, o programa BPF LSM pode estar carregado no kernel. Programas BPF não podem ser removidos dinamicamente. Nesse caso:

```bash
# Reinicie o sistema para descarregar o programa BPF LSM
sudo reboot
```

Após o reinício, compile antes de iniciar o daemon novamente.

O objeto BPF (`.bpf.o`) é compilado automaticamente pelo daemon na primeira execução via `make`.

---

## 3. Ativar o enforcement eBPF (procedimento completo)

Todos os passos abaixo devem ser executados a partir da raiz do projeto.

### 3.1 Criar o cgroup do agente (uma vez por boot, requer sudo)

```bash
sudo mkdir -p /sys/fs/cgroup/nemesis-agent
```

Verificar:
```bash
stat -c "%i" /sys/fs/cgroup/nemesis-agent
# deve retornar um número (ex: 14014) — esse é o cgroup_id
```

### 3.2 Delegar capabilities ao binário (uma vez por build)

Necessário após cada `cargo build` que recriar o binário:

```bash
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+eip \
  .nemesis/target/debug/nemesis-ebpf-daemon
```

Verificar:
```bash
getcap .nemesis/target/debug/nemesis-ebpf-daemon
# esperado: cap_sys_resource,cap_perfmon,cap_bpf=eip
```

### 3.3 Iniciar o daemon BPF LSM

```bash
.nemesis/target/debug/nemesis-ebpf-daemon --start
```

Saída esperada:
```
[nemesis] loading BPF LSM program into kernel...
make: Nada a ser feito para 'all'.
[nemesis] Agent cgroup_id 14014 registered in BPF
[nemesis] BPF LSM attached — enforcement active. Ctrl-C to stop.
```

A linha `Agent cgroup_id ... registered in BPF` confirma que o filtro por cgroup está ativo.
Se essa linha não aparecer, o cgroup não foi criado corretamente (volte ao passo 3.1).

O daemon fica em **modo epoll** — consome ~0% CPU e ~10MB RAM em idle. Acorda apenas quando um execve é interceptado.

### 3.4 Mover processos do agente para o cgroup

Para que o BPF bloqueie comandos, o processo do agente LLM deve estar dentro do cgroup:

```bash
echo <PID_DO_AGENTE> | sudo tee /sys/fs/cgroup/nemesis-agent/cgroup.procs
```

Verificar:
```bash
cat /proc/<PID>/cgroup
# esperado: 0::/nemesis-agent
```

Todos os processos filhos herdam o cgroup automaticamente.

### Ativação automática via systemd (recomendado)

Instalar o service uma vez:

```bash
sudo bash .nemesis/ebpf-kernel/install-service.sh
```

Após a instalação, o daemon inicia automaticamente no boot. Comandos:

```bash
systemctl status nemesis-ebpf       # ver estado
journalctl -u nemesis-ebpf -f       # ver logs em tempo real
sudo systemctl stop nemesis-ebpf    # parar
sudo systemctl restart nemesis-ebpf # reiniciar
```

O systemd cuida de: criar o cgroup, delegar capabilities e iniciar o daemon.
O daemon se move automaticamente para o cgroup ao iniciar — subprocessos herdam.

### Ativação manual (alternativa)

```bash
# 1. Criar cgroup (uma vez por boot)
sudo mkdir -p /sys/fs/cgroup/nemesis-agent

# 2. Capabilities (uma vez por build)
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+eip .nemesis/target/debug/nemesis-ebpf-daemon

# 3. Iniciar daemon (terminal dedicado)
.nemesis/target/debug/nemesis-ebpf-daemon --start
```

O daemon se move automaticamente para o cgroup — não é necessário mover PIDs manualmente.

---

## 4. Verificar estado sem iniciar

```bash
# Diagnóstico completo
.nemesis/target/debug/nemesis-ebpf-daemon --doctor

# Status rápido
.nemesis/target/debug/nemesis-ebpf-daemon --print-status
```

Campos importantes no `--doctor`:
- `bpf_lsm_active`: true = BPF LSM ativo no kernel
- `enforcement_level`: `"bpf_lsm"` = enforcement ativo | `"landlock"` = sem root/CAP_BPF
- `can_load_bpf`: true = capabilities suficientes

---

## 5. Modo sandbox sem root (Landlock + seccomp)

Protege apenas a process tree do processo filho, sem necessidade de root:

```bash
.nemesis/target/debug/nemesis-ebpf-daemon --sandbox
```

---

## 6. Arquitetura do filtro por cgroup

O programa BPF LSM filtra execuções por cgroup. Apenas processos dentro do cgroup `/sys/fs/cgroup/nemesis-agent` são verificados contra a deny-list. Processos do IDE, terminal e sistema passam sem verificação.

Fluxo interno:
1. O daemon lê o inode do diretório `/sys/fs/cgroup/nemesis-agent` (cgroup_id)
2. O cgroup_id é registrado no mapa BPF `agent_cgroup_map`
3. A cada execve, o programa BPF compara `bpf_get_current_cgroup_id()` com o cgroup registrado
4. Processos fora do cgroup: `return 0` (permitido)
5. Processos dentro do cgroup: verificados contra `blocked_commands`
6. Se o comando está na deny-list: `return -EPERM` (bloqueado) + evento no ringbuf

---

## 7. Deny-lists configuráveis

| Arquivo | Conteúdo |
|---|---|
| `denylist-ebpf/commands.toml` | Binários bloqueados por basename |
| `denylist-ebpf/paths.toml` | Paths de escrita bloqueados |
| `denylist-ebpf/landlock-allowed-exec.toml` | Exec permitidos no modo sandbox |

Editar e reiniciar o daemon para aplicar. Não requer recompilação.

### Lista completa de comandos bloqueados no kernel (39 comandos)

| Categoria | Comandos |
|---|---|
| Destruição de dados | rm, shred, truncate, dd, mkfifo, split, csplit |
| Permissões | chmod, chown |
| Sistema de arquivos | mount, umount, mkfs, fdisk |
| Bancos de dados | dropdb, mysql, psql |
| Infraestrutura/cloud | terraform, docker, aws, kubectl |
| Linguagens de script | python, python3, ruby, perl, lua |
| Editores | nano, vim, vi, emacs, micro |
| Exfiltração | curl, wget, ftp, sftp, rsync, scp, nc, netcat, socat |
| Controle de processos | kill, killall, nohup |
| Injeção via texto | sed, awk, gawk, mawk, ed, ex |
| Outros | ln, pax, tar, zip, unzip |

---

## 8. Executar testes de validação

Com o daemon rodando em outro terminal:

```bash
# Level 1 — comandos básicos
bash test-violations/pentest-ebpf-kernel/level-1-bpf-lsm.sh

# Level 2 — evasão via subprocessos e paths absolutos
bash test-violations/pentest-ebpf-kernel/level-2-resource-exhaustion.sh

# Level 3 — bypass via symlinks e wrappers
bash test-violations/pentest-ebpf-kernel/level-3-kernel-bypass-attempts.sh
```

---

## 9. Logs de violações

```bash
cat .nemesis/logs/violations.log | grep '"layer":"ebpf"'
```

---

## Resumo de enforcement por nível

| Condição | Nível ativo | Escopo |
|---|---|---|
| Sem root, sem CAP_BPF, BPF LSM ativo | `landlock` | process tree apenas |
| Com CAP_BPF + CAP_PERFMON + CAP_SYS_RESOURCE, BPF LSM ativo | `bpf_lsm` | cgroup do agente (via `agent_cgroup_map`) |
| BPF LSM inativo no boot | `pretool` | apenas hooks do IDE/Cascade |

---

## Separação de responsabilidades: pretool vs eBPF

| Camada | Responsabilidade |
|---|---|
| **pretool** (deny-list.json) | Regras de padrão de código (TypeScript, React, hooks, naming). Intercepta tool calls do agente LLM dentro do IDE |
| **eBPF kernel** (commands.toml) | Bloqueio de execuções destrutivas via `execve`. Atua no nível do kernel, apenas para processos no cgroup do agente |

---

## 10. Verificar se eBPF está ativo

Use os seguintes comandos para diagnosticar o estado do eBPF-kernel:

```bash
# Verificar se BPF LSM está ativo no kernel
cat /sys/kernel/security/lsm
# Esperado: lockdown,capability,landlock,yama,apparmor,bpf

# Verificar se o daemon está rodando
systemctl status nemesis-ebpf
# Esperado: Active: active (running)

# Reiniciar o daemon (após modificar deny-list)
sudo systemctl restart nemesis-ebpf
# Finalidade: Recarrega a deny-list (commands.toml) para aplicar mudanças

# Verificar status do enforcement (se o binário estiver disponível)
.nemesis/target/debug/nemesis-ebpf-daemon --doctor
# Campos importantes: bpf_lsm_active, enforcement_level, can_load_bpf

# Verificar logs em tempo real
journalctl -u nemesis-ebpf -f
# Procure por: [nemesis] BLOCKED ou [VIOLATION] PermissionDenied
```
