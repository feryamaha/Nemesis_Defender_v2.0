#!/usr/bin/env bash
# =============================================================================
# Nemesis Defender — instalador por BINÁRIOS (sem git clone, sem cargo, sem npm)
# =============================================================================
# Baixa os binários pré-compilados do GitHub Release, VERIFICA o checksum SHA256
# ANTES de extrair, instala em .nemesis/bin/ e faz o scaffold do hook da sua IDE.
# Faz SÓ o essencial: NÃO roda validação nem sobe o daemon — a validação (doctor +
# pentest) é um passo MANUAL pós-install, descrito em info-install.txt.
#
# Suporta: macOS (arm64/x64) e Linux (x64). Windows fora de escopo por enquanto.
#
# ⚠️  NEMESIS É SEGURANÇA: o próprio Nemesis BLOQUEIA `curl … | sh`. Por coerência,
#     o modo RECOMENDADO é em DUAS ETAPAS (baixe, inspecione, execute). Baixe o
#     instalador E o leia-me (info-install.txt) de uma vez:
#
#         curl -fsSLO https://raw.githubusercontent.com/feryamaha/Nemesis_Defender_v2.0/main/.nemesis/install/nemesis-install.sh \
#              -O      https://raw.githubusercontent.com/feryamaha/Nemesis_Defender_v2.0/main/.nemesis/install/info-install.txt
#         less info-install.txt          # leia o passo a passo
#         less nemesis-install.sh        # inspecione o instalador
#         bash nemesis-install.sh        # execute a partir da raiz do SEU projeto
#
# Variáveis: NEMESIS_VERSION (default: latest), NEMESIS_REPO (default: feryamaha/Nemesis_Defender_v2.0)
# =============================================================================
set -euo pipefail

REPO="${NEMESIS_REPO:-feryamaha/Nemesis_Defender_v2.0}"
VERSION="${NEMESIS_VERSION:-latest}"
PKG_PREFIX="nemesis-v2.0"

say()  { printf '\033[0;36m[nemesis-install]\033[0m %s\n' "$*"; }
ok()   { printf '\033[0;32m[nemesis-install] ✔\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[nemesis-install] ⚠\033[0m %s\n' "$*"; }
err()  { printf '\033[0;31m[nemesis-install] ERRO:\033[0m %s\n' "$*" >&2; exit 1; }
hr()   { printf '\033[0;36m%s\033[0m\n' "──────────────────────────────────────────────────────────────"; }

# ── 1. Detectar SO/arch ──────────────────────────────────────────────────────
os="$(uname -s)"; arch="$(uname -m)"
case "$os" in
  Darwin) case "$arch" in
            arm64|aarch64) suffix="darwin-arm64" ;;
            x86_64)        suffix="darwin-x64" ;;
            *) err "arch macOS não suportada: $arch" ;;
          esac ;;
  Linux)  case "$arch" in
            x86_64) suffix="linux-x64" ;;
            *) err "arch Linux não suportada: $arch (somente x86_64 por enquanto)" ;;
          esac ;;
  *) err "SO não suportado: $os (somente macOS e Linux)" ;;
esac
say "Plataforma detectada: $suffix"

# ── 2. Resolver a tag de versão ──────────────────────────────────────────────
if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')" \
    || err "não consegui resolver a release 'latest' de $REPO"
  [ -n "$VERSION" ] || err "tag_name vazio na release latest"
fi
say "Versão: $VERSION"

tarball="$PKG_PREFIX-$suffix.tar.gz"
base="https://github.com/$REPO/releases/download/$VERSION"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# ── 3. Baixar tarball + checksum ─────────────────────────────────────────────
say "Baixando $tarball ..."
curl -fsSL "$base/$tarball"        -o "$tmp/$tarball"        || err "falha ao baixar $tarball"
curl -fsSL "$base/$tarball.sha256" -o "$tmp/$tarball.sha256" || err "falha ao baixar o checksum"

# ── 4. VERIFICAR o checksum ANTES de extrair (inegociável p/ ferramenta de segurança) ──
say "Verificando SHA256 ..."
expected="$(awk '{print $1}' "$tmp/$tarball.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$tarball" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$tmp/$tarball" | awk '{print $1}')"
fi
[ -n "$expected" ] || err "checksum esperado vazio"
[ "$expected" = "$actual" ] || err "CHECKSUM NÃO CONFERE — abortado. esperado=$expected obtido=$actual"
say "Checksum OK."

# ── 5. Extrair para .nemesis/ do projeto atual ───────────────────────────────
[ -d ".git" ] || say "Aviso: não parece a raiz de um repositório git. Instalando em $(pwd)/.nemesis"
mkdir -p .nemesis
tar -xzf "$tmp/$tarball" -C .nemesis
chmod +x .nemesis/bin/* 2>/dev/null || true
chmod +x .nemesis/pentest-nemesis-control/nemesis-defender/run-pentest.sh 2>/dev/null || true

# Rede de segurança: NUNCA herdar logs do empacotamento. O ledger é gerado em runtime;
# qualquer violations.log/nemesis-violations.log que tenha vindo no tarball é removido,
# e a pasta de logs começa limpa (evita "log já preenchido" na máquina do usuário).
rm -f .nemesis/logs/violations.log .nemesis/logs/*.log logs/violations.log 2>/dev/null || true
say "Binários instalados em .nemesis/bin/"

ABS_PRETOOL="$(pwd)/.nemesis/bin/nemesis-pretool-check-unix"
ABS_POSTTOOL="$(pwd)/.nemesis/bin/nemesis-posttool-check-unix"

# ── 6. Scaffold do hook por IDE — cada uma tem NOME e SCHEMA próprios ─────────
# NUNCA sobrescreve config existente (preserva a sua). Caminho absoluto p/ os binários
# (exceto GitHub/VS Code, que usa caminho relativo, conforme o formato dele).
PRE="$ABS_PRETOOL"; POST="$ABS_POSTTOOL"

guard() {  # retorna 1 (e avisa) se o arquivo já existe e tem conteúdo
  if [ -s "$1" ]; then
    say "Já existe $1 — preservado (NÃO sobrescrevi). Garanta que o hook aponta para: $PRE"
    return 1
  fi
  return 0
}

# A — Claude / OpenClaude (settings.json; PreToolUse + matcher + hooks[])
sc_claude_like() { # $1=dir $2=file
  guard "$2" || return 0; mkdir -p "$1"
  cat > "$2" <<EOF
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Read|Write|Edit|MultiEdit|Bash|NotebookEdit", "hooks": [ { "type": "command", "command": "$PRE" } ] }
    ],
    "PostToolUse": [
      { "matcher": "Read|Write|Edit|MultiEdit|Bash|NotebookEdit", "hooks": [ { "type": "command", "command": "$POST" } ] }
    ]
  }
}
EOF
  say "Hook (Claude/OpenClaude) escrito em $2"
}

# B — Codex (hooks.json; matcher .* + timeout)
sc_codex() {
  guard ".codex/hooks.json" || return 0; mkdir -p .codex
  cat > .codex/hooks.json <<EOF
{
  "hooks": {
    "PreToolUse": [
      { "matcher": ".*", "hooks": [ { "type": "command", "command": "$PRE", "timeout": 30 } ] }
    ],
    "PostToolUse": [
      { "matcher": ".*", "hooks": [ { "type": "command", "command": "$POST", "timeout": 30 } ] }
    ]
  }
}
EOF
  say "Hook (Codex) escrito em .codex/hooks.json"
}

# C — Cursor (hooks.json; version 1, preToolUse camelCase, command direto, failClosed)
sc_cursor() {
  guard ".cursor/hooks.json" || return 0; mkdir -p .cursor
  cat > .cursor/hooks.json <<EOF
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      { "matcher": "Shell|Read|Write|StrReplace|Glob|Grep|Delete|EditNotebook|Task|SemanticSearch|WebFetch|TabRead|TabWrite", "command": "$PRE", "failClosed": false }
    ],
    "postToolUse": [
      { "matcher": "Shell|Read|Write|StrReplace|Glob|Grep|Delete|EditNotebook|Task|SemanticSearch|WebFetch", "command": "$POST", "failClosed": false }
    ]
  }
}
EOF
  say "Hook (Cursor) escrito em .cursor/hooks.json"
}

# D — Devin (hooks.json; eventos pre_*/post_* + show_output)
sc_devin() {
  guard ".devin/hooks.json" || return 0; mkdir -p .devin
  cat > .devin/hooks.json <<EOF
{
  "hooks": {
    "pre_write_code":   [ { "command": "$PRE", "show_output": true } ],
    "pre_run_command":  [ { "command": "$PRE", "show_output": true } ],
    "pre_read_code":    [ { "command": "$PRE", "show_output": true } ],
    "pre_mcp_tool_use": [ { "command": "$PRE", "show_output": true } ],
    "post_write_code":   [ { "command": "$POST", "show_output": true } ],
    "post_run_command":  [ { "command": "$POST", "show_output": true } ],
    "post_read_code":    [ { "command": "$POST", "show_output": true } ],
    "post_mcp_tool_use": [ { "command": "$POST", "show_output": true } ]
  }
}
EOF
  say "Hook (Devin) escrito em .devin/hooks.json"
}

# E — Gemini / .agents (hooks.json; objetos nomeados com "enabled")
sc_gemini_like() { # $1=dir
  guard "$1/hooks.json" || return 0; mkdir -p "$1"
  cat > "$1/hooks.json" <<EOF
{
  "nemesis-pretool-hook": {
    "enabled": true,
    "PreToolUse": [ { "matcher": ".*", "hooks": [ { "type": "command", "command": "$PRE", "timeout": 30 } ] } ]
  },
  "nemesis-posttool-hook": {
    "enabled": true,
    "PostToolUse": [ { "matcher": ".*", "hooks": [ { "type": "command", "command": "$POST", "timeout": 30 } ] } ]
  }
}
EOF
  say "Hook (Gemini/Agents) escrito em $1/hooks.json"
}

# F — VS Code / GitHub (.github/hooks/ + .vscode aponta pra ele; caminho RELATIVO)
sc_github_vscode() {
  if guard ".github/hooks/nemesis-pretool-hook.json"; then
    mkdir -p .github/hooks
    cat > .github/hooks/nemesis-pretool-hook.json <<'EOF'
{
  "hooks": {
    "PreToolUse": [ { "type": "command", "command": "./.nemesis/bin/nemesis-pretool-check-unix" } ],
    "PostToolUse": [ { "type": "command", "command": "./.nemesis/bin/nemesis-posttool-check-unix" } ]
  }
}
EOF
    say "Hook (GitHub/VS Code) escrito em .github/hooks/nemesis-pretool-hook.json"
  fi
  if [ -d .vscode ] && ! [ -s .vscode/settings.json ]; then
    cat > .vscode/settings.json <<'EOF'
{
  "chat.hookFilesLocations": { ".github/hooks": true }
}
EOF
    say "VS Code: .vscode/settings.json apontando para .github/hooks"
  fi
}

# Dispatcher por nome de IDE — cria a pasta + o hook no formato correto.
scaffold_ide() {  # $1 = nome
  case "$1" in
    claude)        sc_claude_like .claude .claude/settings.json ;;
    openclaude)    sc_claude_like .openclaude .openclaude/settings.json ;;
    codex)         sc_codex ;;
    cursor)        sc_cursor ;;
    devin)         sc_devin ;;
    gemini)        sc_gemini_like .gemini ;;
    agents)        sc_gemini_like .agents ;;
    github|vscode) sc_github_vscode ;;
    *) say "IDE desconhecida: '$1' (use: claude|openclaude|codex|cursor|devin|gemini|agents|github)"; return 1 ;;
  esac
}

IDES="claude|openclaude|codex|cursor|devin|gemini|agents|github"
detected=0

if [ -n "${NEMESIS_IDE:-}" ]; then
  # IDE(s) EXPLÍCITA(s) via env — cria o hook MESMO que a pasta ainda não exista.
  # Ex.: NEMESIS_IDE=devin bash nemesis-install.sh   (ou lista: NEMESIS_IDE=devin,codex)
  OLD_IFS="$IFS"; IFS=','
  for ide in $NEMESIS_IDE; do
    ide="$(printf '%s' "$ide" | tr 'A-Z' 'a-z' | tr -d '[:space:]')"
    if [ -n "$ide" ] && scaffold_ide "$ide"; then detected=1; fi
  done
  IFS="$OLD_IFS"
else
  # Autodetecção: pastas de IDE já presentes no projeto.
  [ -d ".claude"     ] && { sc_claude_like .claude .claude/settings.json; detected=1; }
  [ -d ".openclaude" ] && { sc_claude_like .openclaude .openclaude/settings.json; detected=1; }
  [ -d ".codex"      ] && { sc_codex; detected=1; }
  [ -d ".cursor"     ] && { sc_cursor; detected=1; }
  [ -d ".devin"      ] && { sc_devin; detected=1; }
  [ -d ".gemini"     ] && { sc_gemini_like .gemini; detected=1; }
  [ -d ".agents"     ] && { sc_gemini_like .agents; detected=1; }
  { [ -d ".github" ] || [ -d ".vscode" ]; } && { sc_github_vscode; detected=1; }
fi

if [ "$detected" -eq 0 ]; then
  say "Nenhuma IDE detectada (pasta inexistente) e NEMESIS_IDE não informado."
  if [ -t 0 ]; then
    printf '[nemesis-install] Para qual IDE configurar o hook? (%s): ' "$IDES"
    read -r choice || choice=""
    choice="$(printf '%s' "$choice" | tr 'A-Z' 'a-z' | tr -d '[:space:]')"
    if [ -n "$choice" ] && scaffold_ide "$choice"; then detected=1; fi
  fi
  if [ "$detected" -eq 0 ]; then
    say "Configure manualmente, OU rode escolhendo a IDE: NEMESIS_IDE=devin bash nemesis-install.sh"
    say "Binário do hook (pre-tool): $PRE"
  fi
fi

# ── 7. Próximos passos — o install NÃO valida nem sobe o daemon (validação é MANUAL) ──
# DECISÃO DE DESIGN: o install faz só o essencial (detectar, baixar, verificar checksum,
# extrair, scaffold do hook). NÃO roda pentest nem doctor aqui: qualquer coisa que invoque o
# pretool (ou o pretool via IDE) dispara `--ensure-daemon`, e subir o daemon no meio do install
# faria ele vigiar e quarentenar o próprio instalador. A validação (doctor + pentest) é um passo
# MANUAL pós-install, abaixo.
hr
ok "INSTALACAO CONCLUIDA  ·  $VERSION  ·  $suffix"
hr
cat <<EOF
  Binarios instalados:  .nemesis/bin/
  Reinicie a IDE para os hooks entrarem em vigor.

  >>> VALIDE A INSTALACAO (manual, passo a passo em info-install.txt) <<<
  1) Diagnostico do ambiente (siga as acoes que ele indicar):
       .nemesis/bin/nemesis-doctor --quick
  2) Validacao ESTATICA (Nivel 1) - binario auto-detectado (macOS/Linux):
       bash .nemesis/pentest-nemesis-control/nemesis-defender/run-pentest.sh
     Sucesso: FAIL=0 (requer 'node' no PATH).
  3) Validacao PRATICA (Nivel 2): cole no seu agente (Claude/Devin/Cursor/Codex/Gemini), na IDE
     ou no TUI, o conteudo de:
       .nemesis/pentest-nemesis-control/nemesis-defender/pentest-final-amplificado-portal-dental.md
     e confirme que o Nemesis BLOQUEIA cada acao (exit 2).

  Guias completos:  info-install.txt  (raiz)  e
                    .nemesis/pentest-nemesis-control/nemesis-defender/info.md

  Se algo que DEVERIA ser bloqueado PASSAR (gap de seguranca):
     abra uma issue em https://github.com/$REPO/issues  ou contate feryamaha@hotmail.com

  eBPF (camada de kernel, Linux, OPT-IN): construida da fonte (veja .nemesis/ebpf-kernel/info.md).
EOF
hr
