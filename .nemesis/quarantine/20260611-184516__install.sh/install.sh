#!/usr/bin/env bash
# =============================================================================
# Nemesis Defender — instalador por BINÁRIOS (sem git clone, sem cargo, sem npm)
# =============================================================================
# Baixa os binários pré-compilados do GitHub Release, VERIFICA o checksum SHA256
# ANTES de extrair, instala em .nemesis/bin/ e faz o scaffold do hook da sua IDE.
#
# Suporta: macOS (arm64/x64) e Linux (x64). Windows fora de escopo por enquanto.
#
# ⚠️  NEMESIS É SEGURANÇA: o próprio Nemesis BLOQUEIA `curl … | sh`. Por coerência,
#     o modo RECOMENDADO é em DUAS ETAPAS (baixe, inspecione, execute):
#
#         curl -fsSLO https://raw.githubusercontent.com/feryamaha/Nemesis_Defender_v2.0/main/install.sh
#         less install.sh        # inspecione
#         bash install.sh        # execute a partir da raiz do SEU projeto
#
# Variáveis: NEMESIS_VERSION (default: latest), NEMESIS_REPO (default: feryamaha/Nemesis_Defender_v2.0)
# =============================================================================
set -euo pipefail

REPO="${NEMESIS_REPO:-feryamaha/Nemesis_Defender_v2.0}"
VERSION="${NEMESIS_VERSION:-latest}"
PKG_PREFIX="nemesis-v2.0"

say()  { printf '\033[0;36m[nemesis-install]\033[0m %s\n' "$*"; }
err()  { printf '\033[0;31m[nemesis-install] ERRO:\033[0m %s\n' "$*" >&2; exit 1; }

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
say "Binários instalados em .nemesis/bin/"

ABS_PRETOOL="$(pwd)/.nemesis/bin/nemesis-pretool-check-unix"
ABS_POSTTOOL="$(pwd)/.nemesis/bin/nemesis-posttool-check-unix"

# ── 6. Scaffold do hook da IDE (sem sobrescrever config existente) ───────────
scaffold_claude() {
  local f=".claude/settings.json"
  mkdir -p .claude
  if [ -s "$f" ]; then
    say "Já existe $f — NÃO sobrescrevi. Adicione o hook PreToolUse/PostToolUse apontando para:"
    say "  $ABS_PRETOOL"
    return
  fi
  cat > "$f" <<EOF
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Read|Write|Edit|MultiEdit|Bash|NotebookEdit",
        "hooks": [ { "type": "command", "command": "$ABS_PRETOOL" } ] }
    ],
    "PostToolUse": [
      { "matcher": "Read|Write|Edit|MultiEdit|Bash|NotebookEdit",
        "hooks": [ { "type": "command", "command": "$ABS_POSTTOOL" } ] }
    ]
  }
}
EOF
  say "Hook do Claude Code escrito em $f"
}

scaffold_generic() { # $1=dir $2=file
  local f="$2"
  if [ -s "$f" ]; then say "Já existe $f — NÃO sobrescrevi. Aponte o hook para $ABS_PRETOOL"; return; fi
  mkdir -p "$1"
  cat > "$f" <<EOF
{
  "hooks": {
    "PreToolUse": [ { "type": "command", "command": "$ABS_PRETOOL" } ],
    "PostToolUse": [ { "type": "command", "command": "$ABS_POSTTOOL" } ]
  }
}
EOF
  say "Hook escrito em $f"
}

detected=0
[ -d ".claude"  ] && { scaffold_claude; detected=1; }
[ -d ".cursor"  ] && { scaffold_generic .cursor .cursor/hooks.json; detected=1; }
[ -d ".codex"   ] && { scaffold_generic .codex  .codex/hooks.json;  detected=1; }
[ -d ".devin"   ] && { scaffold_generic .devin  .devin/hooks.json;  detected=1; }
if [ "$detected" -eq 0 ]; then
  say "Nenhuma pasta de IDE (.claude/.cursor/.codex/.devin) encontrada."
  say "Configure manualmente o hook de pre-tool apontando para: $ABS_PRETOOL"
fi

# ── 7. Próximos passos ───────────────────────────────────────────────────────
cat <<EOF

$(say "Instalação concluída ($VERSION, $suffix).")
  • Binários:   .nemesis/bin/
  • Verificar:  .nemesis/bin/nemesis-doctor
  • eBPF (camada de kernel, Linux, OPT-IN): não vem nos binários — exige libbpf/clang e é
    construída da fonte. Veja .nemesis/ebpf-kernel/info.md (se você clonou o repo).
  • Reinicie a IDE para os hooks entrarem em vigor.
EOF
