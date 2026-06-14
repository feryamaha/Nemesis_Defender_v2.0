#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AUDITORIA FORENSE de conteudo EXTERNO (issue/PR) antes de analisar e mergear.
#
# Uso:
#   1) Cole o conteudo suspeito (corpo da issue, diff/arquivos da PR) em:
#          .nemesis/forensics/incoming/
#   2) Rode:   bash .nemesis/forensics/scan-incoming.sh
#   3) Leia o veredito (APROVADO/REPROVADO) e o relatorio gerado.
#
# O script passa o MOTOR do Nemesis (nemesis-defender --scan) em CADA arquivo da drop zone
# e agrega um veredito. NAO confie so nele: o scan cobre malware/injection/poisoning
# conhecidos; logica de negocio maliciosa ainda exige leitura humana.
#
# A pasta .nemesis/forensics/ e ISENTA da QUARENTENA do daemon (denylist-folder-files.json):
# o daemon ainda escaneia e loga, mas NAO move arquivos nem trava a sessao durante a triagem —
# o veredito autoritativo e este scan manual. Compativel com macOS (bash 3.2) e Linux.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NEMESIS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"   # .nemesis/
INCOMING="$SCRIPT_DIR/incoming"
REPORT="$SCRIPT_DIR/forensics-report.md"

# Resolve o binario do defender no layout ativo (distro bin/ ou build da fonte target/release/).
if [ -x "$NEMESIS_ROOT/bin/nemesis-defender" ]; then
    DEF="$NEMESIS_ROOT/bin/nemesis-defender"
elif [ -x "$NEMESIS_ROOT/target/release/nemesis-defender" ]; then
    DEF="$NEMESIS_ROOT/target/release/nemesis-defender"
else
    echo "ERRO: nemesis-defender nao encontrado (.nemesis/bin/ nem .nemesis/target/release/)." >&2
    echo "      Instale via nemesis-install.sh, ou compile: cd .nemesis && cargo build --release" >&2
    exit 2
fi

mkdir -p "$INCOMING"

{
  echo "# Auditoria Forense de Conteudo Externo"
  echo
  echo "- Data: $(date '+%Y-%m-%d %H:%M')"
  echo "- Drop zone: \`.nemesis/forensics/incoming/\`"
  echo "- Motor: \`$DEF\`"
  echo
  echo "| Arquivo | Veredito |"
  echo "|---------|----------|"
} > "$REPORT"

total=0
flagged=0
# Portavel (sem mapfile/bash-4): itera com find -print0 + read -d ''. O while roda no shell
# atual (process substitution), entao os contadores persistem apos o laco.
while IFS= read -r -d '' f; do
    total=$((total + 1))
    rel="${f#"$INCOMING"/}"
    if "$DEF" --scan "$f" >/dev/null 2>&1; then
        echo "| $rel | LIMPO |" >> "$REPORT"
        echo "[ OK ] $rel" >&2
    else
        flagged=$((flagged + 1))
        echo "| **$rel** | **SUSPEITO** |" >> "$REPORT"
        {
            echo
            echo "<details><summary>Violacoes em $rel</summary>"
            echo
            echo '```'
            "$DEF" --scan "$f" 2>&1
            echo '```'
            echo
            echo "</details>"
        } >> "$REPORT"
        echo "[SUSPEITO] $rel" >&2
        "$DEF" --scan "$f" 2>&1 | sed 's/^/    /' >&2
    fi
done < <(find "$INCOMING" -type f ! -name '.gitkeep' -print0 2>/dev/null)

if [ "$total" -eq 0 ]; then
    echo "Drop zone vazia. Cole o conteudo da issue/PR em: $INCOMING" >&2
    rm -f "$REPORT"
    exit 0
fi

{
  echo
  if [ "$flagged" -eq 0 ]; then
    echo "## VEREDITO: APROVADO — $total arquivo(s), nenhum sinal hostil detectado."
    echo
    echo "Lembrete: o scan cobre padroes conhecidos (malware, injection, poisoning de config),"
    echo "nao logica de negocio. Leia o conteudo antes de mergear."
  else
    echo "## VEREDITO: REPROVADO — $flagged de $total arquivo(s) com sinal hostil."
    echo
    echo "NAO mergeie sem entender cada achado. Pode ser payload oculto, prompt-injection ou"
    echo "poisoning de arquivo de configuracao de agente (CLAUDE.md/AGENTS.md/.cursorrules/etc.)."
  fi
} >> "$REPORT"

echo "" >&2
echo "TOTAL=$total | SUSPEITOS=$flagged" >&2
echo "Relatorio: $REPORT" >&2

# Exit code = veredito (gate para automacao, se desejar).
[ "$flagged" -eq 0 ] || exit 1
