# Auditoria forense de conteúdo externo (issue / PR)

Antes de **analisar e mergear** uma issue ou PR de terceiros, passe o conteúdo pelo próprio
motor do Nemesis. É a "alfândega" do projeto: reduz o risco de **payload oculto**,
**prompt-injection** e **poisoning** de arquivos de configuração de agente entrarem na fonte.

## Como usar

1. Cole o conteúdo não-confiável (corpo da issue, arquivos/diff da PR) dentro de:

   ```
   .nemesis/forensics/incoming/
   ```

2. Rode o scan manual (a partir da raiz do projeto):

   ```bash
   bash .nemesis/forensics/scan-incoming.sh
   ```

3. Leia o veredito no terminal e em `.nemesis/forensics/forensics-report.md`:
   - **APROVADO** — nenhum sinal hostil conhecido. *Ainda assim leia o conteúdo* (o scan não
     entende lógica de negócio).
   - **REPROVADO** — um ou mais arquivos com sinal hostil. **Não mergeie** sem entender cada achado.

4. Limpe a drop zone quando terminar (o conteúdo é descartável e **não** é versionado):

   ```bash
   rm -rf .nemesis/forensics/incoming/*
   ```

## Por que isto é seguro (e o que NÃO é)

- A pasta `.nemesis/forensics/` é **isenta da quarentena do daemon**
  (`denylist-folder-files.json` → `daemon_quarantine_exempt`): o daemon ainda **escaneia e
  loga**, mas **não move** os arquivos nem trava a sessão durante a triagem. O veredito
  autoritativo é o **scan manual** acima.
- A drop zone (`incoming/`) e o relatório **não são commitados** (`.gitignore`): conteúdo
  hostil nunca entra no histórico.
- **Limite honesto:** isto é uma camada de triagem, **não** uma garantia. Um atacante pode
  escrever um payload que o scanner ainda não conhece. A defesa real continua sendo
  **revisão humana** + `CODEOWNERS` + branch protection nos arquivos trust-critical.

## Por que NÃO se chama `src/`

Esta é uma zona de **conteúdo não-confiável**, não código-fonte. Nomeá-la `src/` confundiria
com a fonte do projeto e poderia fazê-la ser tratada como código a compilar/distribuir.
`forensics/incoming/` deixa o propósito explícito.
