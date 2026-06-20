---
name: nao-restaurar-arquivos-deletados
description: Não ressuscitar arquivos que o Fernando apagou de propósito, mesmo que um prompt os cite.
metadata:
  type: feedback
---

Quando um arquivo foi deletado pelo Fernando, a deleção é autoritativa: NÃO restaurar do git, mesmo que o prompt da tarefa cite o arquivo como existente ou peça para "atualizá-lo". Se referências a ele aparecerem em outros arquivos, a ação correta é REMOVER as referências (links de navbar, tiles, pagers), não trazer o arquivo de volta.

**Why:** no onboarding, o Fernando havia deletado `onboarding/RELATORIO.html` de propósito; eu o restaurei do git justificando "evitar link quebrado" e isso causou forte reação negativa. "O que encontro contradiz como foi descrito" deve favorecer remover/perguntar, não resurgir.

**How to apply:** se um arquivo citado está ausente, trate a ausência como decisão deliberada; remova as referências a ele e, na dúvida, pergunte antes de recriar qualquer coisa.
