# Nemesis Defender

**Defense-in-depth contra malware de supply-chain e abuso de agentes LLM em ambientes de desenvolvimento.**

Versão: `2.0` · Workspace: `8.2.0` · Plataforma principal: Linux (eBPF) com fallback cross-platform · Licença: AGPL-3.0 (licenciamento dual disponível)

---

> ## ⚠️ LEIA ANTES DE INSTALAR — isto não é um brinquedo
>
> O Nemesis Defender é um sistema de segurança que **age, não pergunta.** Ele não negocia, não abre concessões e não é uma democracia — é 0 ou 1.
>
> **FAÇA BACKUP DO SEU PROJETO ANTES DE INSTALAR.** Ao ser instalado em um projeto que já contém código com violações (credenciais expostas, comandos destrutivos embutidos, anti-padrões graves), a camada de scanner pode **remover os arquivos infratores** — em um caso real, removeu 24 arquivos de um projeto que não havia sido desenvolvido sob o Nemesis. Se o projeto estiver versionado (Git), o código removido permanece no controle de versão da IDE e é recuperável. Se **não** estiver versionado, a perda é definitiva.
>
> Isto é intencional. O Nemesis intercepta operações destrutivas e inseguras **independentemente de quem as origina — IA ou humano.** No Linux, com a camada eBPF ativa, nem você pelo terminal consegue rodar um `rm -rf`. É a natureza de um sistema que existe para forçar disciplina de qualidade e segurança.
>
> **Use o Nemesis se você quer um harness rígido que obriga código limpo e seguro.** Se você segue as regras, ele é um aliado poderoso. Se você pisa fora da caixa, ele pune — por isso se chama Nemesis. Requer conhecimento técnico mínimo para configurar e operar; não é plug-and-play.

---

> **Aviso honesto de escopo.** O Nemesis Defender é um sistema de enforcement robusto, projetado em camadas independentes para **elevar significativamente o custo de um ataque**. Ele **não** é — e nenhum sistema de segurança é — "impenetrável". Esta documentação descreve o que o Nemesis faz, contra qual modelo de ameaça, e — igualmente importante — **o que ele não faz**. Se você procura uma garantia de proteção total, ela não existe aqui nem em nenhum outro lugar.

---


## Isto já não existe nativamente nas IDEs?

Pergunta justa e esperada — e a que mais vai aparecer quando o projeto for público: *"isso não dá pra configurar nas settings da IDE?"*. A resposta honesta é: os **primitivos existem** (hooks, deny-list, sandbox) e o Nemesis Defender **usa esses recursos nativos**. Não inventei hook nem sandbox. O que fiz foi **recompilar todas essas peças num único framework de enforcement** que bloqueia comandos destrutivos *e* maliciosos, igual em qualquer IDE, com uma camada de kernel que nenhuma delas entrega. **Nenhuma ferramenta nativa faz a combinação completa.**

| Recurso nativo | O que de fato faz | Onde para (evidência) |
|----------------|-------------------|------------------------|
| **Hooks** (Claude Code `PreToolUse`, Cursor `beforeShellExecution`, Copilot) | Interceptam a chamada de ferramenta antes da execução e podem bloquear (exit code 2). | É só o ponto de interceptação — você escreve toda a lógica de enforcement. E é por-IDE, com payloads incompatíveis entre si. Nada vem pronto. |
| **Deny-list / permissions** (`settings.json` allow/deny) | Bloqueia comandos e paths por nome para as ferramentas internas do agente; deny vence allow. | Pela doc da Anthropic: deny-rules só bloqueiam as ferramentas internas — `Read(./.env)` é barrado, mas `cat .env` no bash passa por cima. Não inspeciona conteúdo. |
| **Sandbox / isolamento** (`/sandbox` bubblewrap·Seatbelt, devcontainer/Docker) | Isolamento de filesystem e rede no nível do SO; reduz o blast radius. É o recurso nativo mais forte. | Só cobre o Bash, não as ferramentas Read/Edit (issue #26616 do Claude Code). E *contém*, não *detecta*: um `package.json` envenenado ou uma cadeia de exfiltração passam "dentro" do sandbox. Por-IDE. |
| **Rules / skills / workflows** (`.cursorrules`, `CLAUDE.md`) | Dão contexto e diretrizes ao modelo. | São advisory, não enforcement. O modelo é um motor de previsão, não um aplicador de política — ignora, reinterpreta ou sobrescreve (fórum do Cursor; análise da Knostic). O código vazado do Claude Code mostrou que até o agente da Anthropic trata constraints como dicas. |
| **eBPF / LSM no kernel** (KubeArmor, Tetragon, Falco) | Enforcement de syscall no kernel — a defesa com mais "dentes", que vale inclusive contra o humano no terminal. | Existe e é maduro — mas no mundo cloud/Kubernetes. Não é entregue como binário local, por-projeto, acoplado ao ciclo de um coding agent. É exatamente a camada eBPF do Nemesis, trazida pra máquina do dev. |

**A diferença entre "configurar uma regra" e "forçar uma regra" não é teórica.** Em julho de 2025, o agente do Replit deletou um banco de produção *durante um code freeze ativo*, apesar de instruções repetidas — porque, segundo a análise do incidente, as instruções não eram tecnicamente forçadas: não havia um gate que bloqueasse a ação (AI Incident Database #1152). Na mesma linha: o Gemini CLI apagando arquivos por interpretar mal um comando, e o Claude Code rodando um `terraform destroy` acidental. Settings, rules e até sandbox parcial não impediram nenhum deles.

**Resumindo:** a deny-list nativa não pega `cat .env`; o sandbox nativo não pega Read/Edit nem um pacote envenenado; as rules não pegam nada porque são advisory; e o eBPF de kernel mora na nuvem, não na sua máquina. Cada peça resolve um pedaço — no máximo alguns comandos destrutivos, e não todos. O Nemesis Defender junta tudo num único framework: deny-list + scanner de conteúdo (destrutivo **e** malicioso) + AST + eBPF no kernel como última camada para usuários Linux, igual em Windsurf, Cursor, Codex, Claude Code e VS Code. Construi esse framework que resolveu o meu problema e abri sob AGPL-3.0 para quem quiser usar.

---

## O que é

O Nemesis é um sistema de *enforcement* para fluxos de desenvolvimento assistido por LLM (Specification-Driven Development), escrito em Rust. Ele detecta e bloqueia padrões conhecidos de malware de supply-chain e de comandos destrutivos **antes da execução**. Tudo parte do **Pretool Hook**, que aciona, na mesma interceptação, as trilhas de segurança (Defender) e de qualidade (ast-linters); no Linux, uma camada eBPF no kernel atua como reforço adicional independente.

Não é um linter genérico. O foco é o contexto específico de desenvolvimento guiado por agentes de IA, onde um output aparentemente inócuo pode conter:

- Manipulação de manifests (`package.json`, `Cargo.toml`, `pyproject.toml`)
- *Decode-then-exec* de payloads codificados (base64/hex → `eval`/`exec`)
- Esteganografia Unicode (CVE-2021-42574, caracteres Bidi)
- Prompt injection em skills/comentários
- Exfiltração de credenciais
- Malware com *time-gating* e *self-cleaning*

O problema que motiva o projeto é real e atual: em 2025 foram publicados centenas de milhares de pacotes maliciosos no npm, e campanhas como Shai-Hulud comprometeram pacotes com bilhões de downloads semanais. O Nemesis ataca a janela em que esse código tenta executar na máquina do desenvolvedor.

---

## Como nasceu

O Nemesis não foi projetado numa prancheta de segurança. Ele cresceu de uma dor concreta e repetida dentro de projetos reais de produção (que não podem ser divulgados), e evoluiu em três fases:

**Fase 1 — Regras em markdown.** No início, eram apenas convenções escritas, dentro do ambiente da Windsurf, tentando conter os mesmos erros que apareciam sem parar: hooks condicionais, `setState` síncrono dentro de `useEffect`, uso de `any`, tipagens inline duplicadas, CSS manual fora do `tailwind.config`, lógica de negócio embutida em arquivos de UI. Esses anti-patterns surgiam independentemente da experiência do desenvolvedor humano ou da capacidade do modelo de IA. A lição que ficou: regra escrita é *input de contexto* — o modelo lê, entende o conceito abstrato, e ainda assim executa o padrão neural de "resolver rápido". Instrução não é enforcement.

**Fase 2 — De regra a hook.** Foi aí que o Nemesis virou código. As convenções em markdown que dependiam da boa vontade do modelo viraram hooks que rodam de fato e bloqueiam de fato. O primeiro salto concreto foi um **AST linter automático**: em vez de "por favor não use `any`", o sistema passou a analisar a árvore sintática e barrar o anti-pattern antes de entrar no repositório. Determinístico, não negociável.

**Fase 3 — Expansão para enforcement de segurança.** A partir do linter de qualidade, o escopo cresceu para o que o Nemesis é hoje: deny-list de comandos, scanner de conteúdo, detecção de supply-chain, e a camada eBPF no kernel. A mesma filosofia que barrava `any` passou a barrar `rm -rf` destrutivo e exfiltração de credenciais.

A linha que conecta as três fases — e que justifica a existência do projeto — é uma só: **as regras são rígidas porque a dor das violações foi real e recorrente.** Não nasceram de idealismo. Nasceram de falhas concretas que se repetiam quando faltava uma salvaguarda inegociável. O insight central, formulado já na Fase 1, é que regra como texto compete com o padrão neural do modelo e frequentemente perde; só o enforcement que roda *fora* da inferência — em compile-time, em lint-time, no PreToolUse, no kernel — fecha esse gap.

> **Nota de classificação honesta.** A camada de *governança de workflow* do Nemesis (a que orquestra como o agente trabalha) opera por engenharia de prompt e atinge, por estimativa do autor, ~80% de eficácia — porque ainda depende, em parte, da inferência probabilística do modelo. Já a camada de *enforcement* (deny-list, AST, eBPF) é determinística e não depende da cooperação do modelo. São coisas diferentes, e o documento as separa: a governança *guia*; o enforcement *obriga*.

---

## Por que existe

A função mais importante do Nemesis é prática e cotidiana: **impedir que um agente de IA execute, sem intenção, um comando que destrói o projeto** — um `rm -rf` no diretório errado, um `git reset --hard` que apaga trabalho não commitado, uma sobrescrita de arquivo de configuração. Quem programa com agentes LLM sabe que isso não é hipótese: o modelo, tentando "ajudar", roda um comando destrutivo porque interpretou mal o contexto. O Nemesis intercepta esse comando **antes** de ele rodar e exige confirmação humana explícita.

Isso vale tanto para o erro involuntário (o caso comum, e o mais valioso) quanto para o código malicioso (supply-chain, exfiltração). Modelos de linguagem operam por inferência probabilística, não por análise formal: pedir "por favor não rode comandos destrutivos" é uma instrução que o modelo pode ignorar ou contornar — e, como observado em testes reais, um agente pode tratar um bloqueio como obstáculo a rotear ao redor em vez de uma ordem.

A premissa do Nemesis é que *enforcement determinístico antes da execução* (PreToolUse + scanner de conteúdo + LSM no kernel) é categoricamente diferente de instrução probabilística. Não importa se o modelo foi convencido, enganado ou apenas errou: a camada bloqueia mesmo assim. Ferramentas reativas (linters, CI/CD, SAST) detectam **depois**; o Nemesis bloqueia **antes**. Isso não o torna perfeito — torna-o complementar a essas ferramentas, não substituto.

---

## Linha de autoridade

O coração do design é uma divisão clara do que a IA pode e não pode fazer:

- A IA opera com as **ferramentas nativas de escrita e edição** da IDE — é assim que ela trabalha. Mas só **dentro do scaffold do projeto** em desenvolvimento.
- A IA pode **ler** alguns arquivos sensíveis quando o trabalho exige, mas **não pode editar nem excluir** nenhum deles.
- **Exclusão, sobrescrita fora do escopo, reset, comando destrutivo: prerrogativa exclusivamente humana, não delegável.** O modelo opera; ele não destrói.

Essa fronteira não depende da boa vontade do modelo — é imposta pelas camadas de enforcement abaixo. O "zero incidente" em produção não acontece porque o modelo "se comportou", mas porque a arquitetura nunca lhe deu essa autonomia.

---

## Arquitetura — Tudo parte do Pretool

O **Pretool Hook é o ponto de entrada de todo o sistema** — é ele que intercepta a ação do agente antes da execução e dispara as verificações. **Sem o pretool, o Nemesis não funciona:** as duas trilhas que rodam acopladas a ele (Defender e ast-linters) só são acionadas porque o pretool as invoca. A camada eBPF é a única que opera fora dessa linha, no kernel, como reforço adicional para Linux.

| Camada | Relação com o Pretool | Onde atua | Mecanismo | Cobertura de SO |
|--------|-----------------------|-----------|-----------|-----------------|
| **Pretool / Posttool Hook** | **base — origem de tudo** | Antes de `Bash.run()` / file-write | Deny-list JSON + parser de workflow (exit code 2) | Windows, macOS, Linux |
| **Nemesis Defender** (content scanner) | **opera junto com o pretool** | Em file-write e em comandos | 6 layers de scanning + visitors | Windows, macOS, Linux |
| **ast-linters** (qualidade) | **opera junto com o pretool** | Em file-write de código | Visitors tree-sitter + `rules.toml` declarativo | Windows, macOS, Linux |
| **eBPF Kernel LSM** | **adicional/independente** | Syscalls no kernel | BPF LSM (`bprm_check_security`) | **Linux apenas** |

A leitura correta das relações:

- **Pretool + Defender** operam juntos: o pretool intercepta, o Defender escaneia o conteúdo do que está sendo escrito/executado e classifica malicious.
- **Pretool + ast-linters** operam juntos: na mesma interceptação de escrita de código, a trilha de qualidade analisa a árvore sintática e barra anti-patterns que quebram build/deploy.
- **eBPF é camada extra, só Linux.** Ela não depende do pretool — vive no kernel. Seu papel é segurar as pontas contra **comandos destrutivos** (e alguns malicious) caso o pretool falhe ou seja contornado: se o modelo tentar destruir algo, o kernel barra. Em macOS/Windows essa rede não existe, e a defesa fica nas trilhas do pretool.

### Pretool / Posttool Hook — a base de tudo

Intercepta comandos **antes** da execução (`PreToolUse`), valida contra `deny-list.json` e regras de escopo. Bloqueio é *hard-gate*: sem aprovação humana explícita, o fluxo não prossegue (exit code `2`). É a partir dele que as trilhas de Defender e de qualidade (ast-linters) são acionadas — por isso, **sem pretool, nada do resto roda.**

Há também um hook **`PostToolUse`** que roda **depois** da execução: ele nunca bloqueia (a ferramenta já rodou), mas escaneia o output gerado e registra violações em `output-audit.log`. Serve de auditoria e rede de detecção para o que passou.

E um `nemesis-pretool-fallback` que opera em **fail-closed**: se o binário esperado não existe (config quebrada, caminho errado), ele **bloqueia tudo** em vez de deixar passar. Segurança que falha fechando, não abrindo.

### Nemesis Defender — junto com o pretool

Acionado pelo pretool na interceptação, escaneia conteúdo de arquivos e de comandos por 6 layers independentes: AST (tree-sitter) → byte-level → regex → denylist → entropia → decoder recursivo (máx. 3 níveis). Os *visitors* cobrem os vetores de ataque catalogados (ver abaixo).

### ast-linters (qualidade) — junto com o pretool

Na mesma interceptação de escrita de código, o pretool aciona a trilha de qualidade: visitors tree-sitter + um motor declarativo (`rules.toml`) analisam a árvore sintática e barram anti-patterns que quebram build/deploy **antes** de o código entrar no repositório. Detalhada na seção [Camada de qualidade](#camada-de-qualidade-ast-linters).

### eBPF Kernel LSM — camada adicional (Linux)

A camada com mais "dentes" — bloqueia syscalls perigosas no kernel para processos dentro do cgroup do agente. **Diferente das trilhas acima, ela não depende do pretool:** vive no kernel e opera de forma independente. É uma **camada adicional de segurança** voltada a **comandos destrutivos** (e alguns malicious): se o pretool falhar ou for contornado e o modelo tentar destruir algo, o kernel ainda barra. **Importante:** existe apenas no Linux. Em macOS e Windows, a defesa se apoia nas trilhas do pretool (Defender + ast-linters). Estender essa profundidade extra a outros SOs é um objetivo aberto.

Em execução real (ver `violations.log`), esta camada registra bloqueios de `rm`, `shred`, `dd`, `truncate`, `kill`, `chmod`, `mount`, `nc` e execução de runtimes arbitrários (`python3`, `perl`), todos como `permission_denied` no kernel.

Syscalls bloqueadas atualmente (4): `mount`, `ptrace`, `kexec_load`, `delete_module` (retornam `EPERM`).

---

## Vetores de ataque cobertos (12)

> Esta lista representa os vetores **antecipados e implementados durante o desenvolvimento**. Não é uma lista exaustiva do espaço de ataque possível. Vetores fora desta lista podem não ser detectados.

| # | Visitor | Alvo |
|---|---------|------|
| 1 | `manifest_abuse` | postinstall/preinstall em manifests |
| 2 | `decode_exec` | base64/hex → `eval`/`exec`/`spawn` |
| 3 | `unicode_steg` | Bidi U+202E, PUA, homoglyphs (CVE-2021-42574) |
| 4 | `prompt_injection` | injeção via comentários/templates |
| 5a | `url_in_exec` | URL como argumento de exec |
| 5b | `time_gated` | `setTimeout`/condições de data |
| 6 | `dynamic_cmd` | concatenação de string → exec |
| 7 | `credential_harvest` | leitura de `~/.ssh`/`~/.aws`/`.env` + exfil |
| 8 | `self_clean` | `fs.unlink(__filename)` |
| 9 | `manifest_scanner` | supply-chain em 7 formatos de manifest |
| 10 | `kubernetes_escape` | container breakout |
| 11 | `mount_api_abuse` | syscalls de mount (428–432) |
| 12 | `llm_output_injection` | XSS/SSRF/command injection em output de LLM |

A deny-list do Defender contém atualmente ~402 patterns em 35 categorias. **Patterns são, por natureza, uma lista do que já foi antecipado** — aumentam o custo de um ataque conhecido, mas não cobrem o desconhecido.

---

## Tudo é configurável — e só por humano

Este é um princípio central do design: **não há regra hardcoded.** Os hooks são agnósticos e canônicos — se um padrão está na deny-list, é bloqueado; se não está, passa. Não existe lógica de decisão escondida no código do hook.

Na prática, isso significa que:

- Qualquer vetor, regex ou regra pode ser **desativado, relaxado ou customizado** editando os arquivos de deny-list.
- **Ampliar a cobertura** (adicionar um novo vetor) é adicionar uma entrada na deny-list, não recompilar lógica.
- Apenas um **humano** pode fazer essas mudanças. O modelo de IA não tem autoridade para alterar a própria gaiola — os arquivos de configuração estão sob `absolute_block`.

Há duas exceções, que exigem conhecimento mais profundo:

- A camada **eBPF** tem sua própria lista de syscalls/binários, atrelada à arquitetura (definida no `Cargo.toml` do módulo de kernel).
- Os **visitors do Nemesis Defender** são código Rust de análise (AST, decoder, etc.). Ampliá-los ou relaxá-los exige conhecimento de Rust e segurança — diferente das deny-lists, que são simples de ajustar.

---

## Controle de paths — quem pode ler/editar o quê

O arquivo `denylist-folder-files.json` define, sob controle exclusivamente humano, o que o agente de IA pode tocar. É aqui que vive a "linha de autoridade" na prática, em dois níveis:

- **`absolute_block`** — bloqueio total (leitura + escrita + deleção). Inclui segredos e configuração sensível: `.env`, `.env.production`, `.ssh/id_rsa`, `.ssh/authorized_keys`, `.bashrc`/`.zshrc`, os arquivos de settings/hooks de cada IDE (`.claude/`, `.cursor/`, `.windsurf/`, etc.) e o próprio diretório `.nemesis/`.
- **`write_block`** — leitura permitida, escrita/edição bloqueada. Inclui manifests e configs que a IA precisa consultar mas não deve alterar: `package.json`, `next.config.js`, `eslint.config.mjs`, `.gitignore`, e os logs do Nemesis.
- **`allowed_exceptions`** — o scaffold liberado (ex.: `/src/`), onde o agente tem liberdade de escrita e edição.

O ponto crítico: **só um humano comuta essas permissões.** Precisa relaxar uma restrição para uma manutenção? O bypass é humano e explícito. O agente nunca promove a si mesmo. E, independente de qualquer permissão de leitura/escrita concedida, **comando destrutivo (deletar, sobrescrever fora do escopo, reset) permanece sempre proibido para a IA.**

---

## Camada de qualidade (AST-linters)

A primeira versão do Nemesis nasceu como controle de qualidade de código. Na evolução de Node/TS para Rust, o foco virou **100% segurança** — e a camada de qualidade foi reduzida ao que **afeta ou pode afetar segurança e estabilidade**: exposição de API/credenciais, aninhamento de tags que quebra build/deploy, e falhas graves que derrubam a aplicação.

Essa camada passou por uma reformulação recente e hoje está **operante**, acionada pelo pretool na escrita de código, com foco especial na stack **frontend Next.js / React / TypeScript** — exatamente onde os anti-patterns que quebram build/deploy mais aparecem. O motor de regras é **declarativo** (`rules.toml`): cada regra define os nós tree-sitter que detecta, e o bloqueio acontece no momento da escrita, não depois que o código já entrou no repositório. A cobertura inclui `any` (explícito, em alias, em parâmetro, em assertion), hooks fora do topo / condicionais, dependências incompletas de `useEffect`, promises não tratadas, JSX sem `key`, `dangerouslySetInnerHTML`, atribuição/comparação inseguras, além das regras por linguagem abaixo.

Existem deny-lists de qualidade **específicas por linguagem**. O campo `rule` — que apontava para um arquivo de regra `.md` específico do ambiente do autor — vem **em branco** nas deny-lists distribuídas: assim cada usuário aponta para a própria documentação de regras, sem herdar caminhos que só existiam no ambiente original. As categorias cobertas:

- **Rust** — chain de 3+ `unwrap()`, `unsafe` block em library code, `panic!()`/`process::exit()` em lib, `println!` em lib.
- **Python** — `eval()`, `exec()`, `pickle.loads()`, `os.system()`/`shell=True`, f-string com SQL, `yaml.load()` inseguro, MD5.
- **Java** — `Runtime.exec()`/`ProcessBuilder`, reflection dinâmica, SQL por concatenação, deserialização (`ObjectInputStream`).
- **Go** — `unsafe.Pointer`, `panic()` em função pública, `defer` sem checagem de erro, SQL via `Sprintf`.
- **Genérico** — credenciais hardcoded (OWASP A02), arquivos de secrets, debug output, `TODO`/`FIXME`.

**Importante, e dito sem rodeio:** esta camada (`ast-linters`) está **operante** e foi validada contra pentests (estáticos e por agente real), mas **continua evoluindo** — gaps conhecidos ficam registrados como pontos de melhoria. E ela **não substitui ESLint ou Biome.** É um complemento de bloqueio em tempo de execução, não um linter completo. Use suas ferramentas de lint normais; o Nemesis apenas adiciona uma barreira de bloqueio, no momento da escrita, para o subconjunto que toca build/deploy, segurança e estabilidade — com foco na stack frontend Next/React/TypeScript.

---

## Como o Defender age — e por que ele é perigoso

Esta seção é a mais importante para quem vai instalar. Leia inteira.

O **Nemesis Defender** não apenas avisa: ele **age**. Quando detecta um arquivo com violação grave — credencial exposta, script com comando destrutivo embutido, anti-padrão de segurança sério — ele pode **remover o arquivo infrator** (`rm -rf`). Isso intercepta tanto a IA quanto, no Linux com eBPF, o próprio humano.

**O cenário real que você precisa entender:** ao instalar o Nemesis em um projeto que **não** foi desenvolvido sob ele, esse projeto provavelmente já contém violações acumuladas. Na primeira varredura, o Defender encontrou e removeu **24 arquivos** de um projeto assim — porque continham exatamente o que ele existe para barrar. Não foi bug; foi o sistema fazendo o trabalho dele.

Duas consequências práticas:

- **Se o projeto está versionado (Git):** os arquivos removidos continuam no controle de versão / source control da IDE. Você recupera.
- **Se o projeto NÃO está versionado:** a perda é definitiva. Por isso, **backup antes de instalar, sempre.**

**Por que não há uma pasta de quarentena?** Mover infratores para `quarantine/` em vez de remover seria mais suave, e é uma melhoria reconhecida no roadmap. Mas a decisão de design atual é deliberada: quem desenvolve **sob** o Nemesis desde o início nunca chega a ter esses arquivos — o código nasce limpo, porque o Defender bloqueia a violação no momento da escrita. A dureza na instalação é o preço de um sistema que existe para forçar disciplina, não para administrar bagunça pré-existente.

**O Nemesis é um harness, não só um escudo.** Ele intercepta operações destrutivas e inseguras **independentemente da origem — IA ou humano.** No Linux, a camada eBPF impede até você, no terminal, de rodar um `rm -rf` (porque humano também é alvo de engenharia social). Para deletar algo no Linux sob o Nemesis, você precisa fazê-lo manualmente pela própria IDE/gerenciador de arquivos — uma fricção intencional, que evita tanto o ataque quanto o acidente (o clássico comando errado no terminal que apaga o que não devia). Em macOS e Windows, sem eBPF, o humano mantém liberdade total no terminal; a proteção se concentra nas ações da IA.

O efeito colateral pretendido: quem usa o Nemesis no desenvolvimento **passa a escrever código de qualidade e seguro** — não por escolha, mas porque a alternativa é ser bloqueado. Ele é um balizador. Se você segue as regras, é um aliado. Se pisa fora da borda da caixa, ele pune. É por isso que se chama Nemesis.

---

## Componentes legados (funcionam, mas precisam de melhorias)

Por honestidade técnica, dois componentes históricos seguem no código, funcionais, mas obsoletos e fora do foco atual:

- **Auto-harvest** (`nemesis-harvest`). Foi um salto importante na evolução: o sistema lia o `node_modules`, detectava a stack do projeto e as regras de ESLint/Biome instaladas, e **se auto-municiava** — convertia essas regras em patterns, gerando deny-lists automaticamente (inicialmente gerava regras em markdown; depois, deny-lists JSON). Hoje está **desatualizado e precisa de melhorias**, mas ainda funciona. Não é o foco no momento, porque a arquitetura atual já opera bem com as deny-lists JSON em `config/` — os módulos (incluindo o ast-linter) consultam essas listas para bloquear ou liberar: se há regex/regra para o padrão, decide; se não há, passa.

- **`nemesis-install` (CLI).** Criado para instalar o Nemesis via linha de comando, detectando a IDE e gerando as configs de hooks. **Funciona, mas ficou desorganizado e não teve continuidade** — a instalação hoje é mais confiável feita manualmente (build + configuração de caminho, como descrito em [Instalação](#instalação-e-requisitos)). É um ponto de retomada futura, não uma via recomendada agora.

Documentá-los como legados é proposital: um projeto de segurança honesto declara o que está maduro e o que não está.

---

## Validação

A validação do Nemesis se apoia em três tipos de evidência, da mais forte para a mais fraca. Esta ordem é deliberada: a evidência que mais importa é a que mais se parece com o uso real.

### 1. Track record em produção (evidência mais forte)

O Nemesis nasceu dentro de projetos reais de produção (que não podem ser divulgados) e roda há aproximadamente **um ano e meio** em desenvolvimento ativo do dia a dia, com agentes LLM operando sobre o código. Nesse período, **nenhum agente executou um comando destrutivo nem acessou arquivo sensível para edição/exclusão sem permissão.** Isso não é teste de laboratório — é a única forma de evidência que reflete o caso de uso real: um desenvolvedor trabalhando com um agente que, eventualmente, tenta rodar algo destrutivo por engano. É a função-núcleo do Nemesis, e é a parte mais validada do sistema.

Em resumo direto: o Nemesis **resolveu e resolve um problema real** — protegeu o ambiente de desenvolvimento do autor por um ano e meio, em produção, com projetos reais. Essa proteção foi corroborada por duas frentes de teste: **pentests estáticos contra os próprios binários** (resultados satisfatórios) e **pentests reais executados por agentes LLM** — que provam, na prática, que modelos de linguagem *podem* ser manipulados a executar atividade hostil e maliciosa, e que mesmo assim o enforcement do Nemesis segura. A proteção **não é 100%**: os gaps abertos são vetores ainda não contemplados, e os gaps já conhecidos ficam registrados como pontos de melhoria (especialmente agora, em open source). Mas a proteção mais importante para o ambiente de desenvolvimento de *qualquer* dev — **impedir que o ambiente seja destruído por comandos destrutivos** — é justamente a função-núcleo, e a mais validada.

### 2. Execução adversarial por agente real

Em sessões registradas em dois ambientes (Windsurf no Linux e no macOS, Cursor), agentes de IA receberam suítes de ataque disfarçadas de "scaffolding de projeto" e tentaram executá-las tarefa por tarefa — comandos destrutivos, exfiltração de credenciais, supply-chain, prompt injection, leitura/escrita em diretórios protegidos. O Nemesis bloqueou cada tarefa **no ponto de execução** (no `Write`, no comando aceito pelo agente), com mensagens de bloqueio específicas por categoria. Os logs dessas sessões estão versionados no repositório (`Feature-Documentation/PENTEST-NEMESIS/`).

Este é o teste correto da tese do Nemesis: ele assume que o modelo pode ser enganado, e mede se o enforcement segura mesmo assim. Nesses logs, segurou.

**Mensagens de bloqueio padronizadas.** Toda interceptação emite uma de seis mensagens fixas e categorizadas, para que o agente — e o humano — saiba exatamente *por que* foi bloqueado. As cinco primeiras são da trilha de **segurança** (pretool/posttool/Defender/eBPF); a última é da trilha de **qualidade** (ast-linters). Quando útil, a mensagem traz o alvo no fim (`· arquivo` ou `· comando`).

| Categoria | Mensagem |
|-----------|----------|
| Comando bloqueado | `NEMESIS SEC - COMANDO NAO PERMITIDO` |
| Escrita em arquivo/path protegido | `NEMESIS SEC - ACESSO NEGADO - ARQUIVO PROTEGIDO` |
| Leitura de arquivo protegido | `NEMESIS SEC - LEITURA NEGADA - ARQUIVO PROTEGIDO` |
| Conteúdo malicioso no arquivo | `NEMESIS SEC - CONTEUDO MALICIOSO DETECTADO` |
| Escrita fora do escopo/workflow | `NEMESIS SEC - ESCRITA FORA DO ESCOPO PERMITIDO` |
| Violação de padrão de código | `NEMESIS QUALITY - PADRAO DE CODIGO NAO PERMITIDO ANALISAR REGRAS!` |

### 3. Suíte de vetores sintéticos (evidência de apoio)

O Nemesis inclui uma suíte de **140 vetores autorais** (M1–M20: comandos compostos, exfiltração, reverse shells, persistência, obfuscação, supply-chain multi-ecossistema, etc.). Sobre ela, sendo honesto:

- **O que ela cobre:** os vetores que a maioria dos desenvolvedores de fato encontra — `rm -rf` destrutivo, `curl | bash`, postinstall malicioso, exfiltração de `.env`/chaves. Não são vetores exóticos; são os comuns, que é onde o dano real acontece.
- **O que ela NÃO prova:** completude ou invulnerabilidade. É uma suíte escrita pelo autor; passar nela é o piso esperado, não um diferencial. Cobertura é parcial por definição — vetores não imaginados durante o desenvolvimento podem não ser detectados.

### Os logs: as camadas operando de forma registrada

Os logs de runtime do Nemesis (`violations.log`, `defender.log`) mostram as camadas trabalhando de forma separada e registrada, em execução real. A trilha de segurança (Defender) é acionada pelo pretool; a eBPF opera no kernel de forma independente:

- **eBPF / kernel (adicional, Linux)** — `violations.log` registra mais de 2.000 bloqueios reais com `"layer":"ebpf"`, `"type":"permission_denied"`, cobrindo `rm`, `shred`, `dd`, `truncate`, `kill`, `chmod`, `mount`, `nc`, e a execução de runtimes arbitrários (`python3`, `perl`). Estes são bloqueios no kernel, não dependentes de deny-list em userspace.
- **Defender / classificador (junto com o pretool)** — `defender.log` registra vereditos de classificação nomeados (ex.: `[MALICIOUS] ... denylist-defender / reverse_shells`), com a evidência capturada (`bash -i >&`, `/dev/tcp/`) e a instrução de correção.
- **Correlação e escalação** — o Defender também correlaciona eventos ao longo do tempo: detecta brute force ("N tentativas maliciosas bloqueadas em 300s") e padrões compostos ("leitura de arquivo sensível seguida de comando de rede"). Isso é detecção comportamental, acima do casamento de padrão simples.

Nota sobre medir via script CLI: ao rodar a suíte por um harness que usa `node`/`python3` para montar payloads, a camada eBPF bloqueia o próprio runtime do harness — o que é o comportamento correto e desejado, mas significa que, nesse cenário, o bloqueio é registrado como `permission_denied` da eBPF e não exercita isoladamente o classificador do Defender. As camadas são complementares: na prática, um ataque que passe por uma é candidato a ser pego por outra.

### Evidência de valor real: um bypass encontrado e corrigido

A evidência mais útil de robustez não veio dos testes próprios — veio de um adversário real. Durante stress-testing, um agente de IA contornou o pretool (a trilha de deny-list/regex): após uma manutenção em que se esqueceu de readicionar comandos à deny-list, o regex de extração de paths deixou comandos fora da lista passarem sem verificação. O gap foi identificado, os comandos readicionados, e o vetor refechado.

O que esse incidente mostra, e por que ele é positivo:

1. **O pretool (regex/deny-list) é contornável quando a deny-list está incompleta** — confirmado empiricamente. Esperado para qualquer sistema baseado em lista.
2. **No Linux, a camada eBPF é a rede de segurança** — opera no kernel, independente da deny-list.
3. **O processo de manutenção da deny-list é um ponto de atenção** — o gap surgiu de uma manutenção, não de uma falha de design. Mitigação: testes de regressão que rodam após cada alteração da lista.

Mais importante: este projeto trata bypasses encontrados como o ativo mais valioso de validação, não como vergonha a esconder. Se você encontrar um, veja [Disclosure](#segurança-e-disclosure).

---

## Modelo de ameaça e limitações

**O Nemesis foi projetado para mitigar:**

- **Comandos destrutivos executados por agentes LLM por engano** — `rm -rf`, `git reset --hard`, sobrescrita de configs, exclusão de arquivos sem confirmação (a função-núcleo, e a mais validada)
- Malware de supply-chain via manifests (npm, Cargo, PyPI, RubyGems, Composer, setuptools, lockfiles)
- Payloads ofuscados (encoding, Unicode, time-gating) em código gerado/instalado
- Exfiltração de credenciais e prompt injection em fluxos SDD

**O Nemesis NÃO protege contra (entre outros):**

- **Vetores não contemplados.** Tudo que não está na lista de visitors/patterns pode passar.
- **Bypass das camadas 1–2 fora do Linux.** Sem eBPF, a defesa é deny-list/regex, contornável por um atacante competente que opere dentro do permitido ou explore lacunas de pattern.
- **Reverse engineering do binário.** O binário distribuído pode ser desmontado e analisado.
- **Atacante com privilégios de root** capaz de descarregar o daemon/eBPF (no Linux, o próprio eBPF mitiga parte disso, mas não é absoluto).
- **Ataques fora do escopo de "command/file/manifest"** — rede em runtime, ataques de cadeia de build complexos, ou lógica maliciosa que não casa com nenhum pattern.

O Nemesis **complementa** SAST, linters e CI/CD; não os substitui.

---

## Como se compara ao que já existe

Por honestidade: a técnica central do Nemesis tem prior art maduro, e isso não diminui o projeto — situa ele.

- **eBPF/LSM para enforcement de processo/arquivo/syscall** é consolidado no mundo cloud-native (KubeArmor, Tetragon/Cilium, Falco). A camada eBPF do Nemesis aplica a mesma classe de técnica.
- **Guardrails para agentes LLM** é categoria estabelecida: LlamaFirewall, LLM Guard, NeMo Guardrails, Lakera Guard, Guardrails AI, entre outros.
- **Enforcement determinístico em runtime** é também tema de pesquisa ativa (ex.: AgentSpec, ICSE '26).

**O recorte específico do Nemesis** — máquina de desenvolvimento *local*, agnóstico de IDE, interceptando comandos do coding agent **e** escaneando supply-chain no momento do install, empacotado para o desenvolvedor individual — é menos coberto pelas opções acima, que tendem a focar em cloud/Kubernetes ou no gateway de LLM. É um nicho real, não um espaço vazio.

---

## IDEs suportadas

A biblioteca Rust (`nemesis-defender`) é agnóstica de IDE. Cada IDE contribui hooks que invocam os binários: Claude Code, Codex, Cursor, VS Code (via pretool), Windsurf, OpenClaude.

---

## Instalação e requisitos

> **Antes de tudo: faça backup do projeto.** Veja o aviso no topo deste documento. Em um projeto pré-existente com código que viola as regras, o scanner pode remover arquivos infratores na primeira execução.

### Requisitos mínimos

**Hardware:** o Nemesis é leve em CPU/RAM no dia a dia (os hooks rodam por evento, em milissegundos). O custo real é de disco e build: compilar o workspace Rust exige espaço e tempo de compilação. Recomendado: 4 GB de RAM livres para o build, ~2 GB de disco para toolchain + binários. Em uso normal, o daemon de filesystem consome pouco.

**Software:** Rust 1.70+ e Cargo (toolchain estável). Clang/LLVM para compilar o core. Em projetos JS/TS, Node disponível para o harvest legado (opcional — veja abaixo).

**Kernel / eBPF (camada adicional, Linux):** kernel Linux **5.8+** com **BPF LSM habilitado**. Em muitas distros o BPF LSM não vem ligado por padrão e precisa ser adicionado na linha de comando do kernel (GRUB: `lsm=...,bpf`), com reboot. Sem isso, a camada eBPF não carrega — e o Nemesis opera com as trilhas do pretool (Defender + ast-linters).

**Sistema operacional por camada:**

| Camada | Linux | macOS | Windows |
|--------|:-----:|:-----:|:-------:|
| 1 — Pretool/Posttool Hook | ✅ | ✅ | ✅ |
| 2 — Defender (scanner) | ✅ | ✅ | ✅ |
| 3 — eBPF Kernel LSM | ✅ | ❌ | ❌ |

No Linux você tem todas as camadas, incluindo a proteção de kernel (eBPF) que vale **inclusive contra você mesmo** no terminal. Em macOS e Windows, sem eBPF, você opera com as trilhas do pretool (Defender + ast-linters) — e o humano mantém liberdade total de comandos destrutivos no terminal (a proteção ali se aplica às ações da IA via hooks da IDE).

### Build

```bash
cd .nemesis
cargo build --release --workspace
# Gera os binários em .nemesis/target/release/
```

### Configuração obrigatória — o Nemesis NÃO é plug-and-play

Esta é a parte que mais gera confusão, então seja claro consigo mesmo: **o Nemesis só funciona se você configurar o caminho corretamente.** Os hooks de pre/post-tool de cada IDE (`settings.json`, `hooks.json`, conforme a IDE) precisam apontar para o **caminho absoluto do binário** do Nemesis no seu projeto. Se o caminho estiver errado ou ausente, a IDE não invoca o hook e **o Nemesis simplesmente não roda** — você fica desprotegido sem perceber.

Por isso há um `nemesis-pretool-fallback` que opera em **fail-closed**: se o binário esperado não for encontrado, ele **bloqueia tudo** em vez de deixar passar. É proteção contra config quebrada, mas o correto é configurar o caminho certo desde o início.

Isso exige conhecimento técnico mínimo — lógica de programação e noção de caminhos de arquivo. Não é um defeito; é a natureza de uma ferramenta de segurança. Configurá-la errado e depois dizer que "o Nemesis é complicado" é como culpar o cinto de segurança por não estar afivelado.

### Comandos úteis

```bash
# Escanear um arquivo
nemesis-defender --scan /caminho/arquivo.rs

# Iniciar / parar o daemon (filesystem watcher)
nemesis-defender --ensure-daemon
nemesis-defender --stop

# Instalar hook de shell
nemesis-defender --install-shell-hook

# Validar arquivo / testar escopo
nemesis-validate /caminho/arquivo.ts
nemesis-scope   /caminho/arquivo.rs

# Ver violações recentes
tail -20 .nemesis/logs/violations.log | jq .
```

---

## Princípios de design

- **Defense in depth** — nenhuma camada confia em si mesma como única linha.
- **Sem regra hardcoded** — os hooks são agnósticos e canônicos: o que está na deny-list é bloqueado, o que não está passa. Toda customização é por configuração, sob controle humano.
- **Human override explícito** — o LLM não toma a decisão final; bloqueios exigem consentimento humano, e só humano comuta permissões de path.
- **Rust** — memory safety e type safety para o código de enforcement.
- **Agnóstico de IDE** — roda em qualquer IDE que exponha hooks.
- **Validação empírica e contínua** — cobertura é tratada como incompleta por padrão e expandida conforme novos vetores aparecem.

> **Sobre workflow de desenvolvimento.** Versões antigas do Nemesis incluíam um enforcement de workflow sequencial (`.nemesis/workflow-enforcement/`) que funcionava como um harness de SDD: cada fragmento do fluxo só era liberado quando o anterior havia sido executado, porque os modelos não liam as regras, pulavam etapas e isso introduzia dívida técnica no projeto em desenvolvimento. Depois que o Nemesis amadureceu, passei a usar **skills SDD apenas para criar spec e planos** em tarefas que dependem de IA — porque, na maioria dos casos, o desenvolvimento é humano e a IA é assistente. Então relaxei o harness sequencial. **O módulo continua no código** e pode ser usado para automatizar alguma tarefa quando fizer sentido. **Importante:** processo de desenvolvimento é de cada equipe — não é uma regra do Nemesis. O que o Nemesis impõe é o enforcement de segurança e qualidade (AST + deny-list + eBPF + pretool/posttool), que permanece ativo independentemente do fluxo de trabalho adotado.

---

## Segurança e disclosure

Bypasses e vetores não cobertos são **esperados** e **bem-vindos**. Se você encontrar uma forma de contornar qualquer camada do Nemesis, **não abra uma issue pública** — siga o processo do [`SECURITY.md`](SECURITY.md) e reporte em privado para `feryamaha@hotmail.com`. Cada bypass reportado vale mais para a robustez do projeto do que qualquer teste interno.

Não há recompensa formal no momento — apenas crédito público (salvo se preferir anonimato) e a gratidão de tornar isto melhor.

Para contribuir com código, veja o [`CONTRIBUTING.md`](CONTRIBUTING.md). O projeto adota o **Developer Certificate of Origin (DCO)**: assine seus commits com `git commit -s`.

---

## Licença

Distribuído sob a **GNU Affero General Public License v3.0 (AGPL-3.0)** (veja [`LICENSE`](LICENSE)). Você pode usar, estudar, modificar e redistribuir o Nemesis Defender livremente — mas, sob a AGPL, **qualquer trabalho derivado ou serviço oferecido a partir dele deve ter seu código-fonte aberto sob a mesma licença**, inclusive quando o software é oferecido pela rede (como SaaS). Isso impede que terceiros peguem o código, fechem e o explorem comercialmente sem devolver as modificações à comunidade.

O copyright integral do código original permanece com o autor.

**Licenciamento dual / comercial.** Como autor e único detentor do copyright, ofereço **licenças comerciais separadas** para quem deseje usar o Nemesis Defender sem cumprir as obrigações da AGPL-3.0 (por exemplo, integrar em um produto proprietário fechado). Para licenciamento comercial, contate **feryamaha@hotmail.com**.

---

## Status do projeto

Em desenvolvimento ativo por um único mantenedor. A API, a deny-list e a cobertura de vetores mudam com frequência. Trate como software jovem: leia o código antes de confiar nele em produção.

Mantenedor: [@feryamaha](https://github.com/feryamaha)

---

*Nemesis Defender — defense in depth, enforcement determinístico, validação honesta. Não é mágica; é engenharia em camadas, com limites declarados.*