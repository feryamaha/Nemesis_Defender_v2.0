# Contribuindo para o Nemesis Defender

Obrigado por se interessar em contribuir com o Nemesis Defender! Este é um projeto focado em segurança e governança determinística para desenvolvimento com IA. Para manter a robustez do software, seguimos diretrizes estritas de desenvolvimento.

## Configuração do Ambiente de Desenvolvimento

O Nemesis é escrito principalmente em Rust. Para começar, você precisará de:

* Rust (mínimo v1.70) e Cargo
* Clang/LLVM (necessário para a compilação do core)
* Ambiente Linux (caso queira modificar ou testar a Camada 3 de eBPF/LSM)

### Clonando e Buildando o Projeto

Para clonar e buildar, rode os comandos normais de clone do git e depois:

```bash
cargo build --release --workspace
```

## Como Rodar os Testes

Nenhuma alteração de código será aceita se quebrar a suíte de testes existente. Antes de abrir um Pull Request, execute:

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```

## Padrões de Código

* **Segurança em primeiro lugar:** código `unsafe` deve ser evitado ao máximo e precisa de justificativa explícita documentada em comentário.
* **Agnóstico de IDE:** toda lógica nova adicionada à biblioteca `nemesis-defender` deve permanecer agnóstica de plataforma ou editor de código.
* **Testes de regressão:** se você corrigiu um bug ou um bypass, inclua um caso de teste sintético que cubra esse cenário para evitar regressões futuras.

## Processo de Pull Request (PR)

1. Faça um fork do repositório e crie sua branch a partir da `main`.
2. Garanta que todos os testes passaram localmente.
3. Certifique-se de que sua alteração está documentada.
4. Abra o PR com uma descrição clara do problema que você está resolvendo e do impacto na segurança/performance do framework.

## Reporte de Falhas de Segurança

**Aviso importante:** se a sua contribuição for a descoberta de uma falha de segurança crítica ou um bypass explorável, **não abra um PR público**. Siga o processo descrito no arquivo [SECURITY.md](SECURITY.md).

## Licença das Contribuições (DCO)

Ao enviar uma contribuição para este projeto, você concorda que:

1. Sua contribuição será licenciada sob a mesma licença do projeto (**GNU AGPL v3.0**).
2. Você certifica a origem do código que está enviando, conforme o **Developer Certificate of Origin (DCO)** — ou seja, declara ter o direito de submeter esse código sob a licença do projeto.
3. Você concede ao autor/mantenedor o direito de também licenciar sua contribuição sob **licença comercial separada** (licenciamento dual). Isso é necessário porque o projeto mantém a opção de licenciamento comercial, e contribuições sob AGPL pura impediriam o mantenedor de relicenciar. Ao contribuir, você concorda com essa concessão.

Para certificar, adicione a linha `Signed-off-by: Seu Nome <seu@email.com>` ao final de cada commit (use `git commit -s` para fazer isso automaticamente).

Isso mantém a base de código legalmente limpa e garante que toda contribuição pode ser integrada e mantida sem ambiguidade de direitos.