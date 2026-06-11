//! DefenderReport — logging consolidado no ledger único.
//!
//! O antigo `defender.log` (verboso, write-only, gravado em `logs/` RELATIVO ao CWD) foi
//! DESCONTINUADO. Problemas que ele causava:
//!   - poluía a raiz do projeto com `logs/defender.log` (CWD-relativo);
//!   - sendo escrito na raiz observada pelo daemon, era RE-ESCANEADO — e como contém as
//!     strings de evidência das detecções (nomes de visitor, trechos de payload), casava
//!     padrões e era quarentenado/deletado pelo próprio daemon (falso-positivo + loop).
//!
//! Hoje todo bloqueio vai para o ledger único `.nemesis/logs/nemesis-violations.log`
//! (ver `violations_log`). Estas funções permanecem por compatibilidade com os call-sites
//! (daemon, `--scan`), sem reintroduzir o arquivo legado.

use crate::DefenderResult;

/// No-op: o registro real do bloqueio é feito no ledger unificado (pelo daemon, no ponto
/// da quarentena). `--scan` é uma checagem manual e não deve poluir a telemetria.
pub fn log_result(_result: &DefenderResult) -> std::io::Result<()> {
    Ok(())
}

/// Escalação comportamental (correlação multi-turn) — registrada no ledger unificado.
pub fn log_escalation(message: &str) -> std::io::Result<()> {
    crate::violations_log::append(
        "nemesis-defender",
        &format!("NEMESIS SEC - ESCALACAO COMPORTAMENTAL · {}", message),
    );
    Ok(())
}
