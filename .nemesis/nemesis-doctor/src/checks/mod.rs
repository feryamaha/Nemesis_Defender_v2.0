//! Orquestracao e helpers compartilhados dos checks.

pub mod compile;
pub mod daemon;
pub mod ebpf;
pub mod inventory;
pub mod pentest;
pub mod scaffold;
pub mod unit_tests;

use crate::report::CheckResult;
use std::path::PathBuf;

/// Diretório `.nemesis/`, resolvido subindo do binário até o ancestral chamado `.nemesis` —
/// robusto para AMBOS os layouts (NÃO assume profundidade fixa):
///   dev:    .nemesis/target/release/nemesis-doctor → ancestral `.nemesis`
///   distro: .nemesis/bin/nemesis-doctor            → ancestral `.nemesis`
/// (Mesma estratégia de `pid::pid_path` / `violations_log::ledger_path`. O antigo parent-walk de
///  profundidade fixa, calibrado para o layout dev, OVERSHOOTAVA no distro — passava da raiz do
///  projeto — e o doctor reportava "Nenhum layout de binarios encontrado" mesmo com `.nemesis/bin/`.)
pub fn nemesis_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        for anc in exe.ancestors() {
            if anc.file_name().map(|n| n == ".nemesis").unwrap_or(false) {
                return anc.to_path_buf();
            }
        }
    }
    // Fallback (resolução pelo binário falhou): ancora em `.nemesis` relativo ao CWD.
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".nemesis")
}

/// Raiz do projeto = diretório que contém `.nemesis/`.
pub fn project_root() -> PathBuf {
    nemesis_dir()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// Diretório onde os binários REALMENTE estão, resolvendo o layout (distro `.nemesis/bin/` tem
/// precedência sobre build da fonte `.nemesis/target/release/`). `None` se nenhum existe.
/// Fonte única para G3 (inventário), G4 (scaffold) e G6 (ação do daemon) — evita o laudo errado
/// em que o doctor procurava o binário só em `target/release` e falhava no layout distro.
pub fn binaries_dir() -> Option<PathBuf> {
    let bin = nemesis_dir().join("bin");
    if bin.is_dir() {
        return Some(bin);
    }
    let release = nemesis_dir().join("target").join("release");
    if release.is_dir() {
        return Some(release);
    }
    None
}

/// Caminho COPIÁVEL (relativo a `.nemesis/`) de um binário no layout ativo, para mensagens de
/// ação. Distro → `.nemesis/bin/<bin>`; fonte → `.nemesis/target/release/<bin>`. Sem layout
/// detectado, assume o distro (caminho do instalador).
pub fn binary_action_path(bin: &str) -> String {
    let sub = if nemesis_dir().join("bin").is_dir() {
        "bin"
    } else {
        "target/release"
    };
    format!(".nemesis/{}/{}", sub, bin)
}

/// Verifica se um comando existe no PATH via `<cmd> --version`.
pub fn command_exists(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Executa todos os checks na ordem definida.
pub fn run_all(quick: bool) -> Vec<CheckResult> {
    use crate::report::CheckStatus;
    let mut results = Vec::new();

    if !quick {
        results.push(compile::run());
        results.push(unit_tests::run());
    } else {
        results.push(
            CheckResult::new("G1 - Compilacao")
                .status(CheckStatus::Skip)
                .line("Pulado (--quick)."),
        );
        results.push(
            CheckResult::new("G2 - Testes unitarios")
                .status(CheckStatus::Skip)
                .line("Pulado (--quick)."),
        );
    }

    results.push(inventory::run());
    results.push(scaffold::run());
    results.push(ebpf::run());
    results.push(daemon::run());

    if !quick {
        results.push(pentest::run());
    } else {
        results.push(
            CheckResult::new("G7 - Pentest Red-Team")
                .status(CheckStatus::Skip)
                .line("Pulado (--quick)."),
        );
    }

    results
}
