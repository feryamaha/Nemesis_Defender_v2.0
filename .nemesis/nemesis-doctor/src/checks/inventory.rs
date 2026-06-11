use crate::checks::nemesis_dir;
use crate::report::{CheckResult, CheckStatus};

// Build da fonte (cargo): todos os binários, incluindo windows e eBPF.
const SOURCE_BINARIES: &[&str] = &[
    "nemesis-pretool-check",
    "nemesis-pretool-check-unix",
    "nemesis-pretool-check-windows",
    "nemesis-pretool-hook",
    "nemesis-posttool-check-unix",
    "pre-edit-hook",
    "debug-hook-env",
    "nemesis-lsp",
    "nemesis-defender",
    "nemesis-ebpf-daemon",
    "nemesis-cgroup-watcher",
];

// Distribuição por binários (install.sh → .nemesis/bin/): CORE cross-platform.
// Sem windows e sem eBPF (Linux-only, opt-in, construído da fonte).
const DISTRO_BINARIES: &[&str] = &[
    "nemesis-pretool-check",
    "nemesis-pretool-check-unix",
    "nemesis-pretool-hook",
    "nemesis-posttool-check-unix",
    "pre-edit-hook",
    "debug-hook-env",
    "nemesis-lsp",
    "nemesis-defender",
    "nemesis-doctor",
];

pub fn run() -> CheckResult {
    let mut res = CheckResult::new("G3 - Inventario de binarios");

    let bin = nemesis_dir().join("bin");
    let release = nemesis_dir().join("target").join("release");

    // Detecta o layout: distribuição (.nemesis/bin/) tem precedência sobre build da fonte.
    let (dir, expected, layout) = if bin.is_dir() {
        (bin, DISTRO_BINARIES, "distribuicao (.nemesis/bin/)")
    } else if release.is_dir() {
        (release, SOURCE_BINARIES, "build da fonte (target/release/)")
    } else {
        res.push("Nenhum layout de binarios encontrado (.nemesis/bin/ nem target/release/).");
        res.push("Acao: instale via install.sh, OU 'cd .nemesis && cargo build --release --workspace'.");
        return res.status(CheckStatus::Fail);
    };

    res.push(format!("Layout detectado: {}", layout));

    let mut missing = Vec::new();
    for b in expected {
        let exists = dir.join(b).exists() || dir.join(format!("{}.exe", b)).exists();
        if exists {
            res.push(format!("OK    {}", b));
        } else {
            res.push(format!("FALTA {}", b));
            missing.push(*b);
        }
    }

    if missing.is_empty() {
        res.push("Todos os binarios esperados presentes.");
        res.status(CheckStatus::Ok)
    } else {
        res.push(format!(
            "Faltando {} binario(s) no layout '{}'.",
            missing.len(),
            layout
        ));
        res.status(CheckStatus::Fail)
    }
}
