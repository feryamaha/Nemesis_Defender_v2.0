use crate::checks::{binaries_dir, project_root};
use crate::report::{CheckResult, CheckStatus};

const SCAFFOLD_CONFIGS: &[&str] = &[
    ".devin/hooks.json",
    ".claude/settings.json",
    ".cursor/hooks.json",
    ".codex/hooks.json",
    ".github/hooks.json",
];

pub fn run() -> CheckResult {
    let mut res = CheckResult::new("G4 - Scaffold da IDE (hooks pretool/posttool)");
    let root = project_root();
    // Diretório real dos binários no layout ativo (distro `.nemesis/bin/` ou fonte
    // `target/release/`) — NÃO assumir target/release, senão o scaffold dá laudo falso no distro.
    let bin_dir = binaries_dir();

    let mut found_any = false;
    let mut any_valid_pretool = false;

    for rel in SCAFFOLD_CONFIGS {
        let path = root.join(rel);
        if !path.exists() {
            continue;
        }
        found_any = true;
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let trimmed = content.trim();

        if trimmed.is_empty() || trimmed == "{}" {
            res.push(format!(
                "VAZIO {} - daemon NAO sobe automaticamente (sem hook pretool).",
                rel
            ));
            continue;
        }

        if serde_json::from_str::<serde_json::Value>(trimmed).is_err() {
            res.push(format!("JSON INVALIDO {} - corrija a sintaxe.", rel));
            continue;
        }

        let has_pre = content.contains("pretool");
        let has_post = content.contains("posttool");
        let pre_bin_exists = bin_dir
            .as_ref()
            .map(|d| d.join("nemesis-pretool-check-unix").exists())
            .unwrap_or(false);

        if has_pre && pre_bin_exists {
            any_valid_pretool = true;
            res.push(format!("OK    {} - pretool configurado.", rel));
        } else if has_pre {
            res.push(format!(
                "ATENCAO {} - referencia pretool mas binario nemesis-pretool-check-unix nao \
                 encontrado em nenhum layout (.nemesis/bin/ nem target/release/).",
                rel
            ));
        } else {
            res.push(format!("ATENCAO {} - sem referencia a pretool.", rel));
        }

        if !has_post {
            res.push(format!(
                "NOTA  {} - sem referencia a posttool (scan pos-escrita inativo).",
                rel
            ));
        }
    }

    res.push("Por que importa: sem pretool no scaffold, a IDE nao dispara 'nemesis-defender --ensure-daemon' e o daemon nao sobe sozinho (no Linux so o eBPF protege).");

    if !found_any {
        res.push("Nenhum scaffold de IDE (.devin/.claude/.cursor/.codex/.github) com config encontrado.");
        res.status(CheckStatus::Fail)
    } else if any_valid_pretool {
        res.status(CheckStatus::Ok)
    } else {
        res.status(CheckStatus::Fail)
    }
}
