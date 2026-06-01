//! persistence_patterns visitor — persistence mechanism detection
//!
//! Detects unauthorized persistence mechanisms:
//! - crontab -e / @reboot (scheduled execution)
//! - >> ~/.bashrc / ~/.zshrc / ~/.profile (shell config injection)
//! - authorized_keys / ssh-keygen (SSH backdoor)
//! - systemctl enable / update-rc.d (system service persistence)

use crate::DefenderViolation;
use tree_sitter::Node;

const SUGGESTION_PERSIST: &str =
    "Remove persistence mechanisms. System configuration is for human administrators only — not application code.";

pub fn visit_js_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node.kind() == "call_expression" {
        if node_text.contains("appendFile") || node_text.contains("writeFile") {
            if node_text.contains(".bashrc")
                || node_text.contains(".zshrc")
                || node_text.contains(".profile")
                || node_text.contains("authorized_keys")
            {
                violations.push(DefenderViolation {
                    visitor: "persistence_patterns".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: node_text.to_string(),
                    decoded: None,
                    message: "Persistence mechanism: writing to shell config or SSH authorized_keys via fs.appendFile/writeFile.".to_string(),
                    suggestion: Some(SUGGESTION_PERSIST.to_string()),
                });
            }
        }
    }

    if node.kind() == "call_expression" {
        if (node_text.contains("exec")
            || node_text.contains("execSync")
            || node_text.contains("spawn")
            || node_text.contains("execFile"))
            && (node_text.contains("crontab") || node_text.contains("@reboot"))
        {
            violations.push(DefenderViolation {
                visitor: "persistence_patterns".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "Persistence mechanism: crontab scheduled task via dynamic execution. Malware establishes persistence via cron.".to_string(),
                suggestion: Some(SUGGESTION_PERSIST.to_string()),
            });
        }
    }

    violations
}

pub fn visit_bash_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node_text.contains("crontab")
        && (node_text.contains("-e") || node_text.contains("-l") || node_text.contains("-r"))
    {
        violations.push(DefenderViolation {
            visitor: "persistence_patterns".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message:
                "Persistence mechanism: crontab command used to schedule malicious task execution."
                    .to_string(),
            suggestion: Some(SUGGESTION_PERSIST.to_string()),
        });
    }

    if (node_text.contains(">>") || node_text.contains(">"))
        && !node_text.contains("stdout")
        && (node_text.contains(".bashrc")
            || node_text.contains(".zshrc")
            || node_text.contains(".profile"))
    {
        violations.push(DefenderViolation {
            visitor: "persistence_patterns".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Persistence mechanism: shell config file modification (.bashrc/.zshrc/.profile). Malware injects startup commands.".to_string(),
            suggestion: Some(SUGGESTION_PERSIST.to_string()),
        });
    }

    if node_text.contains("authorized_keys")
        && (node_text.contains("echo") || node_text.contains("cat") || node_text.contains(">>"))
    {
        violations.push(DefenderViolation {
            visitor: "persistence_patterns".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Persistence mechanism: SSH authorized_keys write. Malware installs SSH backdoor for persistent remote access.".to_string(),
            suggestion: Some(SUGGESTION_PERSIST.to_string()),
        });
    }

    if (node_text.contains("systemctl") && node_text.contains("enable"))
        || (node_text.contains("update-rc.d") && node_text.contains("defaults"))
    {
        violations.push(DefenderViolation {
            visitor: "persistence_patterns".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Persistence mechanism: system service installation (systemctl/update-rc.d). Malware registers as system service.".to_string(),
            suggestion: Some(SUGGESTION_PERSIST.to_string()),
        });
    }

    if node_text.contains("ssh-keygen") && !node_text.contains("-A") {
        violations.push(DefenderViolation {
            visitor: "persistence_patterns".to_string(),
            line: (node.start_position().row + 1) as u32,
            col: (node.start_position().column + 1) as u32,
            evidence: node_text.to_string(),
            decoded: None,
            message: "Persistence mechanism: SSH key generation. May be used to install SSH backdoor for persistent access.".to_string(),
            suggestion: Some(SUGGESTION_PERSIST.to_string()),
        });
    }

    violations
}

pub fn visit_python_node(node: &Node, source: &str) -> Vec<DefenderViolation> {
    let mut violations = Vec::new();

    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");

    if node.kind() == "call_expression" {
        if node_text.contains("open(") || node_text.contains("open (") {
            if node_text.contains(".bashrc")
                || node_text.contains(".zshrc")
                || node_text.contains(".profile")
                || node_text.contains("authorized_keys")
            {
                violations.push(DefenderViolation {
                    visitor: "persistence_patterns".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: node_text.to_string(),
                    decoded: None,
                    message: "Persistence mechanism: Python open() writing to shell config or SSH authorized_keys.".to_string(),
                    suggestion: Some(SUGGESTION_PERSIST.to_string()),
                });
            }
        }
    }

    if node.kind() == "call_expression" {
        if (node_text.contains("os.system")
            || node_text.contains("subprocess.run")
            || node_text.contains("subprocess.Popen")
            || node_text.contains("os.popen"))
            && (node_text.contains("crontab") || node_text.contains("@reboot"))
        {
            violations.push(DefenderViolation {
                visitor: "persistence_patterns".to_string(),
                line: (node.start_position().row + 1) as u32,
                col: (node.start_position().column + 1) as u32,
                evidence: node_text.to_string(),
                decoded: None,
                message: "Persistence mechanism: Python crontab scheduled execution via system/subprocess.".to_string(),
                suggestion: Some(SUGGESTION_PERSIST.to_string()),
            });
        }
    }

    if node.kind() == "call_expression" {
        if node_text.contains("shutil.copy") || node_text.contains("shutil.copy2") {
            if node_text.contains(".bashrc")
                || node_text.contains(".zshrc")
                || node_text.contains(".profile")
            {
                violations.push(DefenderViolation {
                    visitor: "persistence_patterns".to_string(),
                    line: (node.start_position().row + 1) as u32,
                    col: (node.start_position().column + 1) as u32,
                    evidence: node_text.to_string(),
                    decoded: None,
                    message: "Persistence mechanism: Python shutil.copy overwriting shell config. Malware replaces startup configuration.".to_string(),
                    suggestion: Some(SUGGESTION_PERSIST.to_string()),
                });
            }
        }
    }

    violations
}
