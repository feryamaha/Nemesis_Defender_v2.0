//! DefenderReport — structured log writer
//!
//! Writes to: .nemesis/logs/defender.log (same directory as violations.log)

use crate::DefenderResult;

/// Log path relative to .nemesis directory (where binary is executed)
pub const LOG_PATH: &str = "logs/defender.log";

/// Write a DefenderResult to defender.log in append mode.
/// Called after every scan that finds Suspicious or Malicious content.
pub fn log_result(result: &DefenderResult) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let timestamp = chrono_or_fallback();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_PATH)?;

    let severity_tag = match result.severity {
        crate::Severity::Clean => return Ok(()), // Don't log clean results
        crate::Severity::Suspicious => "[SUSPICIOUS]",
        crate::Severity::Malicious => "[MALICIOUS]",
    };

    writeln!(
        file,
        "\n{} {} {}",
        timestamp,
        severity_tag,
        result.path.display()
    )?;
    writeln!(
        file,
        "  Language: {:?} | Depth: {}",
        result.language, result.scan_depth
    )?;

    for v in &result.violations {
        writeln!(
            file,
            "  ├─ [{}] Line {}:{} — {}",
            v.visitor, v.line, v.col, v.message
        )?;
        writeln!(file, "  │   Evidence: {}", v.evidence)?;
        if let Some(decoded) = &v.decoded {
            let preview = if decoded.len() > 80 {
                &decoded[..80]
            } else {
                decoded
            };
            writeln!(file, "  │   Decoded: {}...", preview)?;
        }
        if let Some(ref suggestion) = v.suggestion {
            writeln!(file, "  │   → FIX: {}", suggestion)?;
        }
    }

    Ok(())
}

/// Write an escalation message to defender.log in append mode.
/// Called when multi-turn attack escalation is detected.
pub fn log_escalation(message: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let timestamp_str = format!("[{}]", timestamp);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_PATH)?;

    writeln!(file, "\n{} [ESCALATION] {}", timestamp_str, message)?;

    Ok(())
}

fn chrono_or_fallback() -> String {
    // Use std::time for timestamp without adding chrono dependency
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("[{}]", secs)
}
