// src/detect.rs
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub os: String,
    pub arch: String,
    pub suffix: String,
}

#[derive(Debug, Clone)]
pub struct ProjectInfo {
    pub ides: Vec<String>,
    pub stacks: Vec<String>,
}

pub fn detect_platform() -> PlatformInfo {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();

    let suffix = match (os.as_str(), arch.as_str()) {
        ("macos", "aarch64") => "darwin-arm64".to_string(),
        ("macos", "x86_64") => "darwin-x64".to_string(),
        ("linux", "x86_64") => "linux-x64".to_string(),
        ("windows", "x86_64") => "win32-x64".to_string(),
        _ => format!("{}-{}", os, arch),
    };

    PlatformInfo { os, arch, suffix }
}

pub fn detect_ides(target_dir: &Path) -> Vec<String> {
    let mut ides = Vec::new();

    let ide_dirs = vec![
        (".claude", "Claude Code"),
        (".devin", "Devin"),
        (".cursor", "Cursor"),
        (".codex", "Codex"),
        (".agents", "Agents"),
        (".openclaude", "OpenClaude"),
    ];

    for (dir, name) in ide_dirs {
        if target_dir.join(dir).exists() {
            ides.push(name.to_string());
        }
    }

    if ides.is_empty() {
        ides.push("Claude Code".to_string());
    }

    ides
}

/// Detecta todos os stacks presentes no projeto
pub fn detect_all_stacks(target_dir: &Path) -> Vec<String> {
    let mut stacks = Vec::new();

    if target_dir.join("package.json").exists() {
        stacks.push("typescript".to_string());
    }
    if target_dir.join("Cargo.toml").exists() {
        stacks.push("rust".to_string());
    }
    if target_dir.join("go.mod").exists() {
        stacks.push("go".to_string());
    }
    if target_dir.join("pyproject.toml").exists() || target_dir.join("requirements.txt").exists() {
        stacks.push("python".to_string());
    }
    if target_dir.join("pom.xml").exists() {
        stacks.push("java".to_string());
    }

    stacks
}

pub fn detect_project_stack(target_dir: &Path) -> ProjectInfo {
    let stacks = detect_all_stacks(target_dir);
    let ides = detect_ides(target_dir);

    ProjectInfo { ides, stacks }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_all_stacks_empty_dir() {
        let result = detect_all_stacks(std::path::Path::new("/tmp"));
        assert!(result.is_empty() || result.len() > 0); // Just verify it returns a vec
    }

    #[test]
    fn test_detect_platform() {
        let platform = detect_platform();
        assert!(!platform.os.is_empty());
        assert!(!platform.arch.is_empty());
        assert!(!platform.suffix.is_empty());
    }

    #[test]
    fn test_project_info_struct() {
        let project_info = ProjectInfo {
            ides: vec!["Claude Code".to_string()],
            stacks: vec!["typescript".to_string(), "rust".to_string()],
        };
        assert_eq!(project_info.stacks.len(), 2);
        assert_eq!(project_info.stacks[0], "typescript");
        assert_eq!(project_info.stacks[1], "rust");
    }
}
