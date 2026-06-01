//! Filesystem watcher — daemon mode
//!
//! Uses the `notify` crate for cross-platform watching:
//! - Linux:   inotify
//! - macOS:   FSEvents / kqueue
//! - Windows: ReadDirectoryChangesW
//!
//! Single daemon.rs handles all platforms via notify abstraction.

pub mod daemon;

/// All paths to watch in daemon mode (IDE-agnostic)
/// Relative to project root (CWD when daemon starts)
pub const WATCH_PATHS: &[&str] = &[
    // IDE skill/rule directories (all supported IDEs)
    ".claude",
    ".openclaude",
    ".codex",
    ".agents",
    ".windsurf",
    ".vscode",
    ".cursor",
    // Project source
    "src",
    // Package installs
    "node_modules",
    // Project root (catches new files at root level — "." = CWD)
    ".",
];

/// System-level paths to watch for supply chain attacks.
/// These are absolute paths (expanded with $HOME at runtime).
/// Files detected here are ALERTED but NOT auto-deleted.
pub const SYSTEM_WATCH_PATHS: &[&str] = &[
    // Linux/macOS: binarios instalados pelo usuario
    ".local/bin",
    ".local/share",
    // Linux: persistencia de usuario
    ".config/systemd/user",
    ".config/autostart",
    // macOS: persistencia
    "Library/LaunchAgents",
    "Library/LaunchDaemons",
    // Shell configs (diretorios pai — arquivos individuais sao filtrados)
    ".ssh",
    // Cloud credentials
    ".aws",
    ".kube",
    ".docker",
    // Registry configs
    ".npmrc",
    ".yarnrc",
];

/// Nomes de arquivos suspeitos para filtro em /tmp/
pub const SUSPICIOUS_FILE_NAMES: &[&str] = &[
    "setup", "install", "payload", "exploit", "backdoor", "shell", "reverse", "beacon", "monitor",
    "watcher", "hook", "trojan", "miner", "xmr", "coin", "steal", "exfil",
];

/// Extensoes suspeitas para filtro em /tmp/
pub const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    ".sh", ".bash", ".py", ".js", ".mjs", ".rb", ".pl", ".lua", ".php",
];
