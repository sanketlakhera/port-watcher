use thiserror::Error;

#[derive(Error, Debug)]
pub enum PortWatcherError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse command output: {0}")]
    Parse(String),
    #[error("Command execution failed: {0}, stderr: {1}")]
    Command(String, String),
    #[error("Invalid port specification: {0}")]
    InvalidPort(String),
    #[error("Process with PID {0} not found")]
    ProcessNotFound(u32),
    #[error("Failed to kill process with PID {0}: {1}")]
    KillFailed(u32, String),
    #[error("JSON serialization error: {0}")]
    JsonSerialization(#[from] serde_json::Error),
    #[error("Permission denied. Try running with sudo/administrator privileges.")]
    PermissionDenied,
    #[error("Unsupported OS for specific operation")]
    UnsupportedOs,
    #[error("Sysinfo error: {0}")]
    SysinfoError(String), // Catch-all for sysinfo specific issues
}
