use std::collections::HashSet;
use thiserror::Error;
use serde_json; // Keep if PortWatcherError::JsonSerialization is used by parse_ports_spec, otherwise remove.

// It seems serde_json is only used by PortWatcherError::JsonSerialization,
// which itself is not directly returned by parse_ports_spec.
// However, PortWatcherError is a public enum, so its variants should be constructible.
// Let's keep serde_json for now.

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

pub fn parse_ports_spec(ports_str: &str) -> Result<HashSet<u16>, PortWatcherError> {
    let mut ports = HashSet::new();
    if ports_str.trim().is_empty() {
        // Handle empty input string gracefully, perhaps return an error or an empty set.
        // Current behavior (based on original main.rs) is to error if ports set is empty after parsing.
        // Let's ensure this function is self-contained in its error reporting for empty final set.
        return Err(PortWatcherError::InvalidPort(
            "No ports specified".to_string(),
        ));
    }
    for part in ports_str.split(',') {
        let trimmed_part = part.trim();
        if trimmed_part.is_empty() {
            // Skip empty parts, e.g. "80,,443"
            continue;
        }
        if trimmed_part.contains('-') {
            let range_parts: Vec<&str> = trimmed_part.split('-').collect();
            if range_parts.len() == 2 {
                let start_str = range_parts[0].trim();
                let end_str = range_parts[1].trim();

                if start_str.is_empty() || end_str.is_empty() {
                    return Err(PortWatcherError::InvalidPort(format!(
                        "Invalid range format: '{}', missing start or end.",
                        trimmed_part
                    )));
                }

                let start = start_str.parse::<u16>().map_err(|_| {
                    PortWatcherError::InvalidPort(format!(
                        "Invalid range start: {}",
                        start_str
                    ))
                })?;
                let end = end_str.parse::<u16>().map_err(|_| {
                    PortWatcherError::InvalidPort(format!("Invalid range end: {}", end_str))
                })?;

                if start > end {
                    return Err(PortWatcherError::InvalidPort(format!(
                        "Invalid range: start ({}) > end ({})",
                        start, end
                    )));
                }
                if start == 0 || end == 0 {
                    return Err(PortWatcherError::InvalidPort(
                        "Port number cannot be 0".to_string(),
                    ));
                }
                for port in start..=end {
                    ports.insert(port);
                }
            } else {
                return Err(PortWatcherError::InvalidPort(format!(
                    "Invalid range format: {}",
                    trimmed_part
                )));
            }
        } else {
            let port = trimmed_part.parse::<u16>().map_err(|_| {
                PortWatcherError::InvalidPort(format!("Invalid port number: {}", trimmed_part))
            })?;
            if port == 0 {
                return Err(PortWatcherError::InvalidPort(
                    "Port number cannot be 0".to_string(),
                ));
            }
            ports.insert(port);
        }
    }
    if ports.is_empty() {
        // This case handles inputs like "," or ",," which result in no valid ports.
        return Err(PortWatcherError::InvalidPort(
            "No valid ports found in specification".to_string(),
        ));
    }
    Ok(ports)
}

// Adding basic tests for parse_ports_spec within the library itself
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lib_test_parse_ports_single() {
        let ports = parse_ports_spec("80").unwrap();
        assert!(ports.contains(&80));
        assert_eq!(ports.len(), 1);
    }

    #[test]
    fn lib_test_parse_ports_list() {
        let ports = parse_ports_spec("80,443,8080").unwrap();
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&8080));
        assert_eq!(ports.len(), 3);
    }

    #[test]
    fn lib_test_parse_ports_range() {
        let ports = parse_ports_spec("8000-8002").unwrap();
        assert!(ports.contains(&8000));
        assert!(ports.contains(&8001));
        assert!(ports.contains(&8002));
        assert_eq!(ports.len(), 3);
    }
     #[test]
    fn lib_test_parse_empty_str() {
        assert!(parse_ports_spec("").is_err());
    }

    #[test]
    fn lib_test_parse_just_comma() {
        assert!(parse_ports_spec(",").is_err());
    }
     #[test]
    fn lib_test_parse_empty_parts() {
        let ports = parse_ports_spec("80,,443").unwrap();
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert_eq!(ports.len(), 2);
    }
    #[test]
    fn lib_test_parse_range_with_empty_start() {
        assert!(parse_ports_spec("-8000").is_err());
    }

    #[test]
    fn lib_test_parse_range_with_empty_end() {
        assert!(parse_ports_spec("8000-").is_err());
    }
}
