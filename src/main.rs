mod errors;

use clap::Parser;
use errors::PortWatcherError;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::str;
use sysinfo::{Pid, System};

lazy_static::lazy_static! {
    // Regex for parsing netstat/ss output is tricky and platform-dependent.
    // Linux `ss -ltnp` example: LISTEN 0 4096 *:80 *:* users:(("nginx",pid=123,...))
    // macOS `lsof -iTCP -sTCP:LISTEN -P -n -F pcnP`
    //   pPID
    //   cCOMMAND
    //   nNODE_ADDRESS (e.g., *:80 or 127.0.0.1:8080)
    // Windows `netstat -ano -p TCP` example: TCP 0.0.0.0:80 0.0.0.0:0 LISTENING 1234
    // We will primarily rely on sysinfo for process name after getting PID from port.

    // Linux `ss -ltnp` (or `netstat -ltnp`): Looking for port and PID
    // Example: tcp   LISTEN  0   128    *:80   *:*   users:(("nginx",pid=123,fd=4))
    // Simplified: just get IP:Port and PID part
    static ref LINUX_SS_REGEX: Regex = Regex::new(r"(?m)^\s*tcp\s+LISTEN\s+\d+\s+\d+\s+(?:\*|\[::\]):(\d+)\s+.*?users:.*?pid=(\d+)").unwrap();

    // macOS `netstat -anv -p tcp` (lsof is better but netstat is also an option)
    // `lsof -iTCP -sTCP:LISTEN -P -n -F pcnP` is complex to parse sequentially.
    // Let's try simpler `netstat -anv -p tcp` for LISTEN state, port and PID
    // Example: tcp46      0      0  *.80                   *.*                    LISTEN      131072 131072   1234      0 tcp_flow_ctl
    // or:      tcp4       0      0  127.0.0.1.8080         *.*                    LISTEN      131072 131072   5678      0
    // This regex focuses on LISTEN, port number, and PID (if available in this output, lsof is better for PID)
    // A better macOS strategy is to get all PIDs listening on any TCP port and then use sysinfo.
    // `lsof -i TCP -sTCP:LISTEN -P -n` is more reliable for PID and port
    // COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
    // ControlCe   332 myuser  22u  IPv4 0xabcdef1234567890      0t0  TCP *:5000 (LISTEN)
    // SystemUIS   333 myuser  17u  IPv6 0xabcdef1234567890      0t0  TCP [::1]:12345 (LISTEN)
    static ref MACOS_LSOF_REGEX: Regex = Regex::new(r"^(?P<command>\S+)\s+(?P<pid>\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?:\[::1\]|(?:(?:\*|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(?P<port_name_or_num>\S+))|(?:\*|\[::\]):(?P<port_num>\d+))\s*\(LISTEN\)").unwrap();

    // Windows `netstat -ano -p TCP`
    // Example:  TCP    0.0.0.0:80           0.0.0.0:0              LISTENING       1234
    // Example:  TCP    [::]:443             [::]:0                 LISTENING       5678
    static ref WINDOWS_NETSTAT_REGEX: Regex = Regex::new(r"^\s*TCP\s+\S+:(\d+)\s+\S+\s+LISTENING\s+(\d+)").unwrap();
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Ports to check. Can be single (80), comma-separated (80,443), range (8000-8010), or mixed.
    #[clap(required_unless_present = "json")]
    // Make ports optional if only goal is to list all with json
    ports: Option<String>,

    /// Kill the processes found on the specified ports
    #[clap(short, long)]
    kill: bool,

    /// Output in JSON format
    #[clap(long)]
    json: bool,

    /// List all listening TCP ports (ignores `ports` argument if present)
    #[clap(short, long, conflicts_with = "ports")]
    all: bool,
}

#[derive(Debug, Serialize, Clone)]
struct PortInfo {
    port: u16,
    protocol: String,
    pid: Option<u32>,
    process_name: Option<String>,
    status: String, // e.g., "Listening", "In Use", "Free"
}

fn main() -> Result<(), PortWatcherError> {
    let cli = Cli::parse();
    let mut s = System::new_all();
    s.refresh_all(); // Refresh all system information

    let target_ports = if cli.all {
        None // Signifies we want all listening ports
    } else if let Some(ports_str) = cli.ports {
        Some(parse_ports_spec(&ports_str)?)
    } else if cli.json {
        // If --json and no ports/--all, imply all ports
        None
    } else {
        // This case should be caught by clap's `required_unless_present`
        // or if user provides --json without ports or --all
        eprintln!(
            "Error: No ports specified. Use --all to list all listening ports or provide port numbers."
        );
        std::process::exit(1);
    };

    let mut found_processes_info: Vec<PortInfo> = Vec::new();

    // Get all listening connections once
    let listening_connections = get_all_listening_tcp_ports(&s)?;

    if let Some(ref ports_to_check) = target_ports {
        for port in ports_to_check {
            if let Some(conn_info) = listening_connections.get(port) {
                found_processes_info.push(conn_info.clone());
                if cli.kill {
                    if let Some(pid) = conn_info.pid {
                        println!(
                            "Attempting to kill process '{}' (PID: {}) on port {}...",
                            conn_info.process_name.as_deref().unwrap_or("N/A"),
                            pid,
                            port
                        );
                        match kill_process_by_pid(pid, &s) {
                            Ok(()) => println!("Successfully killed process PID {}.", pid),
                            Err(e) => eprintln!("Failed to kill process PID {}: {}", pid, e),
                        }
                    } else {
                        eprintln!("Cannot kill process on port {}: PID not found.", port);
                    }
                }
            } else {
                // Optionally, report ports that are free if not using --json
                if !cli.json && !cli.all {
                    found_processes_info.push(PortInfo {
                        port: *port,
                        protocol: "TCP".to_string(),
                        pid: None,
                        process_name: None,
                        status: "Free".to_string(),
                    });
                }
            }
        }
    } else {
        // --all or --json without specific ports implies listing all found
        found_processes_info.extend(listening_connections.values().cloned());
        if cli.kill {
            eprintln!(
                "Warning: --kill is ignored when --all is used without specific ports. Please specify ports to kill."
            );
        }
    }

    if cli.json {
        // Filter out "Free" status ports for JSON output unless explicitly asked for a specific free port
        let active_ports_info: Vec<&PortInfo> = found_processes_info
            .iter()
            .filter(|p| {
                if target_ports.is_none() {
                    // --all or --json implies only active
                    p.status == "Listening"
                } else {
                    // If specific ports were asked, show their status
                    true
                }
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&active_ports_info)?);
    } else {
        print_human_readable(&found_processes_info, target_ports.is_some());
    }

    Ok(())
}

fn parse_ports_spec(ports_str: &str) -> Result<HashSet<u16>, PortWatcherError> {
    let mut ports = HashSet::new();
    for part in ports_str.split(',') {
        let trimmed_part = part.trim();
        if trimmed_part.contains('-') {
            let range_parts: Vec<&str> = trimmed_part.split('-').collect();
            if range_parts.len() == 2 {
                let start = range_parts[0].parse::<u16>().map_err(|_| {
                    PortWatcherError::InvalidPort(format!(
                        "Invalid range start: {}",
                        range_parts[0]
                    ))
                })?;
                let end = range_parts[1].parse::<u16>().map_err(|_| {
                    PortWatcherError::InvalidPort(format!("Invalid range end: {}", range_parts[1]))
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
        return Err(PortWatcherError::InvalidPort(
            "No ports specified".to_string(),
        ));
    }
    Ok(ports)
}

fn get_all_listening_tcp_ports(s: &System) -> Result<HashMap<u16, PortInfo>, PortWatcherError> {
    let mut listening_ports = HashMap::new();

    #[cfg(target_os = "linux")]
    {
        // Try `ss` first, fallback to `netstat` if ss is not available or fails
        let output = Command::new("ss")
            .args(["-ltnp"]) // TCP, listening, numeric, processes
            .output();

        let output = match output {
            Ok(out) if out.status.success() => out,
            _ => {
                // Fallback to netstat
                Command::new("netstat")
                    .args(["-ltnp"]) // TCP, listening, numeric, processes
                    .output()?
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PortWatcherError::Command(
                "ss/netstat".to_string(),
                stderr.to_string(),
            ));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);

        for cap in LINUX_SS_REGEX.captures_iter(&stdout) {
            if let (Some(port_match), Some(pid_match)) = (cap.get(1), cap.get(2)) {
                if let (Ok(port), Ok(pid_val)) = (
                    port_match.as_str().parse::<u16>(),
                    pid_match.as_str().parse::<u32>(),
                ) {
                    let process_name = s
                        .process(Pid::from_u32(pid_val))
                        .map(|p| p.name().to_string_lossy().into_owned())
                        .unwrap_or_else(|| "N/A".to_string());
                    listening_ports.insert(
                        port,
                        PortInfo {
                            port,
                            protocol: "TCP".to_string(),
                            pid: Some(pid_val),
                            process_name: Some(process_name),
                            status: "Listening".to_string(),
                        },
                    );
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        // `lsof -iTCP -sTCP:LISTEN -P -n` is generally best
        // Output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        // e.g. rapportd 759 user  22u IPv4 ... 0t0 TCP *:52202 (LISTEN)
        let output = Command::new("lsof")
            .args(["-iTCP", "-sTCP:LISTEN", "-P", "-n"])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PortWatcherError::Command(
                "lsof".to_string(),
                stderr.to_string(),
            ));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 9 {
                let pid_str = parts[1];
                let name_part = parts[8]; // e.g., *:5000 or 127.0.0.1:8080 or [::1]:12345

                if let Ok(pid_val) = pid_str.parse::<u32>() {
                    let port_str = name_part.split(':').last().unwrap_or("");
                    if let Ok(port) = port_str.parse::<u16>() {
                        let process_name = s
                            .process(Pid::from_u32(pid_val))
                            .map(|p| p.name().to_string_lossy().into_owned())
                            .unwrap_or_else(|| parts[0].to_string()); // Fallback to lsof command name

                        listening_ports.insert(
                            port,
                            PortInfo {
                                port,
                                protocol: "TCP".to_string(),
                                pid: Some(pid_val),
                                process_name: Some(process_name),
                                status: "Listening".to_string(),
                            },
                        );
                    }
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("netstat")
            .args(["-ano", "-p", "TCP"])
            .stdout(Stdio::piped()) // Important for non-UTF8 output
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PortWatcherError::Command(
                "netstat".to_string(),
                stderr.to_string(),
            ));
        }
        // Windows netstat output can be in system's locale encoding, not always UTF-8.
        // For simplicity, we assume UTF-8 or compatible. A robust solution might need encoding detection.
        let stdout = String::from_utf8_lossy(&output.stdout);

        for cap in WINDOWS_NETSTAT_REGEX.captures_iter(&stdout) {
            if let (Some(port_match), Some(pid_match)) = (cap.get(1), cap.get(2)) {
                if let (Ok(port), Ok(pid_val)) = (
                    port_match.as_str().parse::<u16>(),
                    pid_match.as_str().parse::<u32>(),
                ) {
                    if pid_val == 0 {
                        continue;
                    } // System Idle Process, not a user process
                    let process_name = s
                        .process(Pid::from_u32(pid_val))
                        .map(|p| p.name().to_string_lossy().into_owned())
                        .unwrap_or_else(|| "N/A".to_string());
                    listening_ports.insert(
                        port,
                        PortInfo {
                            port,
                            protocol: "TCP".to_string(),
                            pid: Some(pid_val),
                            process_name: Some(process_name),
                            status: "Listening".to_string(),
                        },
                    );
                }
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        return Err(PortWatcherError::UnsupportedOs);
    }

    Ok(listening_ports)
}

fn kill_process_by_pid(pid_val: u32, s: &System) -> Result<(), PortWatcherError> {
    if let Some(process) = s.process(Pid::from_u32(pid_val)) {
        if process.kill() {
            Ok(())
        } else {
            // On Unix, kill can fail due to permissions. sysinfo might not give detailed error.
            // On Windows, taskkill might be more robust if sysinfo::kill fails for permissions.
            // For now, we rely on sysinfo. If it returns false, it might be permissions.
            Err(PortWatcherError::KillFailed(
                pid_val,
                "Failed to send kill signal. Insufficient permissions or process already exited."
                    .to_string(),
            ))
        }
    } else {
        Err(PortWatcherError::ProcessNotFound(pid_val))
    }
}

fn print_human_readable(infos: &[PortInfo], show_free: bool) {
    if infos.is_empty() {
        println!("No specified ports are currently in use or no listening ports found.");
        return;
    }

    println!(
        "{:<8} {:<8} {:<8} {:<25} {:<10}",
        "PORT", "PROTOCOL", "PID", "PROCESS NAME", "STATUS"
    );
    println!("{:-<8} {:-<8} {:-<8} {:-<25} {:-<10}", "", "", "", "", "");

    let mut displayed_any = false;
    for info in infos {
        if !show_free && info.status == "Free" {
            continue;
        }
        displayed_any = true;
        println!(
            "{:<8} {:<8} {:<8} {:<25} {:<10}",
            info.port,
            info.protocol,
            info.pid
                .map_or_else(|| "N/A".to_string(), |p| p.to_string()),
            info.process_name.as_deref().unwrap_or("N/A"),
            info.status
        );
    }
    if !displayed_any && !show_free {
        println!("No specified ports are currently in use.");
    }
}

// Basic Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_single() {
        let ports = parse_ports_spec("80").unwrap();
        assert!(ports.contains(&80));
        assert_eq!(ports.len(), 1);
    }

    #[test]
    fn test_parse_ports_list() {
        let ports = parse_ports_spec("80,443,8080").unwrap();
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&8080));
        assert_eq!(ports.len(), 3);
    }

    #[test]
    fn test_parse_ports_range() {
        let ports = parse_ports_spec("8000-8002").unwrap();
        assert!(ports.contains(&8000));
        assert!(ports.contains(&8001));
        assert!(ports.contains(&8002));
        assert_eq!(ports.len(), 3);
    }

    #[test]
    fn test_parse_ports_mixed() {
        let ports = parse_ports_spec("80,443,8000-8001,3000").unwrap();
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&8000));
        assert!(ports.contains(&8001));
        assert!(ports.contains(&3000));
        assert_eq!(ports.len(), 5);
    }

    #[test]
    fn test_parse_ports_duplicates() {
        let ports = parse_ports_spec("80,80,8000-8000").unwrap();
        assert!(ports.contains(&80));
        assert!(ports.contains(&8000));
        assert_eq!(ports.len(), 2);
    }

    #[test]
    fn test_parse_ports_invalid_range() {
        assert!(parse_ports_spec("8002-8000").is_err());
    }

    #[test]
    fn test_parse_ports_invalid_char() {
        assert!(parse_ports_spec("80a").is_err());
        assert!(parse_ports_spec("80-82b").is_err());
    }

    #[test]
    fn test_parse_port_zero() {
        assert!(parse_ports_spec("0").is_err());
        assert!(parse_ports_spec("0-10").is_err());
        assert!(parse_ports_spec("10-0").is_err());
    }

    // Platform-specific regex tests can be tricky without actual command output.
    // These are basic sanity checks for the regex patterns.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_ss_regex() {
        let sample_output = "tcp   LISTEN  0   128    *:80   *:*   users:((\"nginx\",pid=123,fd=4))\n\
                             tcp   LISTEN  0   5      [::]:22 [::]:*  users:((\"sshd\",pid=456,fd=3))";
        let mut found_count = 0;
        for cap in LINUX_SS_REGEX.captures_iter(sample_output) {
            found_count += 1;
            let port = cap.get(1).unwrap().as_str();
            let pid = cap.get(2).unwrap().as_str();
            if port == "80" {
                assert_eq!(pid, "123");
            } else if port == "22" {
                assert_eq!(pid, "456");
            }
        }
        assert_eq!(found_count, 2);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_netstat_regex() {
        let sample_output = "  TCP    0.0.0.0:80           0.0.0.0:0              LISTENING       1234\n\
                             UDP    0.0.0.0:500            *:*                                    5678\n\
                             TCP    [::]:443             [::]:0                 LISTENING       9101";
        let mut found_count = 0;
        for cap in WINDOWS_NETSTAT_REGEX.captures_iter(sample_output) {
            found_count += 1;
            let port = cap.get(1).unwrap().as_str();
            let pid = cap.get(2).unwrap().as_str();
            if port == "80" {
                assert_eq!(pid, "1234");
            } else if port == "443" {
                assert_eq!(pid, "9101");
            }
        }
        assert_eq!(found_count, 2);
    }

    // macOS lsof output is a bit more complex, so the current regex is simpler.
    // A more robust test would mock `lsof` output structure.
    // The current macOS lsof parsing in `get_all_listening_tcp_ports` is line-by-line split, not regex based.
    // The MACOS_LSOF_REGEX is not currently used for the primary parsing logic due to complexity.
}
