use clap::Parser;
// errors::PortWatcherError is now part of the library crate `port_watcher`
// use errors::PortWatcherError;
use port_watcher::{parse_ports_spec, PortWatcherError}; // Use from library
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::str;
use sysinfo::{Pid, System, ProcessRefreshKind, ProcessesToUpdate};

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
    // rapportd    759 myuser  11u  IPv4 0xabcdef1234567890      0t0  TCP 127.0.0.1:60140 (LISTEN)
    // The regex aims to capture PID (2nd column) and port (from 9th column, NAME).
    // It assumes `lsof -P -n` output which provides numeric ports.
    // Handles NAME formats like *:PORT, IPV4:PORT, [IPV6]:PORT, [IPV6%scope]:PORT
    static ref MACOS_LSOF_REGEX: Regex = Regex::new(
        r"^(?P<command>\S+)\s+(?P<pid>\d+)(?:\s+\S+){6}\s+(?:(?:[^\s:]+)|(?:\[[^\s\]]+\])):(?P<port>\d+)\s+\(LISTEN\)"
    ).unwrap();

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
                        match kill_process_by_pid(pid, &mut s) { // Pass s as mutable
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

// parse_ports_spec function has been moved to src/lib.rs

fn get_all_listening_tcp_ports(s: &System) -> Result<HashMap<u16, PortInfo>, PortWatcherError> {
    let mut listening_ports = HashMap::new();

    #[cfg(target_os = "linux")]
    {
        // Try `ss` first, fallback to `netstat` if ss is not available or fails
        let output_result = Command::new("ss")
            .args(["-ltnp"]) // TCP, listening, numeric, processes
            .output();

        let final_output = match output_result {
            Ok(out) if out.status.success() => Ok(out),
            Err(_e) => { // ss command failed to execute (e.g. not found or other IO error)
                // Try netstat
                Command::new("netstat")
                    .args(["-ltnp"])
                    .output()
                    // .map_err(PortWatcherError::Io) // Map IO error from netstat
            }
            Ok(out) => { // ss executed but failed (e.g. returned non-zero exit code)
                 // Try netstat, and if this also fails, map its error
                Command::new("netstat")
                    .args(["-ltnp"])
                    .output()
                    // .map_err(PortWatcherError::Io) // Map IO error from netstat
            }
        }?; // Propagate IO error if command itself fails to run (e.g. from the fallback)


        if !final_output.status.success() {
            let stderr = String::from_utf8_lossy(&final_output.stderr);
            // This logic tries to guess which command's error to report.
            // If ss ran and failed, cmd_name is ss. If ss failed to run, netstat was tried.
            let cmd_name = if output_result.is_ok() && !output_result.as_ref().unwrap().status.success() {
                 "ss" // ss ran but had an error status
            } else if output_result.is_err() {
                "netstat" // ss failed to run, so netstat was the fallback
            } else {
                 "ss/netstat" // Default or if ss succeeded initially (shouldn't reach here if ss succeeded)
            };
            return Err(PortWatcherError::Command(
                cmd_name.to_string(),
                stderr.to_string(),
            ));
        }
        let stdout = String::from_utf8_lossy(&final_output.stdout);

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

        // Example lsof output lines:
        // COMMAND    PID  USER   FD TYPE DEVICE SIZE/OFF NODE NAME
        // ControlCe  332 myuser  22u IPv4  0x...   0t0  TCP *:5000 (LISTEN)
        // SystemUIS  333 myuser  17u IPv6  0x...   0t0  TCP [::1]:12345 (LISTEN)
        // rapportd   759 myuser  11u IPv4  0x...   0t0  TCP 127.0.0.1:60140 (LISTEN)
        // SomeProces 101 myuser  20u IPv4  0x...   0t0  TCP localhost:http (LISTEN) <- -P should prevent 'http'
        // SomeProces 102 myuser  20u IPv4  0x...   0t0  TCP 127.0.0.1:8080 (LISTEN)

        for line in stdout.lines().skip(1) { // Skip header line
            if let Some(cap) = MACOS_LSOF_REGEX.captures(line) {
                let command_name_from_lsof = cap.name("command").map_or_else(|| "N/A".to_string(), |m| m.as_str().to_string());
                let pid_str = cap.name("pid").map_or("", |m| m.as_str());
                let port_str = cap.name("port").map_or("", |m| m.as_str());

                if let (Ok(pid_val), Ok(port)) = (pid_str.parse::<u32>(), port_str.parse::<u16>()) {
                    // Successfully parsed PID and Port
                    let process_name = s
                        .process(Pid::from_u32(pid_val))
                        .map(|p| p.name().to_string_lossy().into_owned())
                        .unwrap_or(command_name_from_lsof); // Fallback to lsof command name captured by regex

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
    #[cfg(target_os = "windows")]
    {
        // Ensure we import Stdio for Windows command execution
        use std::process::Stdio;
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

fn kill_process_by_pid(pid_val: u32, s: &mut System) -> Result<(), PortWatcherError> {
    // First, try to get the process.
    if let Some(process) = s.process(Pid::from_u32(pid_val)) {
        if process.kill() {
            // If kill() returns true, assume success.
            // SIGKILL is generally effective immediately. Further checks could be added if necessary.
            return Ok(());
        } else {
            // process.kill() returned false. Let's find out why.
            // Refresh the specific process's state.
            // `ProcessesToUpdate::Some` expects a slice of PIDs.
            // `ProcessRefreshKind::everything()` ensures its existence status is up-to-date.
            // The `true` argument for `clear_state` in refresh_processes_specifics is crucial
            // if we want to ensure we are not looking at cached state for the process existence.
            // However, sysinfo's `refresh_processes_specifics` takes `ProcessesToUpdate`, `clear_state: bool`, `refresh_kind: ProcessRefreshKind`
            // The method signature is pub fn refresh_processes_specifics(&mut self, pids_to_update: ProcessesToUpdate<'_>, clear_state: bool, kind: ProcessRefreshKind) -> usize
            // Let's ensure we use it correctly. `clear_state` should probably be true.
            s.refresh_processes_specifics(ProcessesToUpdate::Some(&[Pid::from_u32(pid_val)]), true, ProcessRefreshKind::everything());


            // Check if the process still exists after the refresh.
            if s.process(Pid::from_u32(pid_val)).is_some() {
                // Process still exists, so kill probably failed due to permissions.
                Err(PortWatcherError::PermissionDenied)
            } else {
                // Process no longer exists, so it likely exited before or during the kill attempt,
                // or was unkillable by this user but terminated for other reasons after the attempt.
                Err(PortWatcherError::KillFailed(
                    pid_val,
                    "Failed to kill process. It may have already exited or was not killable by the current user and then terminated.".to_string(),
                ))
            }
        }
    } else {
        // Process was not found in the first place.
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
    use super::*; // This will bring LINUX_SS_REGEX, WINDOWS_NETSTAT_REGEX etc. into scope

    // Tests for parse_ports_spec have been moved to src/lib.rs
    // Keep platform-specific regex tests here as they are related to binary's direct dependencies.

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
    // The MACOS_LSOF_REGEX is now used for parsing.
    // A test for MACOS_LSOF_REGEX could be added here if desired, similar to Linux and Windows.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_lsof_regex() {
        let sample_output1 = "ControlCe  332 myuser  22u IPv4  0x...   0t0  TCP *:5000 (LISTEN)";
        let sample_output2 = "SystemUIS  333 myuser  17u IPv6  0x...   0t0  TCP [::1]:12345 (LISTEN)";
        let sample_output3 = "rapportd   759 myuser  11u IPv4  0x...   0t0  TCP 127.0.0.1:60140 (LISTEN)";
        let sample_output4 = "nginx     123 root    5u  IPv4  0x...   0t0  TCP *:80 (LISTEN)"; // Typical command

        let cap1 = MACOS_LSOF_REGEX.captures(sample_output1).unwrap();
        assert_eq!(cap1.name("command").unwrap().as_str(), "ControlCe");
        assert_eq!(cap1.name("pid").unwrap().as_str(), "332");
        assert_eq!(cap1.name("port").unwrap().as_str(), "5000");

        let cap2 = MACOS_LSOF_REGEX.captures(sample_output2).unwrap();
        assert_eq!(cap2.name("command").unwrap().as_str(), "SystemUIS");
        assert_eq!(cap2.name("pid").unwrap().as_str(), "333");
        assert_eq!(cap2.name("port").unwrap().as_str(), "12345");

        let cap3 = MACOS_LSOF_REGEX.captures(sample_output3).unwrap();
        assert_eq!(cap3.name("command").unwrap().as_str(), "rapportd");
        assert_eq!(cap3.name("pid").unwrap().as_str(), "759");
        assert_eq!(cap3.name("port").unwrap().as_str(), "60140");
        
        let cap4 = MACOS_LSOF_REGEX.captures(sample_output4).unwrap();
        assert_eq!(cap4.name("command").unwrap().as_str(), "nginx");
        assert_eq!(cap4.name("pid").unwrap().as_str(), "123");
        assert_eq!(cap4.name("port").unwrap().as_str(), "80");
    }
}
