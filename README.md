# Port Watcher

A cross-platform command-line tool to monitor and manage TCP ports. Written in Rust, it provides a simple way to check which processes are using specific ports and optionally kill them.

## Features

- Check specific ports or ranges of ports
- List all listening TCP ports
- Kill processes using specified ports
- Cross-platform support (Linux, macOS, Windows)
- JSON output support
- Human-readable output format

## Installation

### From Source

1. Clone the repository:

```bash
git clone https://github.com/yourusername/port-watcher.git
cd port-watcher
```

2. Build the project:

```bash
cargo build --release
```

3. The binary will be available at `target/release/port-watcher`

### Using Cargo

```bash
cargo install port-watcher
```

## Usage

```bash
port-watcher [OPTIONS] [PORTS]
```

### Arguments

- `PORTS`: Ports to check. Can be:
  - Single port: `3000`
  - Comma-separated ports: `3000,3001,3002`
  - Port range: `3000-3005`
  - Mixed: `3000,3001,3005-3010`

### Options

- `-k, --kill`: Kill processes found on the specified ports
- `-a, --all`: List all listening TCP ports (ignores `PORTS` argument if present)
- `--json`: Output in JSON format

## Examples

1. Check specific ports:

```bash
port-watcher 3000,3001,3002
```

2. Check a range of ports:

```bash
port-watcher 3000-3005
```

3. List all listening ports:

```bash
port-watcher --all
```

4. Kill processes on specific ports:

```bash
port-watcher 3000,3001 --kill
```

5. Get JSON output:

```bash
port-watcher 3000,3001 --json
```

6. List all ports in JSON format:

```bash
port-watcher --all --json
```

## Output Format

### Human-readable Output

```
PORT     PROTOCOL PID      PROCESS NAME               STATUS
-------- -------- -------- ------------------------- ----------
3000     TCP      1234     node                      Listening
3001     TCP      5678     python                    Listening
3002     TCP      N/A      N/A                       Free
```

### JSON Output

```json
[
  {
    "port": 3000,
    "protocol": "TCP",
    "pid": 1234,
    "process_name": "node",
    "status": "Listening"
  },
  {
    "port": 3001,
    "protocol": "TCP",
    "pid": 5678,
    "process_name": "python",
    "status": "Listening"
  }
]
```

## Platform Support

- **Linux**: Uses `ss` or `netstat` to get port information
- **macOS**: Uses `lsof` to get port information
- **Windows**: Uses `netstat` to get port information

## Building from Source

1. Ensure you have Rust installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. Clone and build:

```bash
git clone https://github.com/yourusername/port-watcher.git
cd port-watcher
cargo build --release
```

## Dependencies

- clap: Command-line argument parsing
- sysinfo: System information gathering
- serde: Serialization/deserialization
- regex: Regular expression support

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
