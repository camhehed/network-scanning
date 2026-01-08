# Network Scanning Tool

A comprehensive network scanning and authentication monitoring tool that collects network data and login information, writing all output to organized log files.

## Features

- **Network Discovery**: Scans local network for devices using ARP and nmap
- **Port Scanning**: Detects open ports and running services
- **OS Detection**: Identifies operating systems of network devices (requires sudo)
- **Network Analysis**: Latency checks, traceroute, and WHOIS lookups
- **Login & Authentication Monitoring**:
  - Current login sessions
  - Active users on the system
  - Authentication logs and failed login attempts
  - Login history and activity tracking
  - Network connection monitoring
- **Silent Operation**: All output written to timestamped log files in `scan_logs/` directory
- **Sudo Handling**: Automatically requests sudo when needed, gracefully degrades if unavailable

## Requirements

- Python 3.6+
- nmap (install via package manager: `sudo apt install nmap` or `brew install nmap`)
- Standard Unix utilities: who, w, last, lastlog, ss, netstat, ping, traceroute, whois

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 network_scanner.py
```

The tool will:
1. Request sudo privileges if needed (for enhanced scanning features)
2. Scan the local network
3. Collect authentication and login data
4. Write all results to timestamped files in the `scan_logs/` directory

## Output Files

All files are timestamped with format `YYYYMMDD_HHMMSS_filename.txt`:

- `network_scan.txt` - Network discovery results
- `port_scan.txt` - Open ports and services
- `os_detection.txt` - Operating system detection
- `latency.txt` - Ping latency results
- `traceroute.txt` - Network route traces
- `whois.txt` - WHOIS information
- `login_sessions.txt` - Current and recent login sessions
- `active_users.txt` - Currently active users
- `auth_logs.txt` - Authentication logs
- `network_connections.txt` - Active network connections
- `login_activity.txt` - Detailed login activity history
- `scan_summary.txt` - Scan overview and status

## Permissions

The tool works without sudo but has limited functionality. For full features (OS detection, auth logs, detailed network info), run with sudo access. The tool will request sudo automatically when first run.