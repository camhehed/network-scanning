# Network Scanning Tool

A comprehensive network scanning and authentication monitoring tool with advanced features for penetration testing and security auditing. This tool collects network data, discovers hosts, scans ports, performs banner grabbing, and can test for common security vulnerabilities.

## ⚠️ Security Disclaimer

**READ THIS BEFORE USING THIS TOOL**

This tool should **ONLY** be used on networks you own or have explicit written permission to test.

Unauthorized network scanning and credential testing may be:
- **Illegal** in your jurisdiction
- A violation of computer fraud and abuse laws
- Grounds for civil and criminal prosecution

The authors assume **NO LIABILITY** for misuse of this tool. Use for authorized penetration testing and security auditing only.

By using this tool, you acknowledge that you have permission to scan the target network and accept full responsibility for your actions.

## Features

### Core Features
- **Network Discovery**: Multi-method host discovery using ARP, ICMP ping, TCP, and UDP probes
- **Port Scanning**: Threaded port scanning with customizable port ranges
- **Service/Banner Grabbing**: Detects services and versions running on open ports
- **Vulnerability Detection**: Automatically flags risky configurations and services
- **DNS Resolution**: Reverse DNS lookups with caching for discovered hosts
- **MAC Vendor Lookup**: Identifies device manufacturers from MAC addresses
- **OS Detection**: Identifies operating systems of network devices (requires nmap and sudo)
- **Network Analysis**: Latency checks, traceroute, and WHOIS lookups

### Authentication & Logging Features
- **Login Session Monitoring**: Current and historical login sessions
- **Active Users Tracking**: Monitor who is logged into systems
- **Authentication Logs**: Detailed auth log analysis (requires sudo)
- **Login History**: Comprehensive login activity tracking
- **Network Connections**: Active connection monitoring

### Offensive Security Features (OPT-IN)
- **Default Credential Testing**: Tests common username/password combinations on:
  - FTP (anonymous, admin/admin, etc.)
  - SSH (accessibility testing)
  - Telnet (accessibility and unencrypted protocol warning)
  - Databases (MySQL, PostgreSQL, MongoDB, Redis exposure detection)
- **Rate-Limited**: Prevents lockouts during testing
- **Security Audit Logging**: All findings logged to dedicated security audit file

### Output Formats
- **TXT**: Traditional log files (default)
- **JSON**: Structured JSON output for integration with other tools
- **CSV**: Spreadsheet-compatible format for reporting

## Requirements

- Python 3.6+
- nmap (optional but recommended: `sudo apt install nmap` or `brew install nmap`)
- Standard Unix utilities: who, w, last, lastlog, ss, netstat, ping, traceroute, whois

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Basic scan (auto-detect network)
python3 network_scanner.py

# The tool will request sudo privileges when needed for enhanced features
```

### Command-Line Options

```
  --target <ip/hostname>     Scan specific target instead of auto-detecting network
  --quick                    Fast scan mode (fewer ports, shorter timeouts)
  --full                     Comprehensive scan (more ports, deeper analysis)
  --output-format <format>   Output format: json, csv, or txt (default: txt)
  --no-sudo                  Skip sudo operations entirely
  --ports <range>            Custom port range (e.g., "1-1000" or "22,80,443")
  --check-defaults           ⚠️  Test for default credentials (AUTHORIZED USE ONLY)
  --help                     Show help message
```

### Usage Examples

#### Scan Specific Target
```bash
python3 network_scanner.py --target 192.168.1.1
```

#### Quick Scan (Faster, Less Thorough)
```bash
python3 network_scanner.py --quick --no-sudo
```

#### Full Comprehensive Scan
```bash
python3 network_scanner.py --full
```

#### Custom Port Range
```bash
# Scan ports 1-100
python3 network_scanner.py --target 192.168.1.1 --ports 1-100

# Scan specific ports
python3 network_scanner.py --target 192.168.1.1 --ports 22,80,443,8080
```

#### Export to JSON
```bash
python3 network_scanner.py --target 192.168.1.1 --output-format json
```

#### Offensive Security Testing (Authorized Networks Only)
```bash
# ⚠️  WARNING: Only use on networks you have permission to test
python3 network_scanner.py --full --check-defaults
```

#### Scan Without Sudo
```bash
python3 network_scanner.py --no-sudo --quick
```

## Output Files

All files are timestamped with format `YYYYMMDD_HHMMSS_filename.txt` and saved in the `scan_logs/` directory:

### Network Scanning Logs
- `network_scan.txt` - Network discovery results with DNS and MAC vendor info
- `port_scan.txt` - Open ports, services, and banners
- `os_detection.txt` - Operating system detection results
- `latency.txt` - Ping latency measurements
- `traceroute.txt` - Network route traces
- `whois.txt` - WHOIS information

### Authentication & Activity Logs
- `login_sessions.txt` - Current and recent login sessions
- `active_users.txt` - Currently active users
- `auth_logs.txt` - Authentication logs and failed login attempts
- `network_connections.txt` - Active network connections
- `login_activity.txt` - Detailed login activity history

### Security Findings
- `vulnerabilities.txt` - Detected vulnerabilities and security risks
- `security_audit.txt` - Default credential test results (when enabled)
- `scan_summary.txt` - Scan overview and status

### Structured Output (Optional)
- `results.json` - Complete scan results in JSON format (--output-format json)
- `results.csv` - Scan results in CSV format (--output-format csv)

## Detected Vulnerabilities

The tool automatically flags:
- **Unencrypted Protocols**: Telnet (port 23) - plaintext credentials
- **Insecure Services**: FTP (port 21) - often misconfigured
- **Exposed Databases**: MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379)
- **SMB Exposure**: Port 445 - potential security risk (EternalBlue, etc.)
- **Anonymous FTP**: Detects anonymous FTP access
- **Outdated Software**: Flags old versions when detected in banners
- **Default Credentials**: Tests common username/password combinations (opt-in)

## Host Discovery Methods

The tool uses multiple methods to discover alive hosts:
1. **ICMP Ping**: Standard ping requests
2. **TCP Connect**: Tests connections to common ports (22, 80, 443, 445)
3. **UDP Probe**: Tests UDP services (DNS port 53, SNMP port 161)
4. **ARP Scan**: Queries local ARP table
5. **Nmap**: Uses nmap for advanced discovery when available

## Performance

- **Threading**: Port scanning uses multi-threading for speed
- **Rate Limiting**: Credential testing is rate-limited to avoid lockouts
- **Configurable Modes**: 
  - Quick mode: Fast, minimal ports
  - Normal mode: Balanced speed and coverage
  - Full mode: Comprehensive, thorough scanning

## Permissions

The tool works without sudo but has limited functionality. For full features, run with sudo access:

| Feature | Without Sudo | With Sudo |
|---------|-------------|-----------|
| Port Scanning | ✓ | ✓ |
| Banner Grabbing | ✓ | ✓ |
| Host Discovery | ✓ | ✓ |
| DNS Resolution | ✓ | ✓ |
| Network Connections | Limited | Full |
| OS Detection | ✗ | ✓ |
| Auth Logs | ✗ | ✓ |
| Nmap Features | ✗ | ✓ |

## Legal and Ethical Use

This tool is provided for:
- **Security auditing** of your own networks
- **Authorized penetration testing** with written permission
- **Educational purposes** in controlled lab environments
- **Network administration** on networks you manage

**DO NOT USE** for:
- Unauthorized network scanning
- Testing networks without permission
- Malicious purposes
- Violating computer fraud laws

## Troubleshooting

### No hosts discovered
- Check network connectivity
- Verify you're on the correct network
- Try with `--full` for more thorough discovery
- Ensure firewall isn't blocking scans

### Permission denied errors
- Run with sudo for full features: `sudo python3 network_scanner.py`
- Or use `--no-sudo` to skip privileged operations

### Slow scanning
- Use `--quick` mode for faster scans
- Reduce port range with `--ports`
- Scan specific targets with `--target` instead of full network

## Contributing

Contributions are welcome! Please ensure any new features:
- Include proper error handling
- Add appropriate security warnings
- Document usage in README
- Follow existing code style

## License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for compliance with all applicable laws.