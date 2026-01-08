# Network Scanning Tool

A comprehensive Python network scanning tool that automatically detects and scans your network, discovering all active devices and gathering detailed information about them.

## Features

- Auto-detects the network the system is connected to
- Scans all active devices on the network using ARP
- Logs comprehensive information including:
  - Network interface details (IP, netmask, gateway, MAC)
  - All active devices with IP and MAC addresses
  - Hostnames and DNS information
  - Open ports per device
  - Services and service banners
  - OS detection/fingerprinting
  - Network latency and ping response times
  - Traceroute information
  - WHOIS data
  - Network speed information
- Outputs all data to organized, timestamped text log files

## Requirements

- Python 3.6+
- Root/Administrator privileges (for full functionality)

## Installation

1. Clone this repository
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

Note: On some systems you may also need to install nmap:
- Ubuntu/Debian: `sudo apt-get install nmap`
- macOS: `brew install nmap`
- Windows: Download from https://nmap.org/download.html

## Usage

Run the scanner with root privileges for full functionality:

```bash
sudo python3 network_scanner.py
```

The tool will:
1. Automatically detect your network interface and configuration
2. Scan for all active devices on the network
3. Gather detailed information about each device
4. Generate a comprehensive log file in the `logs/` directory

## Output

All scan results are saved to timestamped log files in the `logs/` directory:
- Format: `network_scan_YYYYMMDD_HHMMSS.log`
- Contains complete details of the network scan including all discovered devices and their information

## Security Note

This tool is designed for network administrators to scan and monitor their own networks. Always ensure you have proper authorization before scanning any network.