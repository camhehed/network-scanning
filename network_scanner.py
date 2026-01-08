#!/usr/bin/env python3

import os
import sys
import subprocess
import socket
import datetime
import ipaddress
import argparse
import threading
import time
import json
import csv
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

class NetworkScanner:
    def __init__(self, config=None):
        self.config = config or {}
        self.output_dir = Path("scan_logs")
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.has_sudo = False
        self.dns_cache = {}
        self.vulnerability_findings = []
        
        # Load configuration
        self.target = self.config.get('target')
        self.quick_mode = self.config.get('quick', False)
        self.full_mode = self.config.get('full', False)
        self.output_format = self.config.get('output_format', 'txt')
        self.no_sudo = self.config.get('no_sudo', False)
        self.custom_ports = self.config.get('ports')
        self.check_defaults = self.config.get('check_defaults', False)
        
        if not self.no_sudo:
            self.check_sudo()
        
    def check_sudo(self):
        if self.no_sudo:
            self.has_sudo = False
            return
            
        try:
            result = subprocess.run(
                ['sudo', '-n', 'true'],
                capture_output=True,
                timeout=2,
                stdin=subprocess.DEVNULL
            )
            self.has_sudo = (result.returncode == 0)
        except Exception:
            self.has_sudo = False
            
        if not self.has_sudo:
            try:
                if sys.stdin.isatty():
                    subprocess.run(
                        ['sudo', '-v'],
                        timeout=5,
                        stdin=sys.stdin
                    )
                    result = subprocess.run(
                        ['sudo', '-n', 'true'],
                        capture_output=True,
                        timeout=2,
                        stdin=subprocess.DEVNULL
                    )
                    self.has_sudo = (result.returncode == 0)
            except Exception:
                self.has_sudo = False
    
    def command_exists(self, command):
        try:
            result = subprocess.run(
                ['which', command],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False
    
    def log_to_file(self, filename, content):
        filepath = self.output_dir / f"{self.timestamp}_{filename}"
        with open(filepath, 'a') as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {content}\n")
    
    def print_status(self, message):
        """Print status message to console for user feedback"""
        print(f"[*] {message}")
    
    def print_finding(self, message):
        """Print important finding to console"""
        print(f"[+] {message}")
    
    def print_warning(self, message):
        """Print warning to console"""
        print(f"[!] {message}")
    
    def log_vulnerability(self, vulnerability_type, target, details):
        """Log a vulnerability finding"""
        finding = {
            'timestamp': datetime.datetime.now().isoformat(),
            'type': vulnerability_type,
            'target': target,
            'details': details
        }
        self.vulnerability_findings.append(finding)
        self.log_to_file("vulnerabilities.txt", f"[{vulnerability_type}] {target}: {details}")
        self.print_warning(f"Vulnerability: {vulnerability_type} on {target}")
    
    def resolve_dns(self, ip):
        """Resolve IP to hostname with caching"""
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            self.dns_cache[ip] = None
            return None
    
    def get_mac_vendor(self, mac_address):
        """Get vendor information from MAC address"""
        # Simple OUI lookup - first 3 octets
        if not mac_address:
            return None
        
        # Common vendor prefixes (simplified database)
        vendors = {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:05:69': 'VMware',
            '08:00:27': 'Oracle VirtualBox',
            '52:54:00': 'QEMU/KVM',
            '00:16:3E': 'Xen',
            '00:1B:21': 'Intel',
            '00:1C:42': 'Parallels',
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            '00:0A:95': 'Apple',
            '00:1D:4F': 'Apple',
            '00:1F:5B': 'Apple',
            '28:6A:BA': 'Apple',
            '40:6C:8F': 'Apple',
            '00:25:00': 'Apple',
            '00:03:93': 'Apple',
            '00:19:E3': 'Apple',
            '00:1E:C2': 'Apple',
            '00:1F:F3': 'Apple',
            '00:23:12': 'Apple',
            '00:23:32': 'Apple',
            '00:23:6C': 'Apple',
            '00:23:DF': 'Apple',
            '00:24:36': 'Apple',
            '00:25:BC': 'Apple',
            '00:26:08': 'Apple',
            '00:26:4A': 'Apple',
            '00:26:B0': 'Apple',
            '00:26:BB': 'Apple',
            '00:D0:B7': 'Intel',
            '00:13:02': 'Intel',
            '00:15:00': 'Intel',
            '00:16:76': 'Intel',
            '00:16:EA': 'Intel',
            '00:16:EB': 'Intel',
            '00:18:DE': 'Intel',
            '00:19:D1': 'Intel',
            '00:19:D2': 'Intel',
            '00:1B:77': 'Intel',
            '00:1C:23': 'Intel',
            '00:1D:E0': 'Intel',
            '00:1D:E1': 'Intel',
            '00:1E:64': 'Intel',
            '00:1E:65': 'Intel',
            '00:1E:67': 'Intel',
            '00:1F:3A': 'Intel',
            '00:1F:3B': 'Intel',
            '00:1F:3C': 'Intel',
            '00:21:5C': 'Intel',
            '00:21:5D': 'Intel',
            '00:21:6A': 'Intel',
            '00:21:6B': 'Intel',
            '00:22:FA': 'Intel',
            '00:22:FB': 'Intel',
            '00:23:14': 'Intel',
            '00:23:15': 'Intel',
            '00:24:D6': 'Intel',
            '00:24:D7': 'Intel',
            '00:25:D3': 'Intel',
            '00:26:C6': 'Intel',
            '00:26:C7': 'Intel',
            '00:27:0E': 'Intel',
            '00:50:F2': 'Microsoft',
            '00:15:5D': 'Microsoft',
            '00:03:FF': 'Microsoft',
            '00:12:5A': 'Microsoft',
            '00:17:FA': 'Microsoft',
            '00:50:F1': 'Microsoft',
            '7C:1E:52': 'Microsoft',
            '00:0D:3A': 'Microsoft',
            '28:18:78': 'Microsoft',
            '00:01:5C': 'Cisco',
            '00:0B:45': 'Cisco',
            '00:0D:BC': 'Cisco',
            '00:0E:38': 'Cisco',
            '00:0E:83': 'Cisco',
            '00:0E:84': 'Cisco',
            '00:0F:23': 'Cisco',
            '00:0F:24': 'Cisco',
            '00:0F:8F': 'Cisco',
            '00:0F:90': 'Cisco',
            '00:10:07': 'Cisco',
            '00:10:11': 'Cisco',
            '00:10:29': 'Cisco',
            '00:10:2F': 'Cisco',
            '00:10:54': 'Cisco',
            '00:10:79': 'Cisco',
            '00:10:7B': 'Cisco',
            '00:10:A6': 'Cisco',
            '00:10:F6': 'Cisco',
            '00:10:FF': 'Cisco',
            '00:11:20': 'Cisco',
            '00:11:21': 'Cisco',
            '00:11:5C': 'Cisco',
            '00:11:5D': 'Cisco',
            '00:11:92': 'Cisco',
            '00:11:93': 'Cisco',
            '00:11:BB': 'Cisco',
            '00:12:00': 'Cisco',
            '00:12:01': 'Cisco',
            '00:12:17': 'Cisco',
            '00:12:43': 'Cisco',
            '00:12:44': 'Cisco',
            '00:12:7F': 'Cisco',
            '00:12:80': 'Cisco',
            '00:12:D9': 'Cisco',
            '00:12:DA': 'Cisco',
            '00:13:10': 'Cisco',
            '00:13:19': 'Cisco',
            '00:13:1A': 'Cisco',
            '00:13:5F': 'Cisco',
            '00:13:60': 'Cisco',
            '00:13:7F': 'Cisco',
            '00:13:80': 'Cisco',
            '00:13:C3': 'Cisco',
            '00:13:C4': 'Cisco',
            '00:14:1B': 'Cisco',
            '00:14:1C': 'Cisco',
            '00:14:69': 'Cisco',
            '00:14:6A': 'Cisco',
            '00:14:A8': 'Cisco',
            '00:14:A9': 'Cisco',
            '00:14:BF': 'Cisco',
            '00:14:F1': 'Cisco',
            '00:14:F2': 'Cisco',
        }
        
        # Normalize MAC address
        mac_prefix = ':'.join(mac_address.upper().split(':')[:3])
        
        return vendors.get(mac_prefix, 'Unknown Vendor')
    
    def grab_banner(self, ip, port, timeout=2):
        """Grab service banner from a port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Send a generic request for some services
            if port in [80, 8080, 8000]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 21:  # FTP
                pass  # FTP sends banner immediately
            elif port == 22:  # SSH
                pass  # SSH sends banner immediately
            elif port == 25:  # SMTP
                pass  # SMTP sends banner immediately
            elif port == 23:  # Telnet
                pass  # Telnet might send banner
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
        except (socket.timeout, socket.error, OSError):
            return None
    
    def check_anonymous_ftp(self, ip):
        """Check if FTP allows anonymous access"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, 21))
            
            # Read banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Try anonymous login
            sock.send(b"USER anonymous\r\n")
            time.sleep(0.5)
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.send(b"PASS anonymous@\r\n")
            time.sleep(0.5)
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.close()
            
            # Check if login was successful (230 response code)
            if '230' in response:
                return True
            return False
        except (socket.timeout, socket.error, OSError):
            return False
    
    def is_host_alive(self, ip):
        """Check if host is alive using multiple methods"""
        # Method 1: ICMP Ping
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                return True, 'ICMP'
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        
        # Method 2: TCP connect to common ports
        common_ports = [22, 80, 443, 445]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True, f'TCP-{port}'
            except (socket.error, OSError):
                continue
        
        # Method 3: UDP probe (simplified check)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'\x00', (ip, 53))  # DNS
            sock.close()
            return True, 'UDP-53'
        except (socket.error, OSError):
            pass
        
        return False, None
    
    def test_ssh_credentials(self, ip, port=22, timeout=3):
        """Test common SSH credentials (requires paramiko or basic socket test)"""
        # Note: Full SSH credential testing requires paramiko library
        # This is a placeholder that checks if SSH is accessible
        findings = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                findings.append({
                    'service': 'SSH',
                    'port': port,
                    'status': 'accessible',
                    'note': 'SSH accessible - manual credential testing recommended'
                })
        except (socket.error, OSError):
            pass
        
        return findings
    
    def test_ftp_credentials(self, ip, port=21, timeout=3):
        """Test common FTP credentials"""
        findings = []
        credentials = [
            ('anonymous', 'anonymous'),
            ('anonymous', 'anonymous@'),
            ('ftp', 'ftp'),
            ('admin', 'admin'),
            ('root', 'root'),
        ]
        
        for username, password in credentials:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((ip, port))
                
                # Read banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Try login
                sock.send(f"USER {username}\r\n".encode())
                time.sleep(0.3)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                sock.send(f"PASS {password}\r\n".encode())
                time.sleep(0.3)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                sock.close()
                
                # Check if login was successful (230 response code)
                if '230' in response:
                    findings.append({
                        'service': 'FTP',
                        'port': port,
                        'username': username,
                        'password': password,
                        'status': 'SUCCESS'
                    })
                    self.log_vulnerability(
                        'Default Credentials',
                        f"{ip}:{port}",
                        f"FTP allows login with {username}/{password}"
                    )
                
                time.sleep(0.5)  # Rate limiting
            except (socket.timeout, socket.error, OSError):
                continue
        
        return findings
    
    def test_telnet_credentials(self, ip, port=23, timeout=3):
        """Test common Telnet credentials"""
        findings = []
        # Note: Full telnet testing is complex due to terminal negotiation
        # This checks if telnet is accessible
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                findings.append({
                    'service': 'Telnet',
                    'port': port,
                    'status': 'accessible',
                    'note': 'Telnet accessible - UNENCRYPTED PROTOCOL'
                })
                self.log_vulnerability(
                    'Insecure Protocol',
                    f"{ip}:{port}",
                    "Telnet is unencrypted and should not be used"
                )
        except (socket.error, OSError):
            pass
        
        return findings
    
    def test_database_credentials(self, ip):
        """Test for unauthenticated database access"""
        findings = []
        
        # MySQL (3306)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 3306))
            sock.close()
            if result == 0:
                findings.append({
                    'service': 'MySQL',
                    'port': 3306,
                    'status': 'accessible',
                    'note': 'MySQL port exposed'
                })
                self.log_vulnerability(
                    'Exposed Database',
                    f"{ip}:3306",
                    "MySQL port is accessible"
                )
        except (socket.error, OSError):
            pass
        
        # PostgreSQL (5432)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 5432))
            sock.close()
            if result == 0:
                findings.append({
                    'service': 'PostgreSQL',
                    'port': 5432,
                    'status': 'accessible',
                    'note': 'PostgreSQL port exposed'
                })
                self.log_vulnerability(
                    'Exposed Database',
                    f"{ip}:5432",
                    "PostgreSQL port is accessible"
                )
        except (socket.error, OSError):
            pass
        
        # MongoDB (27017)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 27017))
            sock.close()
            if result == 0:
                findings.append({
                    'service': 'MongoDB',
                    'port': 27017,
                    'status': 'accessible',
                    'note': 'MongoDB port exposed'
                })
                self.log_vulnerability(
                    'Exposed Database',
                    f"{ip}:27017",
                    "MongoDB port is accessible"
                )
        except (socket.error, OSError):
            pass
        
        # Redis (6379)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 6379))
            sock.close()
            if result == 0:
                findings.append({
                    'service': 'Redis',
                    'port': 6379,
                    'status': 'accessible',
                    'note': 'Redis port exposed'
                })
                self.log_vulnerability(
                    'Exposed Database',
                    f"{ip}:6379",
                    "Redis port is accessible"
                )
        except (socket.error, OSError):
            pass
        
        return findings
    
    def check_default_credentials(self, ip, open_ports):
        """Main function to check default credentials on discovered services"""
        if not self.check_defaults:
            return []
        
        self.print_warning("Starting default credential checks - USE ONLY ON AUTHORIZED NETWORKS")
        self.log_to_file("security_audit.txt", f"=== Default Credential Check for {ip} ===")
        
        all_findings = []
        
        # Test based on open ports
        for port in open_ports:
            if port == 21:  # FTP
                findings = self.test_ftp_credentials(ip, port)
                all_findings.extend(findings)
            elif port == 22:  # SSH
                findings = self.test_ssh_credentials(ip, port)
                all_findings.extend(findings)
            elif port == 23:  # Telnet
                findings = self.test_telnet_credentials(ip, port)
                all_findings.extend(findings)
        
        # Test database ports
        db_findings = self.test_database_credentials(ip)
        all_findings.extend(db_findings)
        
        # Log all findings
        for finding in all_findings:
            self.log_to_file("security_audit.txt", f"Finding: {json.dumps(finding, indent=2)}")
        
        return all_findings
    
    def run_command(self, cmd, use_sudo=False):
        try:
            if use_sudo and self.has_sudo:
                cmd = ['sudo'] + cmd
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            return f"Error: {str(e)}"
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except (socket.error, OSError):
            return "127.0.0.1"
    
    def get_network_range(self):
        local_ip = self.get_local_ip()
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network)
    
    def scan_network_arp(self):
        self.print_status("Starting network discovery...")
        self.log_to_file("network_scan.txt", "=== Network Discovery (ARP + Multi-Method) ===")
        
        network_range = self.get_network_range()
        self.log_to_file("network_scan.txt", f"Scanning network: {network_range}")
        self.print_status(f"Scanning network: {network_range}")
        
        # Get ARP table
        output = self.run_command(['arp', '-a'])
        self.log_to_file("network_scan.txt", output)
        
        # Parse ARP output to get discovered hosts
        discovered_hosts = []
        import re
        for line in output.split('\n'):
            # Match IP addresses in ARP output
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
            
            if ip_match:
                ip = ip_match.group(0)
                mac = mac_match.group(0) if mac_match else None
                
                if ip not in ['255.255.255.255', '0.0.0.0']:
                    discovered_hosts.append({'ip': ip, 'mac': mac, 'method': 'ARP'})
        
        # Enhanced host discovery using multiple methods
        self.print_status("Performing multi-method host discovery...")
        network = ipaddress.IPv4Network(network_range, strict=False)
        
        def check_host(ip_str):
            alive, method = self.is_host_alive(ip_str)
            if alive:
                # Get DNS name
                hostname = self.resolve_dns(ip_str)
                
                # Try to get MAC from ARP (if available)
                mac = None
                for host in discovered_hosts:
                    if host['ip'] == ip_str:
                        mac = host['mac']
                        break
                
                return {
                    'ip': ip_str,
                    'hostname': hostname,
                    'mac': mac,
                    'vendor': self.get_mac_vendor(mac) if mac else None,
                    'method': method
                }
            return None
        
        # Scan network with threading (limit to avoid overwhelming the network)
        max_hosts = 20 if self.quick_mode else 50
        hosts_to_check = list(network.hosts())[:max_hosts]
        
        alive_hosts = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_host, str(ip)): ip for ip in hosts_to_check}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive_hosts.append(result)
                    
                    # Log and display the finding
                    host_info = f"Host: {result['ip']}"
                    if result['hostname']:
                        host_info += f" ({result['hostname']})"
                    if result['vendor']:
                        host_info += f" - {result['vendor']}"
                    host_info += f" [detected via {result['method']}]"
                    
                    self.log_to_file("network_scan.txt", host_info)
                    self.print_finding(host_info)
        
        self.print_status(f"Discovered {len(alive_hosts)} alive hosts")
        
        # Log DNS resolutions
        self.log_to_file("network_scan.txt", "\n=== DNS Resolutions ===")
        for host in alive_hosts:
            if host['hostname']:
                self.log_to_file("network_scan.txt", f"{host['ip']} -> {host['hostname']}")
        
        # Log MAC vendors
        self.log_to_file("network_scan.txt", "\n=== MAC Vendor Information ===")
        for host in alive_hosts:
            if host['mac'] and host['vendor']:
                self.log_to_file("network_scan.txt", f"{host['ip']} - {host['mac']} - {host['vendor']}")
        
        # Optionally run nmap for deeper analysis
        if self.has_sudo and self.command_exists('nmap') and not self.quick_mode:
            self.print_status("Running nmap host discovery...")
            nmap_output = self.run_command(
                ['nmap', '-sn', network_range],
                use_sudo=True
            )
            self.log_to_file("network_scan.txt", "\n=== Nmap Host Discovery ===")
            self.log_to_file("network_scan.txt", nmap_output)
        elif not self.command_exists('nmap'):
            self.log_to_file("network_scan.txt", "\n=== Nmap not available ===")
        
        return alive_hosts
    
    def scan_ports(self, target_ip):
        self.print_status(f"Scanning ports on {target_ip}")
        self.log_to_file("port_scan.txt", f"=== Port Scan for {target_ip} ===")
        
        # Determine port list based on mode
        if self.custom_ports:
            # Parse custom port range
            try:
                if '-' in self.custom_ports:
                    parts = self.custom_ports.split('-')
                    if len(parts) != 2:
                        raise ValueError("Invalid port range format")
                    start, end = int(parts[0]), int(parts[1])
                    if start < 1 or end > 65535 or start > end:
                        raise ValueError("Port numbers must be between 1-65535 and start <= end")
                    ports_to_scan = list(range(start, end + 1))
                elif ',' in self.custom_ports:
                    ports_to_scan = []
                    for p in self.custom_ports.split(','):
                        port_num = int(p.strip())
                        if port_num < 1 or port_num > 65535:
                            raise ValueError(f"Port number {port_num} out of valid range (1-65535)")
                        ports_to_scan.append(port_num)
                else:
                    port_num = int(self.custom_ports)
                    if port_num < 1 or port_num > 65535:
                        raise ValueError(f"Port number {port_num} out of valid range (1-65535)")
                    ports_to_scan = [port_num]
            except ValueError as e:
                self.print_warning(f"Invalid port specification: {e}")
                self.print_warning("Using default ports instead")
                ports_to_scan = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 27017]
        elif self.full_mode:
            # Full mode: scan all common ports (1-65535 would be too slow, so use extended list)
            ports_to_scan = list(range(1, 1001)) + [1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9090, 27017]
        elif self.quick_mode:
            # Quick mode: only most common ports
            ports_to_scan = [21, 22, 23, 80, 443, 445, 3389]
        else:
            # Default mode
            ports_to_scan = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 27017]
        
        open_ports = []
        timeout = 0.3 if self.quick_mode else 0.5
        
        # Use threading for faster port scanning
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    # Grab banner
                    banner = self.grab_banner(target_ip, port, timeout=2)
                    
                    # Log the finding
                    if banner:
                        self.log_to_file("port_scan.txt", f"Port {port} is OPEN on {target_ip} - Banner: {banner[:100]}")
                        self.print_finding(f"Port {port} open on {target_ip} - {banner[:50]}")
                    else:
                        self.log_to_file("port_scan.txt", f"Port {port} is OPEN on {target_ip}")
                        self.print_finding(f"Port {port} open on {target_ip}")
                    
                    # Check for vulnerabilities
                    self.check_port_vulnerability(target_ip, port, banner)
                    
                    sock.close()
                    return port, banner
                sock.close()
            except (socket.error, OSError):
                pass
            return None, None
        
        # Scan ports with threading (reduced workers for less aggressive scanning)
        max_workers = 10 if self.quick_mode else 20
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports_to_scan}
            for future in as_completed(futures):
                port, banner = future.result()
                if port:
                    open_ports.append(port)
        
        self.print_status(f"Found {len(open_ports)} open ports on {target_ip}")
        
        # Check for anonymous FTP if port 21 is open
        if 21 in open_ports:
            self.print_status("Checking for anonymous FTP access...")
            if self.check_anonymous_ftp(target_ip):
                self.log_vulnerability(
                    'Anonymous Access',
                    f"{target_ip}:21",
                    "FTP allows anonymous access"
                )
        
        # Run default credential checks if enabled
        if self.check_defaults and open_ports:
            self.check_default_credentials(target_ip, open_ports)
        
        # Optionally run nmap for deeper analysis
        if self.has_sudo and self.command_exists('nmap') and not self.quick_mode:
            nmap_output = self.run_command(
                ['nmap', '-sV', '-p', '1-1000', target_ip],
                use_sudo=True
            )
            self.log_to_file("port_scan.txt", f"\n=== Nmap Service Detection {target_ip} ===")
            self.log_to_file("port_scan.txt", nmap_output)
        elif not self.command_exists('nmap'):
            self.log_to_file("port_scan.txt", "\n=== Nmap not available ===")
        
        return open_ports
    
    def check_port_vulnerability(self, ip, port, banner):
        """Check for known vulnerabilities based on port and banner"""
        # Telnet
        if port == 23:
            self.log_vulnerability(
                'Insecure Protocol',
                f"{ip}:{port}",
                "Telnet is unencrypted and vulnerable to eavesdropping"
            )
        
        # FTP
        if port == 21:
            self.log_vulnerability(
                'Potentially Insecure',
                f"{ip}:{port}",
                "FTP is often misconfigured and may transmit credentials in plaintext"
            )
        
        # SMB
        if port == 445:
            self.log_vulnerability(
                'SMB Exposed',
                f"{ip}:{port}",
                "SMB port exposed - potential security risk (EternalBlue, etc.)"
            )
        
        # Database ports
        db_ports = {
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB',
            6379: 'Redis'
        }
        if port in db_ports:
            self.log_vulnerability(
                'Exposed Database',
                f"{ip}:{port}",
                f"{db_ports[port]} database port is exposed to network"
            )
        
        # Check for outdated versions in banner
        if banner:
            # Common outdated version patterns (simplified)
            if 'OpenSSH_5' in banner or 'OpenSSH_6' in banner:
                self.log_vulnerability(
                    'Outdated Software',
                    f"{ip}:{port}",
                    f"Potentially outdated SSH version detected: {banner[:100]}"
                )
            elif 'Apache/2.2' in banner or 'Apache/2.0' in banner:
                self.log_vulnerability(
                    'Outdated Software',
                    f"{ip}:{port}",
                    f"Outdated Apache version detected: {banner[:100]}"
                )
    
    def detect_os(self, target_ip):
        self.log_to_file("os_detection.txt", f"=== OS Detection for {target_ip} ===")
        
        if not self.command_exists('nmap'):
            self.log_to_file("os_detection.txt", "OS detection requires nmap (not available)")
        elif self.has_sudo:
            nmap_output = self.run_command(
                ['nmap', '-O', target_ip],
                use_sudo=True
            )
            self.log_to_file("os_detection.txt", nmap_output)
        else:
            self.log_to_file("os_detection.txt", "OS detection requires sudo privileges (not available)")
    
    def check_latency(self, target_ip):
        self.log_to_file("latency.txt", f"=== Latency check for {target_ip} ===")
        
        output = self.run_command(['ping', '-c', '2', '-W', '2', target_ip])
        self.log_to_file("latency.txt", output)
    
    def traceroute(self, target_ip):
        self.log_to_file("traceroute.txt", f"=== Traceroute to {target_ip} ===")
        
        if self.command_exists('traceroute'):
            cmd = ['traceroute', target_ip]
            output = self.run_command(cmd)
            self.log_to_file("traceroute.txt", output)
        elif self.command_exists('tracert'):
            cmd = ['tracert', target_ip]
            output = self.run_command(cmd)
            self.log_to_file("traceroute.txt", output)
        else:
            self.log_to_file("traceroute.txt", "Traceroute command not available")
    
    def whois_lookup(self, target_ip):
        self.log_to_file("whois.txt", f"=== WHOIS lookup for {target_ip} ===")
        
        if self.command_exists('whois'):
            output = self.run_command(['whois', target_ip])
            self.log_to_file("whois.txt", output)
        else:
            self.log_to_file("whois.txt", "WHOIS command not available")
    
    def collect_login_sessions(self):
        self.log_to_file("login_sessions.txt", "=== Current Login Sessions ===")
        
        who_output = self.run_command(['who'])
        self.log_to_file("login_sessions.txt", who_output)
        
        w_output = self.run_command(['w'])
        self.log_to_file("login_sessions.txt", "\n=== Detailed User Activity (w) ===")
        self.log_to_file("login_sessions.txt", w_output)
        
        last_output = self.run_command(['last', '-20'])
        self.log_to_file("login_sessions.txt", "\n=== Recent Login History (last) ===")
        self.log_to_file("login_sessions.txt", last_output)
        
        if self.has_sudo:
            lastb_output = self.run_command(['lastb', '-20'], use_sudo=True)
            self.log_to_file("login_sessions.txt", "\n=== Failed Login Attempts (lastb) ===")
            self.log_to_file("login_sessions.txt", lastb_output)
    
    def collect_active_users(self):
        self.log_to_file("active_users.txt", "=== Active Users on System ===")
        
        users_output = self.run_command(['users'])
        self.log_to_file("active_users.txt", users_output)
        
        who_output = self.run_command(['who', '-H'])
        self.log_to_file("active_users.txt", "\n=== Who is logged in ===")
        self.log_to_file("active_users.txt", who_output)
        
        if self.command_exists('finger'):
            finger_output = self.run_command(['finger'])
            self.log_to_file("active_users.txt", "\n=== Finger output ===")
            self.log_to_file("active_users.txt", finger_output)
        else:
            self.log_to_file("active_users.txt", "\n=== Finger not available ===")
    
    def collect_auth_logs(self):
        self.log_to_file("auth_logs.txt", "=== Authentication Logs ===")
        
        if self.has_sudo:
            auth_log_paths = [
                '/var/log/auth.log',
                '/var/log/secure',
                '/var/log/messages'
            ]
            
            for log_path in auth_log_paths:
                if os.path.exists(log_path):
                    tail_output = self.run_command(
                        ['tail', '-100', log_path],
                        use_sudo=True
                    )
                    self.log_to_file("auth_logs.txt", f"\n=== {log_path} (last 100 lines) ===")
                    self.log_to_file("auth_logs.txt", tail_output)
            
            if self.command_exists('journalctl'):
                journalctl_output = self.run_command(
                    ['journalctl', '-u', 'ssh', '-n', '100', '--no-pager'],
                    use_sudo=True
                )
                self.log_to_file("auth_logs.txt", "\n=== SSH Authentication Logs (journalctl) ===")
                self.log_to_file("auth_logs.txt", journalctl_output)
        else:
            self.log_to_file("auth_logs.txt", "Authentication log access requires sudo privileges (not available)")
    
    def collect_network_connections(self):
        self.log_to_file("network_connections.txt", "=== Active Network Connections ===")
        
        if self.has_sudo:
            ss_output = self.run_command(['ss', '-tunapl'], use_sudo=True)
            self.log_to_file("network_connections.txt", ss_output)
        else:
            ss_output = self.run_command(['ss', '-tuna'])
            self.log_to_file("network_connections.txt", ss_output)
        
        netstat_output = self.run_command(['netstat', '-an'])
        self.log_to_file("network_connections.txt", "\n=== Netstat output ===")
        self.log_to_file("network_connections.txt", netstat_output)
    
    def collect_login_activity(self):
        self.log_to_file("login_activity.txt", "=== Login Activity Analysis ===")
        
        if self.command_exists('lastlog'):
            lastlog_output = self.run_command(['lastlog'])
            self.log_to_file("login_activity.txt", lastlog_output)
        else:
            self.log_to_file("login_activity.txt", "lastlog command not available")
        
        if self.has_sudo and self.command_exists('utmpdump'):
            utmpdump_output = self.run_command(
                ['utmpdump', '/var/log/wtmp'],
                use_sudo=True
            )
            self.log_to_file("login_activity.txt", "\n=== WTMP Dump (login records) ===")
            self.log_to_file("login_activity.txt", utmpdump_output)
        
        self.log_to_file("login_activity.txt", "\n=== Login History (last -F) ===")
        last_full_output = self.run_command(['last', '-F', '-20'])
        self.log_to_file("login_activity.txt", last_full_output)
    
    def export_results_json(self, scan_results):
        """Export scan results to JSON format"""
        filepath = self.output_dir / f"{self.timestamp}_results.json"
        with open(filepath, 'w') as f:
            json.dump(scan_results, f, indent=2, default=str)
        self.print_status(f"Results exported to {filepath}")
    
    def export_results_csv(self, scan_results):
        """Export scan results to CSV format"""
        filepath = self.output_dir / f"{self.timestamp}_results.csv"
        
        with open(filepath, 'w', newline='') as f:
            if 'hosts' in scan_results and scan_results['hosts']:
                fieldnames = ['ip', 'hostname', 'mac', 'vendor', 'open_ports', 'vulnerabilities']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for host in scan_results.get('hosts', []):
                    row = {
                        'ip': host.get('ip', ''),
                        'hostname': host.get('hostname', ''),
                        'mac': host.get('mac', ''),
                        'vendor': host.get('vendor', ''),
                        'open_ports': ','.join(map(str, host.get('open_ports', []))),
                        'vulnerabilities': len(host.get('vulnerabilities', []))
                    }
                    writer.writerow(row)
        
        self.print_status(f"Results exported to {filepath}")
    
    def export_results(self, scan_results):
        """Export results based on configured format"""
        if self.output_format == 'json':
            self.export_results_json(scan_results)
        elif self.output_format == 'csv':
            self.export_results_csv(scan_results)
        elif self.output_format == 'txt':
            # TXT format is default (log files)
            self.print_status("Results logged to scan_logs/ directory")
    
    def scan_full_network(self):
        self.print_status("Network scanning started")
        self.log_to_file("scan_summary.txt", "=== Network Scanning Started ===")
        
        scan_results = {
            'timestamp': self.timestamp,
            'hosts': [],
            'vulnerabilities': []
        }
        
        # If specific target is provided, scan only that target
        if self.target:
            self.print_status(f"Scanning specific target: {self.target}")
            self.log_to_file("scan_summary.txt", f"Target: {self.target}")
            
            # Check if target is alive
            alive, method = self.is_host_alive(self.target)
            if alive:
                self.print_finding(f"Target {self.target} is alive (detected via {method})")
                
                # Get DNS and other info
                hostname = self.resolve_dns(self.target)
                
                # Scan ports
                open_ports = self.scan_ports(self.target)
                
                # Optionally detect OS
                if not self.quick_mode:
                    self.detect_os(self.target)
                    self.check_latency(self.target)
                    self.traceroute(self.target)
                
                scan_results['hosts'].append({
                    'ip': self.target,
                    'hostname': hostname,
                    'open_ports': open_ports,
                    'vulnerabilities': [v for v in self.vulnerability_findings if self.target in v['target']]
                })
            else:
                self.print_warning(f"Target {self.target} appears to be down")
        
        else:
            # Scan full network
            self.print_status("Performing network-wide scan")
            alive_hosts = self.scan_network_arp()
            
            local_ip = self.get_local_ip()
            self.log_to_file("scan_summary.txt", f"Local IP: {local_ip}")
            self.print_status(f"Local IP: {local_ip}")
            
            # Scan ports on local machine
            self.print_status(f"Scanning local machine: {local_ip}")
            local_ports = self.scan_ports(local_ip)
            
            if not self.quick_mode:
                self.detect_os(local_ip)
                self.check_latency("8.8.8.8")
                self.traceroute("8.8.8.8")
                
                # Collect authentication and login information
                self.print_status("Collecting authentication logs...")
                self.collect_login_sessions()
                self.collect_active_users()
                self.collect_auth_logs()
                self.collect_network_connections()
                self.collect_login_activity()
            
            # Add local machine to results
            scan_results['hosts'].append({
                'ip': local_ip,
                'hostname': self.resolve_dns(local_ip),
                'open_ports': local_ports,
                'vulnerabilities': [v for v in self.vulnerability_findings if local_ip in v['target']]
            })
            
            # Scan other alive hosts
            for host in alive_hosts:
                if host['ip'] != local_ip:
                    self.print_status(f"Scanning {host['ip']}")
                    host_ports = self.scan_ports(host['ip'])
                    
                    scan_results['hosts'].append({
                        'ip': host['ip'],
                        'hostname': host.get('hostname'),
                        'mac': host.get('mac'),
                        'vendor': host.get('vendor'),
                        'open_ports': host_ports,
                        'vulnerabilities': [v for v in self.vulnerability_findings if host['ip'] in v['target']]
                    })
        
        # Collect all vulnerabilities
        scan_results['vulnerabilities'] = self.vulnerability_findings
        
        # Export results if needed
        self.export_results(scan_results)
        
        self.log_to_file("scan_summary.txt", "=== Network Scanning Completed ===")
        self.print_status("Network scanning completed")
        
        # Print summary
        self.print_status(f"Total hosts scanned: {len(scan_results['hosts'])}")
        self.print_status(f"Total vulnerabilities found: {len(scan_results['vulnerabilities'])}")
        
        return scan_results

def print_banner():
    """Print tool banner and security disclaimer"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║         Network Scanner - Advanced Security Tool             ║
╚══════════════════════════════════════════════════════════════╝

⚠️  SECURITY DISCLAIMER ⚠️

This tool should ONLY be used on networks you own or have 
explicit written permission to test.

Unauthorized network scanning and credential testing may be:
  • Illegal in your jurisdiction
  • Violation of computer fraud and abuse laws
  • Grounds for civil and criminal prosecution

The authors assume NO LIABILITY for misuse of this tool.
Use for authorized penetration testing and security auditing only.

By using this tool, you acknowledge that you have permission to
scan the target network and accept full responsibility for your actions.

════════════════════════════════════════════════════════════════
"""
    print(banner)

def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='Advanced Network Scanner - Security Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan (auto-detect network)
  python3 network_scanner.py

  # Scan specific target
  python3 network_scanner.py --target 192.168.1.1

  # Quick scan with no sudo
  python3 network_scanner.py --quick --no-sudo

  # Full scan with all features
  python3 network_scanner.py --full --check-defaults

  # Scan custom ports and export to JSON
  python3 network_scanner.py --target 192.168.1.1 --ports 1-100 --output-format json

  # Scan common web ports
  python3 network_scanner.py --target example.com --ports 80,443,8080,8443
        """
    )
    
    parser.add_argument(
        '--target',
        help='Scan specific target IP or hostname (default: auto-detect network)',
        type=str
    )
    
    parser.add_argument(
        '--quick',
        help='Fast scan mode (fewer ports, shorter timeouts)',
        action='store_true'
    )
    
    parser.add_argument(
        '--full',
        help='Comprehensive scan (more ports, deeper analysis)',
        action='store_true'
    )
    
    parser.add_argument(
        '--output-format',
        help='Output format for scan results',
        choices=['json', 'csv', 'txt'],
        default='txt'
    )
    
    parser.add_argument(
        '--no-sudo',
        help='Skip sudo operations entirely',
        action='store_true'
    )
    
    parser.add_argument(
        '--ports',
        help='Custom port range (e.g., "1-1000" or "22,80,443")',
        type=str
    )
    
    parser.add_argument(
        '--check-defaults',
        '--brute',
        help='⚠️  Check for default/common credentials (AUTHORIZED USE ONLY)',
        action='store_true',
        dest='check_defaults'
    )
    
    return parser.parse_args()

def main():
    # Print banner and disclaimer
    print_banner()
    
    # Parse arguments
    args = parse_arguments()
    
    # Show warning for offensive features
    if args.check_defaults:
        print("\n⚠️  WARNING: Default credential checking enabled!")
        print("This feature performs active authentication attempts.")
        print("Ensure you have authorization before proceeding.\n")
        
        try:
            response = input("Do you have authorization to test credentials on this network? (yes/no): ")
            if response.lower() not in ['yes', 'y']:
                print("Aborting scan. Authorization required for credential testing.")
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            print("\nScan aborted by user.")
            sys.exit(0)
    
    # Create configuration from arguments
    config = {
        'target': args.target,
        'quick': args.quick,
        'full': args.full,
        'output_format': args.output_format,
        'no_sudo': args.no_sudo,
        'ports': args.ports,
        'check_defaults': args.check_defaults
    }
    
    # Initialize scanner with configuration
    scanner = NetworkScanner(config)
    
    try:
        # Run the scan
        scanner.scan_full_network()
        print("\n✓ Scan completed successfully!")
        print(f"Results saved to: {scanner.output_dir}/")
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Error during scan: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
