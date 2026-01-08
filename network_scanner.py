#!/usr/bin/env python3

import os
import sys
import subprocess
import socket
import datetime
import ipaddress
import threading
from pathlib import Path
import json
import time
import re

class NetworkScanner:
    def __init__(self):
        self.output_dir = Path("scan_logs")
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.has_sudo = False
        self.check_sudo()
        
    def check_sudo(self):
        try:
            result = subprocess.run(
                ['sudo', '-n', 'true'],
                capture_output=True,
                timeout=2,
                stdin=subprocess.DEVNULL
            )
            self.has_sudo = (result.returncode == 0)
        except:
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
            except:
                self.has_sudo = False
    
    def command_exists(self, command):
        try:
            subprocess.run(
                ['which', command],
                capture_output=True,
                timeout=2
            )
            return True
        except:
            return False
    
    def log_to_file(self, filename, content):
        filepath = self.output_dir / f"{self.timestamp}_{filename}"
        with open(filepath, 'a') as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {content}\n")
    
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
        except Exception as e:
            return f"Error: {str(e)}"
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def get_network_range(self):
        local_ip = self.get_local_ip()
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network)
    
    def scan_network_arp(self):
        self.log_to_file("network_scan.txt", "=== Network Discovery (ARP) ===")
        
        network_range = self.get_network_range()
        self.log_to_file("network_scan.txt", f"Scanning network: {network_range}")
        
        output = self.run_command(['arp', '-a'])
        self.log_to_file("network_scan.txt", output)
        
        if self.has_sudo and self.command_exists('nmap'):
            nmap_output = self.run_command(
                ['nmap', '-sn', network_range],
                use_sudo=True
            )
            self.log_to_file("network_scan.txt", "\n=== Nmap Host Discovery ===")
            self.log_to_file("network_scan.txt", nmap_output)
        elif not self.command_exists('nmap'):
            self.log_to_file("network_scan.txt", "\n=== Nmap not available ===")
    
    def scan_ports(self, target_ip):
        self.log_to_file("port_scan.txt", f"=== Port Scan for {target_ip} ===")
        
        common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    self.log_to_file("port_scan.txt", f"Port {port} is OPEN on {target_ip}")
                sock.close()
            except:
                pass
        
        if self.has_sudo and self.command_exists('nmap'):
            nmap_output = self.run_command(
                ['nmap', '-sV', '-p', '1-1000', target_ip],
                use_sudo=True
            )
            self.log_to_file("port_scan.txt", f"\n=== Nmap Service Detection {target_ip} ===")
            self.log_to_file("port_scan.txt", nmap_output)
        elif not self.command_exists('nmap'):
            self.log_to_file("port_scan.txt", "\n=== Nmap not available ===")
    
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
    
    def scan_full_network(self):
        self.log_to_file("scan_summary.txt", "=== Network Scanning Started ===")
        
        self.scan_network_arp()
        
        local_ip = self.get_local_ip()
        self.log_to_file("scan_summary.txt", f"Local IP: {local_ip}")
        
        self.scan_ports(local_ip)
        self.detect_os(local_ip)
        self.check_latency("8.8.8.8")
        self.traceroute("8.8.8.8")
        
        self.collect_login_sessions()
        self.collect_active_users()
        self.collect_auth_logs()
        self.collect_network_connections()
        self.collect_login_activity()
        
        network_range = self.get_network_range()
        network = ipaddress.IPv4Network(network_range)
        
        scanned_ips = []
        for ip in list(network.hosts())[:5]:
            ip_str = str(ip)
            if ip_str != local_ip:
                scanned_ips.append(ip_str)
        
        for ip in scanned_ips[:3]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((ip, 80))
                sock.close()
                
                if result == 0 or True:
                    self.check_latency(ip)
            except:
                pass
        
        self.log_to_file("scan_summary.txt", "=== Network Scanning Completed ===")

def main():
    scanner = NetworkScanner()
    scanner.scan_full_network()

if __name__ == "__main__":
    main()
