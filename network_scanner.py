#!/usr/bin/env python3

import os
import sys
import time
import socket
import platform
from datetime import datetime

try:
    import netifaces
    from scapy.all import ARP, Ether, srp, IP, ICMP, TCP, sr1, sr
    import nmap
    import dns.resolver
    import dns.reversename
    import whois
    import requests
except ImportError as e:
    print(f"Error: Required module not found: {e}")
    print("Please install required packages: pip install -r requirements.txt")
    sys.exit(1)


class NetworkScanner:
    def __init__(self):
        self.log_dir = "logs"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = None
        self.network_info = {}
        self.devices = []
        
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        log_filename = os.path.join(self.log_dir, f"network_scan_{self.timestamp}.log")
        try:
            self.log_file = open(log_filename, 'w')
        except Exception as e:
            print(f"Error creating log file: {e}")
            sys.exit(1)
        
    def log(self, message, print_to_console=True):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        self.log_file.write(log_message + "\n")
        self.log_file.flush()
        if print_to_console:
            print(log_message)
    
    def get_default_gateway_info(self):
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {}).get(netifaces.AF_INET, None)
            if default_gateway:
                return default_gateway[0], default_gateway[1]
            return None, None
        except Exception as e:
            self.log(f"Error getting default gateway: {e}")
            return None, None
    
    def get_network_interface_info(self):
        self.log("=" * 80)
        self.log("NETWORK INTERFACE DETECTION")
        self.log("=" * 80)
        
        try:
            gateway_ip, interface_name = self.get_default_gateway_info()
            
            if not interface_name:
                interfaces = netifaces.interfaces()
                for iface in interfaces:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip = addrs[netifaces.AF_INET][0]['addr']
                        if not ip.startswith('127.'):
                            interface_name = iface
                            break
            
            if not interface_name:
                self.log("Error: Could not detect network interface")
                return None
            
            addrs = netifaces.ifaddresses(interface_name)
            
            if netifaces.AF_INET not in addrs:
                self.log(f"Error: No IPv4 address found on interface {interface_name}")
                return None
            
            ipv4_info = addrs[netifaces.AF_INET][0]
            ip_address = ipv4_info['addr']
            netmask = ipv4_info['netmask']
            
            mac_address = None
            if netifaces.AF_LINK in addrs:
                mac_address = addrs[netifaces.AF_LINK][0].get('addr', 'N/A')
            
            self.network_info = {
                'interface': interface_name,
                'ip': ip_address,
                'netmask': netmask,
                'gateway': gateway_ip if gateway_ip else 'N/A',
                'mac': mac_address if mac_address else 'N/A'
            }
            
            self.log(f"Interface: {interface_name}")
            self.log(f"IP Address: {ip_address}")
            self.log(f"Netmask: {netmask}")
            self.log(f"Gateway: {gateway_ip if gateway_ip else 'N/A'}")
            self.log(f"MAC Address: {mac_address if mac_address else 'N/A'}")
            
            ip_parts = list(map(int, ip_address.split('.')))
            netmask_parts = list(map(int, netmask.split('.')))
            
            network_parts = [ip_parts[i] & netmask_parts[i] for i in range(4)]
            network_address = '.'.join(map(str, network_parts))
            
            cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
            network_range = f"{network_address}/{cidr}"
            
            self.network_info['network_range'] = network_range
            self.log(f"Network Range: {network_range}")
            
            return network_range
            
        except Exception as e:
            self.log(f"Error detecting network interface: {e}")
            return None
    
    def scan_active_devices(self, network_range):
        self.log("\n" + "=" * 80)
        self.log("SCANNING FOR ACTIVE DEVICES (ARP)")
        self.log("=" * 80)
        self.log(f"Scanning network: {network_range}")
        
        try:
            arp_request = ARP(pdst=network_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            answered_list = srp(arp_request_broadcast, timeout=3, verbose=False)[0]
            
            self.log(f"\nFound {len(answered_list)} active device(s):\n")
            
            for element in answered_list:
                device_info = {
                    'ip': element[1].psrc,
                    'mac': element[1].hwsrc,
                    'hostname': 'Unknown',
                    'dns': [],
                    'open_ports': [],
                    'services': [],
                    'os': 'Unknown',
                    'latency': 0,
                    'traceroute': [],
                    'whois': {}
                }
                self.devices.append(device_info)
                self.log(f"IP: {device_info['ip']:<15} MAC: {device_info['mac']}")
            
            return len(answered_list)
            
        except Exception as e:
            self.log(f"Error during ARP scan: {e}")
            return 0
    
    def get_hostname_and_dns(self, ip):
        hostname = 'Unknown'
        dns_records = []
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            pass
        
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev_name, "PTR")
            for rdata in answers:
                dns_records.append(str(rdata))
        except:
            pass
        
        return hostname, dns_records
    
    def ping_device(self, ip):
        try:
            packet = IP(dst=ip)/ICMP()
            start_time = time.time()
            reply = sr1(packet, timeout=2, verbose=False)
            end_time = time.time()
            
            if reply:
                latency = (end_time - start_time) * 1000
                return latency
            return 0
        except:
            return 0
    
    def traceroute_device(self, ip, max_hops=15):
        hops = []
        try:
            for ttl in range(1, max_hops + 1):
                packet = IP(dst=ip, ttl=ttl)/ICMP()
                reply = sr1(packet, timeout=1, verbose=False)
                
                if reply is None:
                    hops.append(f"Hop {ttl}: *")
                elif reply.src == ip:
                    hops.append(f"Hop {ttl}: {reply.src}")
                    break
                else:
                    hops.append(f"Hop {ttl}: {reply.src}")
        except:
            pass
        return hops
    
    def scan_ports(self, ip, ports=None):
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                     993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
        
        open_ports = []
        
        try:
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    pass
        except:
            pass
        
        return open_ports
    
    def get_service_banner(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            if port in [80, 8080, 443, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200] if banner else "No banner"
        except:
            return "No banner"
    
    def detect_os(self, ip):
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-O -F')
            
            if ip in nm.all_hosts():
                if 'osmatch' in nm[ip]:
                    matches = nm[ip]['osmatch']
                    if matches:
                        return matches[0]['name']
        except:
            pass
        return "Unknown"
    
    def get_whois_info(self, ip):
        whois_data = {}
        try:
            w = whois.whois(ip)
            if isinstance(w, dict):
                whois_data['domain_name'] = w.get('domain_name', 'N/A')
                whois_data['registrar'] = w.get('registrar', 'N/A')
                whois_data['creation_date'] = str(w.get('creation_date', 'N/A'))
                whois_data['country'] = w.get('country', 'N/A')
            else:
                whois_data['domain_name'] = getattr(w, 'domain_name', 'N/A')
                whois_data['registrar'] = getattr(w, 'registrar', 'N/A')
                whois_data['creation_date'] = str(getattr(w, 'creation_date', 'N/A'))
                whois_data['country'] = getattr(w, 'country', 'N/A')
        except:
            whois_data = {'error': 'WHOIS lookup failed'}
        
        return whois_data
    
    def test_network_speed(self):
        self.log("\n" + "=" * 80)
        self.log("NETWORK SPEED TEST")
        self.log("=" * 80)
        
        try:
            test_url = "https://www.google.com"
            test_size = 1024 * 100
            
            start_time = time.time()
            response = requests.get(test_url, timeout=10)
            end_time = time.time()
            
            duration = end_time - start_time
            speed_kbps = (len(response.content) / 1024) / duration
            
            self.log(f"Test URL: {test_url}")
            self.log(f"Response time: {duration:.3f} seconds")
            self.log(f"Downloaded: {len(response.content)} bytes")
            self.log(f"Approximate speed: {speed_kbps:.2f} KB/s")
            
            return {
                'url': test_url,
                'response_time': duration,
                'bytes': len(response.content),
                'speed_kbps': speed_kbps
            }
        except Exception as e:
            self.log(f"Network speed test failed: {e}")
            return {'error': str(e)}
    
    def scan_device_details(self):
        self.log("\n" + "=" * 80)
        self.log("DETAILED DEVICE SCANNING")
        self.log("=" * 80)
        
        for idx, device in enumerate(self.devices, 1):
            ip = device['ip']
            self.log(f"\n--- Device {idx}/{len(self.devices)}: {ip} ---")
            
            self.log("Getting hostname and DNS...")
            hostname, dns_records = self.get_hostname_and_dns(ip)
            device['hostname'] = hostname
            device['dns'] = dns_records
            self.log(f"Hostname: {hostname}")
            if dns_records:
                self.log(f"DNS Records: {', '.join(dns_records)}")
            
            self.log("Measuring latency...")
            latency = self.ping_device(ip)
            device['latency'] = latency
            self.log(f"Latency: {latency:.2f} ms" if latency > 0 else "Latency: Unreachable")
            
            self.log("Scanning ports...")
            open_ports = self.scan_ports(ip)
            device['open_ports'] = open_ports
            if open_ports:
                self.log(f"Open ports: {', '.join(map(str, open_ports))}")
                
                services = []
                for port in open_ports[:5]:
                    banner = self.get_service_banner(ip, port)
                    service_info = f"Port {port}: {banner}"
                    services.append(service_info)
                    self.log(f"  {service_info}")
                device['services'] = services
            else:
                self.log("No open ports found (filtered or firewalled)")
            
            if ip != self.network_info.get('ip'):
                self.log("Performing OS detection (this may take a moment)...")
                try:
                    os_guess = self.detect_os(ip)
                    device['os'] = os_guess
                    self.log(f"OS Detection: {os_guess}")
                except Exception as e:
                    self.log(f"OS detection failed: {e}")
            
            self.log("Performing traceroute...")
            traceroute_hops = self.traceroute_device(ip, max_hops=10)
            device['traceroute'] = traceroute_hops
            if traceroute_hops:
                for hop in traceroute_hops[:5]:
                    self.log(f"  {hop}")
            
            is_private = (ip.startswith('192.168.') or 
                         ip.startswith('10.') or 
                         ip.startswith('172.16.') or 
                         ip.startswith('172.17.') or 
                         ip.startswith('172.18.') or 
                         ip.startswith('172.19.') or 
                         ip.startswith('172.20.') or 
                         ip.startswith('172.21.') or 
                         ip.startswith('172.22.') or 
                         ip.startswith('172.23.') or 
                         ip.startswith('172.24.') or 
                         ip.startswith('172.25.') or 
                         ip.startswith('172.26.') or 
                         ip.startswith('172.27.') or 
                         ip.startswith('172.28.') or 
                         ip.startswith('172.29.') or 
                         ip.startswith('172.30.') or 
                         ip.startswith('172.31.'))
            
            if not is_private:
                self.log("Getting WHOIS information...")
                whois_info = self.get_whois_info(ip)
                device['whois'] = whois_info
                if 'error' not in whois_info:
                    self.log(f"  Country: {whois_info.get('country', 'N/A')}")
                    self.log(f"  Registrar: {whois_info.get('registrar', 'N/A')}")
    
    def generate_summary_report(self):
        self.log("\n" + "=" * 80)
        self.log("SCAN SUMMARY REPORT")
        self.log("=" * 80)
        
        self.log(f"\nScan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log(f"Total devices found: {len(self.devices)}")
        self.log(f"\nNetwork Information:")
        self.log(f"  Interface: {self.network_info.get('interface', 'N/A')}")
        self.log(f"  IP Address: {self.network_info.get('ip', 'N/A')}")
        self.log(f"  Network Range: {self.network_info.get('network_range', 'N/A')}")
        self.log(f"  Gateway: {self.network_info.get('gateway', 'N/A')}")
        
        self.log(f"\nDevice Summary:")
        for idx, device in enumerate(self.devices, 1):
            self.log(f"  {idx}. IP: {device['ip']}, MAC: {device['mac']}, " +
                    f"Hostname: {device['hostname']}, " +
                    f"Open Ports: {len(device['open_ports'])}")
        
        self.log("\n" + "=" * 80)
        self.log(f"Log file saved to: {os.path.join(self.log_dir, f'network_scan_{self.timestamp}.log')}")
        self.log("=" * 80)
    
    def run(self):
        try:
            self.log("Network Scanner Starting...")
            self.log(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self.log(f"Platform: {platform.system()} {platform.release()}")
            
            network_range = self.get_network_interface_info()
            if not network_range:
                self.log("Failed to detect network. Exiting.")
                return
            
            device_count = self.scan_active_devices(network_range)
            if device_count == 0:
                self.log("No active devices found. Exiting.")
                return
            
            self.scan_device_details()
            
            self.test_network_speed()
            
            self.generate_summary_report()
            
        except KeyboardInterrupt:
            self.log("\n\nScan interrupted by user.")
        except Exception as e:
            self.log(f"\nUnexpected error: {e}")
        finally:
            if self.log_file:
                self.log_file.close()


def main():
    try:
        is_root = os.geteuid() == 0
    except AttributeError:
        import ctypes
        try:
            is_root = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            is_root = False
    
    if not is_root:
        print("Warning: This script requires root/administrator privileges for full functionality.")
        print("Please run with sudo: sudo python3 network_scanner.py")
        print("\nContinuing with limited functionality...")
        print()
    
    scanner = NetworkScanner()
    scanner.run()


if __name__ == "__main__":
    main()
