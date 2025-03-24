import subprocess
import re
import os
import socket
from colorama import Fore, Style

def scan_listeners():
    print(Fore.CYAN + Style.BRIGHT + "[*] Scanning for network listeners...\n")
    try:
        result = subprocess.run(["ss", "-tulpn"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = result.stdout.splitlines()
    except Exception as e:
        print(Fore.RED + f"[-] Failed to run ss -tulpn: {e}")
        return

    flagged = 0
    for line in output:
        if not line.startswith("tcp") and not line.startswith("udp"):
            continue

        # Example line format:
        # tcp   LISTEN  0  128  0.0.0.0:6379   0.0.0.0:*   users:(("redis-server",pid=888,uid=0))
        parts = line.split()
        if len(parts) < 6:
            continue

        proto = parts[0]
        local_address = parts[4]
        process_info = parts[-1]

        # Port
        address, _, port = local_address.rpartition(":")
        port = port.strip()

        # UID
        uid_match = re.search(r'uid=(\d+)', process_info)
        uid = int(uid_match.group(1)) if uid_match else -1

        # Process name
        proc_match = re.search(r'\("([^"]+)"', process_info)
        proc = proc_match.group(1) if proc_match else "unknown"

        flags = []

        if uid == 0:
            flags.append("root-owned")

        if address == "0.0.0.0" or address == "::":
            flags.append("public")

        if port.isdigit() and int(port) > 1024:
            flags.append("high-port")

        if flags:
            flagged += 1
            print(Fore.YELLOW + f"[!] {proto.upper()} {address}:{port} -> {proc} ({', '.join(flags)})")

    if flagged == 0:
        print(Fore.GREEN + "[+] No suspicious listeners found.\n")
    else:
        print(Fore.RED + f"\n[*] Total flagged listeners: {flagged}\n")

def check_docker_vulns():
    print(Fore.CYAN + Style.BRIGHT + "[*] Checking for Docker socket and remote API exposure...\n")

    # 1. Check local Docker socket
    sock_path = "/var/run/docker.sock"
    if os.path.exists(sock_path):
        flags = []
        if os.access(sock_path, os.R_OK):
            flags.append("readable")
        if os.access(sock_path, os.W_OK):
            flags.append("writable")
        if flags:
            print(Fore.RED + f"[!] Docker socket found at {sock_path} ({', '.join(flags)})")
            print(Fore.YELLOW + "    → This may allow full root access if Docker is running.\n")
        else:
            print(Fore.GREEN + f"[+] Docker socket exists at {sock_path}, but not accessible by current user.\n")
    else:
        print(Fore.GREEN + "[+] No Docker socket found at /var/run/docker.sock\n")

    # 2. Check port 2375 (Docker remote API)
    try:
        with socket.create_connection(("localhost", 2375), timeout=2) as sock:
            sock.sendall(b"GET /version HTTP/1.0\r\n\r\n")
            resp = sock.recv(1024).decode()
            if "Docker" in resp or "Api-Version" in resp or "Server" in resp:
                print(Fore.RED + "[!] Docker Remote API exposed on localhost:2375")
                print(Fore.YELLOW + "    → This is unauthenticated and can allow full container control!\n")
            else:
                print(Fore.GREEN + "[+] Port 2375 is open but did not respond with Docker API info.\n")
    except (ConnectionRefusedError, socket.timeout):
        print(Fore.GREEN + "[+] Docker remote API (port 2375) not exposed on localhost.\n")
    except Exception as e:
        print(Fore.RED + f"[-] Error checking Docker remote API: {e}\n")

def analyze_firewall_rules():
    print(Fore.CYAN + Style.BRIGHT + "[*] Analyzing iptables firewall rules...\n")
    try:
        result = subprocess.run(["iptables", "-L", "-n", "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        error = result.stderr

        if "command not found" in error or "No chain/target/match" in error:
            print(Fore.YELLOW + "[~] iptables command not available or unsupported on this system.\n")
            return

        if "Chain" not in output:
            print(Fore.YELLOW + "[~] No iptables rules found. System may have no active firewall.\n")
            return

        flagged = 0
        lines = output.splitlines()
        current_chain = ""

        for line in lines:
            line = line.strip()

            if line.startswith("Chain"):
                current_chain = line.split()[1]
                if "ACCEPT" in line and "policy ACCEPT" in line:
                    print(Fore.RED + f"[!] Chain {current_chain} has default policy ACCEPT (no filtering!)")
                    flagged += 1

            elif line and ("ACCEPT" in line or "all" in line):
                if "0.0.0.0/0" in line or "anywhere" in line:
                    print(Fore.YELLOW + f"[!] Rule in {current_chain} allows all traffic: {line}")
                    flagged += 1

        if flagged == 0:
            print(Fore.GREEN + "[+] No overly permissive iptables rules found.\n")
        else:
            print(Fore.RED + f"\n[*] Total flagged firewall issues: {flagged}\n")

    except FileNotFoundError:
        print(Fore.YELLOW + "[~] iptables not found on system. Skipping firewall analysis.\n")
    except Exception as e:
        print(Fore.RED + f"[-] Error analyzing iptables rules: {e}\n")

def check_writable_configs():
    print(Fore.CYAN + Style.BRIGHT + "[*] Checking for writable network-related configuration files...\n")

    config_targets = [
    "/etc/hosts",                                # Hostname resolution
    "/etc/resolv.conf",                          # DNS configuration
    "/etc/network/interfaces",                   # Debian/Ubuntu
    "/etc/netplan",                              # Ubuntu (modern)
    "/etc/sysconfig/network",                    # RHEL/CentOS - basic network setup
    "/etc/sysconfig/network-scripts",            # RHEL/CentOS - per-interface configs
    "/etc/systemd/network",                      # systemd-networkd configs
    "/etc/NetworkManager/system-connections",    # NetworkManager profiles (WiFi/eth)
    "/etc/wpa_supplicant",                       # WiFi configs and keys
    ]

    flagged = 0

    for path in config_targets:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    if os.access(full_path, os.W_OK):
                        flagged += 1
                        print(Fore.YELLOW + f"[!] Writable network config: {full_path}")
        elif os.path.isfile(path):
            if os.access(path, os.W_OK):
                flagged += 1
                print(Fore.YELLOW + f"[!] Writable network config: {path}")

    if flagged == 0:
        print(Fore.GREEN + "[+] No writable network configuration files found.\n")
    else:
        print(Fore.RED + f"\n[*] Total writable network config files: {flagged}\n")