import os
import subprocess
from colorama import Fore, Style

KNOWN_SAFE = [
    "passwd", "ping", "su", "sudo", "mount", "umount", "chsh",
    "chfn", "newgrp", "crontab", "at", "Xorg", "pkexec", "traceroute6.iputils"
]

def run(full_scan=False, custom_dirs=None):
    print(Fore.CYAN + Style.BRIGHT + "[*] Scanning for SUID binaries...\n")

    if custom_dirs is None:
        custom_dirs = []

    if full_scan:
        search_dirs = ["/"]
    elif custom_dirs:
        search_dirs = custom_dirs
    else:
        search_dirs = ["/bin", "/sbin", "/usr", "/usr/local", "/opt", "/home", "/root"]

    try:
        result = subprocess.run(
            ["find"] + search_dirs + ["-perm", "-4000", "-type", "f", "-exec", "ls", "-la", "{}", "+"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        output = result.stdout
        if result.stderr.strip():
            print(Fore.MAGENTA + "[~] Some directories could not be accessed (permission denied or restricted)\n")

    except Exception as e:
        print(Fore.RED + f"[-] Unexpected error running find: {e}")
        return

    lines = output.strip().split("\n")
    total = 0
    uncommon = 0

    for line in lines:
        total += 1
        parts = line.split()
        if len(parts) < 9:
            continue

        filepath = parts[-1]
        binary_name = os.path.basename(filepath)

        if binary_name in KNOWN_SAFE:
            print(Fore.GREEN + f"[+] SUID binary: {filepath} (common)")
        else:
            print(Fore.YELLOW + f"[!] SUID binary: {filepath} (uncommon - investigate)")
            uncommon += 1

    print(Fore.CYAN + f"\n[*] Total SUID binaries found: {total}")
    print(Fore.MAGENTA + f"[*] Uncommon / suspicious binaries: {uncommon}\n")
