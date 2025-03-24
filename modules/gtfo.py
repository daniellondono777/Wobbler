import subprocess
import json
import os
from colorama import Fore, Style
from shutil import which
import re

def run():
    print(Fore.CYAN + Style.BRIGHT + "[*] Parsing sudo permissions and checking against GTFOBins...\n")

    try:
        output = subprocess.check_output(["sudo", "-l"], stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        print(Fore.RED + "[-] Error running sudo -l or permission denied.\n")
        return

    if not os.path.exists("modules/gtfobins.json"):
        print(Fore.RED + "[-] gtfobins.json not found.\n")
        return

    with open("modules/gtfobins.json", "r") as f:
        gtfo_data = json.load(f)

    matched = 0
    printed = set()

    for line in output.splitlines():
        stripped = line.strip()

        if re.match(r"^\(.*\)\s+ALL$", stripped):
            print(Fore.RED + f"[!] Unrestricted sudo access: {stripped}")
            print(Fore.YELLOW + "    → You can run ANY command as root. GTFOBins not needed.\n")
            matched += 1
            continue

        if "NOPASSWD" in stripped or "/usr" in stripped or stripped.startswith("("):
            parts = stripped.split()
            for part in parts:
                if part.startswith("/"):
                    binary_path = part
                    binary_name = os.path.basename(binary_path)
                    normalized = binary_name.lower().split("3")[0].split("2")[0]
                    if normalized in gtfo_data and normalized not in printed:
                        matched += 1
                        printed.add(normalized)
                        print(Fore.YELLOW + f"[!] Sudo allowed binary: {binary_path}")
                        print(Fore.MAGENTA + f"    → GTFOBins link: {gtfo_data[normalized]}\n")

    if matched == 0:
        print(Fore.GREEN + "[+] No matching GTFOBins found in sudo permissions.\n")
    else:
        print(Fore.RED + f"[*] Total GTFOBin matches found: {matched}\n")
