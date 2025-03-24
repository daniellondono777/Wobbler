import os
import subprocess
import pwd
import re
from colorama import Fore, Style

CRON_LOCATIONS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly"
]

def is_writable(path):
    try:
        return os.access(path, os.W_OK)
    except:
        return False

def extract_commands(line):
    # Skip comments and env vars
    if line.startswith("#") or "=" in line:
        return None

    parts = line.strip().split()
    if len(parts) < 6:
        return None

    command = " ".join(parts[5:])
    return command

def scan_crontab_file(path):
    flagged = 0
    if os.path.isfile(path):
        try:
            with open(path, "r") as f:
                for line in f:
                    cmd = extract_commands(line)
                    if cmd:
                        binary = cmd.split()[0]
                        if os.path.exists(binary) and is_writable(binary):
                            print(Fore.YELLOW + f"[!] Writable cron job target in {path}: {binary}")
                            flagged += 1
        except Exception:
            pass
    return flagged

def scan_cron_directory(dirpath):
    flagged = 0
    if os.path.isdir(dirpath):
        if is_writable(dirpath):
            print(Fore.RED + f"[!] Cron directory is writable: {dirpath}")
            flagged += 1
        for file in os.listdir(dirpath):
            full_path = os.path.join(dirpath, file)
            if os.path.isfile(full_path):
                flagged += scan_crontab_file(full_path)
    return flagged

def scan_user_crontabs():
    flagged = 0
    for user in pwd.getpwall():
        username = user.pw_name
        try:
            output = subprocess.check_output(["crontab", "-l", "-u", username], stderr=subprocess.DEVNULL, text=True)
            for line in output.splitlines():
                cmd = extract_commands(line)
                if cmd:
                    binary = cmd.split()[0]
                    if os.path.exists(binary) and is_writable(binary):
                        print(Fore.YELLOW + f"[!] Writable cron job target for user '{username}': {binary}")
                        flagged += 1
        except subprocess.CalledProcessError:
            continue
    return flagged

def run():
    print(Fore.CYAN + Style.BRIGHT + "[*] Scanning cron jobs for privilege escalation vectors...\n")

    flagged_total = 0

    for path in CRON_LOCATIONS:
        if os.path.isfile(path):
            flagged_total += scan_crontab_file(path)
        elif os.path.isdir(path):
            flagged_total += scan_cron_directory(path)

    flagged_total += scan_user_crontabs()

    if flagged_total == 0:
        print(Fore.GREEN + "[+] No writable cron jobs or dangerous configs found.\n")
    else:
        print(Fore.RED + f"\n[*] Total cron-based privilege escalation risks found: {flagged_total}\n")
