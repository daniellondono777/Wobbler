import os
from colorama import Fore, Style

def get_path_dirs():
    return os.environ.get("PATH", "").split(":")

def is_writable(path):
    try:
        return os.access(path, os.W_OK)
    except:
        return False

def scan_writable_path_dirs():
    print(Fore.CYAN + Style.BRIGHT + "[*] Scanning for writable directories in $PATH...\n")
    writable_dirs = []

    for path_dir in get_path_dirs():
        if os.path.isdir(path_dir) and is_writable(path_dir):
            writable_dirs.append(path_dir)
            print(Fore.RED + f"[!] Writable PATH directory found: {path_dir}")

    if not writable_dirs:
        print(Fore.GREEN + "[+] No writable directories found in $PATH.\n")
    return writable_dirs

def scan_writable_binaries_in_path():
    print(Fore.CYAN + Style.BRIGHT + "[*] Scanning for writable binaries in $PATH...\n")
    binaries_flagged = 0

    for path_dir in get_path_dirs():
        if not os.path.isdir(path_dir):
            continue
        try:
            for entry in os.listdir(path_dir):
                full_path = os.path.join(path_dir, entry)
                if os.path.isfile(full_path) and os.access(full_path, os.X_OK) and is_writable(full_path):
                    binaries_flagged += 1
                    print(Fore.YELLOW + f"[!] Writable binary in $PATH: {full_path}")
        except PermissionError:
            continue

    if binaries_flagged == 0:
        print(Fore.GREEN + "[+] No writable binaries found in $PATH.\n")
    else:
        print(Fore.RED + f"\n[*] Total writable binaries found: {binaries_flagged}\n")

def run():
    print(Fore.CYAN + Style.BRIGHT + "\n[*] PATH-Based Privilege Escalation Checks\n")
    scan_writable_path_dirs()
    scan_writable_binaries_in_path()
