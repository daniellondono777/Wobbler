import os
from colorama import Fore, Style

SCRIPT_EXTENSIONS = [".sh", ".py", ".pl", ".rb", ".php"]

def is_ignored(path, ignored_dirs):
    path = os.path.normpath(os.path.abspath(path))
    for ignored in ignored_dirs:
        ignored = os.path.normpath(os.path.abspath(ignored))
        if path == ignored or path.startswith(ignored + os.sep):
            return True
    return False

def run(full_scan=False, custom_dirs=None, ignored_dirs=None):
    print(Fore.CYAN + Style.BRIGHT + "[*] Searching for writable root-owned scripts...\n")

    if custom_dirs is None:
        custom_dirs = []
    if ignored_dirs is None:
        ignored_dirs = []

    if full_scan:
        search_dirs = ["/"]
    elif custom_dirs:
        search_dirs = custom_dirs
    else:
        search_dirs = [
            "/home", "/root", "/etc", "/opt", "/var/www",
            "/usr/local/bin", "/usr/local/sbin", "/srv"
        ]

    writable_scripts = []

    try:
        for base_dir in search_dirs:
            for root, dirs, files in os.walk(base_dir):
                if is_ignored(root, ignored_dirs):
                    continue

                for file in files:
                    filepath = os.path.join(root, file)
                    
                    if is_ignored(filepath, ignored_dirs):
                        continue

                    if not any(filepath.endswith(ext) for ext in SCRIPT_EXTENSIONS):
                        continue

                    try:
                        stat_info = os.stat(filepath)
                        if stat_info.st_uid != 0:
                            continue
                        if os.access(filepath, os.W_OK):
                            writable_scripts.append(filepath)
                    except (PermissionError, FileNotFoundError):
                        continue
    except Exception as e:
        print(Fore.RED + f"[-] Unexpected error while scanning: {e}")
        return

    if writable_scripts:
        for path in writable_scripts:
            print(Fore.YELLOW + f"[!] Writable root-owned script: {path}")
        print(Fore.RED + f"\n[*] Total writable root-owned scripts found: {len(writable_scripts)}\n")
    else:
        print(Fore.GREEN + "[+] No writable root-owned scripts found.\n")
