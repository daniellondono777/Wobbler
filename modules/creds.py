import os
from colorama import Fore, Style

def run(ignored_dirs=None, custom_keywords=None, full_scan=False, custom_dirs=None):
    if ignored_dirs is None:
        ignored_dirs = []
    if custom_keywords is None:
        custom_keywords = []
    if custom_dirs is None:
        custom_dirs = []

    print(Fore.CYAN + Style.BRIGHT + "[*] Scanning for exposed credentials...")

    # Default scan dirs
    target_dirs_default = [
        "/home", "/root", "/etc", "/opt", "/var/www",
        "/var/backups", "/var/log", "/srv", "/mnt",
        "/media", "/usr/local/bin", "/usr/local/etc", "/tmp"
    ]

    # Final directory selection logic
    if full_scan:
        target_dirs = ["/"]
    elif custom_dirs:
        target_dirs = custom_dirs
    else:
        target_dirs = target_dirs_default

    default_keywords = ["password", "passwd", "token", "secret", "key", "credentials"]

    if custom_keywords:
        keywords = list(set([kw.lower() for kw in custom_keywords]))
    else:
        keywords = default_keywords


    dotfiles = [
        ".bash_history", ".zsh_history", ".git-credentials",
        ".aws/credentials", ".npmrc", ".env"
    ]

    for base in ["/home", "/root"]:
        try:
            for user_dir in os.listdir(base):
                full_path = os.path.join(base, user_dir)
                if not os.path.isdir(full_path):
                    continue
                for dotfile in dotfiles:
                    full_dotfile_path = os.path.join(full_path, dotfile)
                    if os.path.isfile(full_dotfile_path):
                        try:
                            with open(full_dotfile_path, "r", errors="ignore") as f:
                                content = f.read().lower()
                                for keyword in keywords:
                                    if keyword in content:
                                        print(Fore.GREEN + f"[+] Keyword '{Fore.MAGENTA}{keyword}{Fore.GREEN}' found in: {full_dotfile_path}")
                                        break
                        except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                            continue
        except (PermissionError, FileNotFoundError):
            continue

    for dirpath in target_dirs:
        for root, dirs, files in os.walk(dirpath):
            if any(root.startswith(ignored) for ignored in ignored_dirs):
                continue

            for file in files:
                filepath = os.path.join(root, file)

                if any(filepath.startswith(ignored) for ignored in ignored_dirs):
                    continue

                try:
                    if not os.path.isfile(filepath):
                        continue
                    with open(filepath, "r", errors="ignore") as f:
                        content = f.read().lower()
                        for keyword in keywords:
                            if keyword in content:
                                print(Fore.GREEN + f"[+] Keyword '{Fore.MAGENTA}{keyword}{Fore.GREEN}' found in: {filepath}")
                                break
                except (PermissionError, FileNotFoundError, UnicodeDecodeError):
                    continue

    print(Fore.YELLOW + "\n[*] Done.\n")
