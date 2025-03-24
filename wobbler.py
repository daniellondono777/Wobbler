import argparse
from colorama import init, Fore, Style
from modules import creds, suid, gtfo, cron, scripts, network, path

def print_banner():
    init(autoreset=True)
    print(Fore.WHITE + Style.BRIGHT + "\nWobbler v1.0.0 — Modular Linux Privilege Escalation Tool\n")
    banner = r"""
__/\\\______________/\\\_______/\\\\\_______/\\\\\\\\\\\\\____/\\\\\\\\\\\\\____/\\\______________/\\\\\\\\\\\\\\\____/\\\\\\\\\_____        
 _\/\\\_____________\/\\\_____/\\\///\\\____\/\\\/////////\\\_\/\\\/////////\\\_\/\\\_____________\/\\\///////////___/\\\///////\\\___       
  _\/\\\_____________\/\\\___/\\\/__\///\\\__\/\\\_______\/\\\_\/\\\_______\/\\\_\/\\\_____________\/\\\_____________\/\\\_____\/\\\___      
   _\//\\\____/\\\____/\\\___/\\\______\//\\\_\/\\\\\\\\\\\\\\__\/\\\\\\\\\\\\\\__\/\\\_____________\/\\\\\\\\\\\_____\/\\\\\\\\\\\/____     
    __\//\\\__/\\\\\__/\\\___\/\\\_______\/\\\_\/\\\/////////\\\_\/\\\/////////\\\_\/\\\_____________\/\\\///////______\/\\\//////\\\____    
     ___\//\\\/\\\/\\\/\\\____\//\\\______/\\\__\/\\\_______\/\\\_\/\\\_______\/\\\_\/\\\_____________\/\\\_____________\/\\\____\//\\\___   
      ____\//\\\\\\//\\\\\______\///\\\__/\\\____\/\\\_______\/\\\_\/\\\_______\/\\\_\/\\\_____________\/\\\_____________\/\\\_____\//\\\__  
       _____\//\\\__\//\\\_________\///\\\\\/_____\/\\\\\\\\\\\\\/__\/\\\\\\\\\\\\\/__\/\\\\\\\\\\\\\\\_\/\\\\\\\\\\\\\\\_\/\\\______\//\\\_ 
        ______\///____\///____________\/////_______\/////////////____\/////////////____\///////////////__\///////////////__\///________\///__ 
    """
    banner2 =r"""
    [*] A compact and concise privilege escalation tool for redteamers!
    [*] Author: Daniel S. Londoño
    [*] Wobbler is for educational and authorized security testing only. Please use it legally, or don’t use it at all.
    """
    print(Fore.YELLOW + Style.BRIGHT + banner)
    print(Fore.YELLOW + Style.DIM + banner2)

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Wobbler - Modular Linux Privilege Escalation Tool")

    parser.add_argument("--creds", action="store_true", help="Search for exposed credentials. Default lookup dirs: /home, /root, /etc, /opt, /var/www, /var/backups, /var/log, /srv, /mnt, /media, /usr/local/bin, /usr/local/etc, /tmp")
    
    parser.add_argument("--suid", action="store_true", help="Enumerate SUID binaries")
    
    parser.add_argument("--gtfo", action="store_true", help="Check sudo perms against GTFOBins")

    parser.add_argument("--cron", action="store_true", help="Analyze cron jobs for privilege escalation")

    parser.add_argument("--scripts", action="store_true", help="Find root-executed scripts that are user-writable")

    parser.add_argument("--path", action="store_true", help="Check for writable $PATH directories and binaries")

    parser.add_argument("--network", action="store_true", help="Run all network misconfiguration checks")
    parser.add_argument("--listeners", action="store_true", help="Check for suspicious network listeners")
    parser.add_argument("--net-configs", action="store_true", help="Check for writable network configuration files")
    parser.add_argument("--docker", action="store_true", help="Check for Docker socket and remote API exposure")
    parser.add_argument("--iptables", action="store_true", help="Analyze basic firewall rules")

    parser.add_argument("--keywords", nargs='*', default=[], help="Custom keywords to search for in files (e.g. --keywords password token aws_secret). Default: 'password', 'passwd', 'token', 'secret', 'key', 'credentials'")
    parser.add_argument("--ignore-dirs", nargs='*', default=[], help="Directories to ignore (space-separated)")
    parser.add_argument("--dirs", nargs='*', default=[], help="Specific directories to scan instead of default ones (space separated). Default lookup dirs: /home, /root, /etc, /opt, /var/www, /var/backups, /var/log, /srv, /mnt, /media, /usr/local/bin, /usr/local/etc, /tmp")
    parser.add_argument("--full", action="store_true", help="Scan the entire filesystem instead of default directories")


    args = parser.parse_args()

    if args.creds:
        creds.run(
        ignored_dirs=args.ignore_dirs,
        custom_keywords=args.keywords,
        full_scan=args.full,
        custom_dirs=args.dirs)

    if args.suid:
        suid.run()
    if args.gtfo:
        gtfo.run()
    if args.cron:
        cron.run()
    if args.scripts:
        scripts.run(full_scan=args.full, custom_dirs=args.dirs, ignored_dirs=args.ignore_dirs)
    if args.network:
        network.run()
    if args.listeners:
        network.scan_listeners()
    if args.path:
        path.run()
    if args.network:
        network.scan_listeners()
        network.check_writable_configs()
        network.check_docker_vulns()
        network.analyze_firewall_rules()

    if args.listeners:
        network.scan_listeners()
    if args.net_configs:
        network.check_writable_configs()
    if args.docker:
        network.check_docker_vulns()
    if args.iptables:
        network.analyze_firewall_rules()




    if not any([args.creds, args.suid, args.gtfo, args.cron, args.scripts, args.network, args.listeners, args.docker, args.net_configs, args.iptables ]):
        parser.print_help()


if __name__ == "__main__":
    main()
