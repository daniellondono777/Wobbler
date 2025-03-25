# Wobbler
Wobbler is a concise, modular Linux privilege escalation tool built for speed, precision, and real-world exploitation. Designed to help red teamers, CTF players, and pentesting certification candidates focus on exactly what matters—whether it’s exposed credentials, misconfigured SUID binaries, or exploitable sudo permissions mapped to GTFOBins.

![image](https://github.com/user-attachments/assets/6980bd1f-01a1-4193-8a0d-7eb441dc9d1c)

# Wobbler

**Wobbler** is a modular and precision-driven Linux privilege escalation toolkit built for red teamers, CTF players, and offensive security professionals.  
Unlike traditional enumeration tools, Wobbler focuses on targeted scanning—giving you exactly what you ask for, and nothing more.


---

## 🚀 Features

- 🔹 Modular architecture — run only what you need
- 🔹 Customizable keyword scanning for credentials
- 🔹 Writable root-owned script detection
- 🔹 GTFOBins sudo permission mapping
- 🔹 SUID binary analysis
- 🔹 Cronjob abuse detection
- 🔹 Docker socket exposure detection
- 🔹 Iptables & firewall rule inspection
- 🔹 PATH hijack & binary overwrite detection
- 🔹 Fully configurable scan scope (`--dirs`, `--ignore-dirs`, `--full`)

---

## 🧪 Usage

```bash
python3 wobbler.py [FLAGS]
```
---

## Example:
```bash
python3 wobbler.py --creds --gtfo --suid --scripts --docker --ignore-dirs /opt/metasploit-framework
```


