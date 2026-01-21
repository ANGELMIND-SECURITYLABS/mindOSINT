#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import subprocess
import argparse
import json
import time
import requests
import hashlib
from datetime import datetime, UTC

COPYRIGHT = "Criado Por Geovane Baptista - AngelMind Security"

# =========================================================
# BANNER
# =========================================================
def banner():
    print(f"""
============================================
mindOSINT - Framework OSINT
{COPYRIGHT}
============================================
""")

# =========================================================
# VIRTUALENV AUTO BOOTSTRAP
# =========================================================
def ensure_venv():
    if any(a in ("-h", "--help") for a in sys.argv):
        return

    if sys.prefix != sys.base_prefix:
        return

    venv = ".venv"
    py = os.path.join(venv, "bin", "python")

    if not os.path.exists(py):
        print("[*] Criando ambiente virtual isolado (.venv)")
        subprocess.check_call([sys.executable, "-m", "venv", venv])
        subprocess.check_call([py, "-m", "pip", "install", "--upgrade", "pip"])

        if not os.path.exists("requirements.txt"):
            print("[!] requirements.txt não encontrado")
            sys.exit(1)

        subprocess.check_call([py, "-m", "pip", "install", "-r", "requirements.txt"])

    os.execv(py, [py] + sys.argv)


ensure_venv()

# =========================================================
# ARGUMENTOS CLI
# =========================================================
def parse_args():
    p = argparse.ArgumentParser(
        prog="mindOSINT",
        description=f"Framework OSINT – Senha, IP e Hash\n{COPYRIGHT}",
    )

    p.add_argument("--password", help="Verifica se uma senha foi vazada (HIBP Pwned Passwords)")
    p.add_argument("--ip", help="Consulta IP (Shodan + AbuseIPDB)")
    p.add_argument("--hash", help="Consulta hash no VirusTotal (MD5/SHA1/SHA256)")
    p.add_argument("--report", choices=["pdf", "txt", "json", "all"],
                   help="Gera relatório")
    return p.parse_args()

# =========================================================
# CONFIGURAÇÃO INICIAL
# =========================================================
def load_config():
    cfg_file = "config.json"

    if os.path.exists(cfg_file):
        with open(cfg_file) as f:
            return json.load(f)

    print("[*] Configuração inicial obrigatória")
    lang = input("Idioma (pt/en) [pt]: ") or "pt"

    cfg = {
        "language": lang,
        "virustotal": input("VirusTotal API Key: ").strip(),
        "abuseipdb": input("AbuseIPDB API Key: ").strip(),
        "shodan": input("Shodan API Key: ").strip(),
    }

    with open(cfg_file, "w") as f:
        json.dump(cfg, f, indent=2)

    print(f"[+] Configuração salva - {COPYRIGHT}")
    return cfg

# =========================================================
# PWNED PASSWORDS (SEM API)
# =========================================================
def pwned_password(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    r = requests.get(url, timeout=10)

    if r.status_code != 200:
        raise RuntimeError("Erro ao consultar Pwned Passwords")

    for line in r.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return {"pwned": True, "count": int(count)}

    return {"pwned": False, "count": 0}

# =========================================================
# VIRUSTOTAL
# =========================================================
def vt_hash(hashv, api):
    url = f"https://www.virustotal.com/api/v3/files/{hashv}"
    headers = {"x-apikey": api}
    r = requests.get(url, headers=headers, timeout=15)
    if r.status_code != 200:
        raise RuntimeError("Erro VirusTotal")
    return r.json()["data"]["attributes"]

# =========================================================
# ABUSEIPDB
# =========================================================
def abuse_ip(ip, api):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(url, headers=headers, params=params, timeout=15)
    if r.status_code != 200:
        raise RuntimeError("Erro AbuseIPDB")
    return r.json()["data"]

# =========================================================
# SHODAN
# =========================================================
def shodan_ip(ip, api):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api}"
    r = requests.get(url, timeout=15)
    if r.status_code != 200:
        raise RuntimeError("Erro Shodan")
    return r.json()

# =========================================================
# CORE
# =========================================================
def run_osint(args, cfg):
    results = {
        "timestamp": datetime.now(UTC).isoformat(),
        "data": {},
        "copyright": COPYRIGHT
    }

    if args.password:
        print("[*] Verificando senha vazada (HIBP)")
        results["data"]["password"] = pwned_password(args.password)

    if args.hash:
        print("[*] Consultando hash no VirusTotal")
        results["data"]["hash"] = vt_hash(args.hash, cfg["virustotal"])

    if args.ip:
        print("[*] Consultando IP no AbuseIPDB")
        abuse = abuse_ip(args.ip, cfg["abuseipdb"])
        print("[*] Consultando IP no Shodan")
        shodan = shodan_ip(args.ip, cfg["shodan"])

        results["data"]["ip"] = {
            "abuseipdb": abuse,
            "shodan": {
                "ports": shodan.get("ports"),
                "org": shodan.get("org"),
                "os": shodan.get("os"),
                "vulns": shodan.get("vulns"),
            }
        }

    return results

# =========================================================
# OUTPUT
# =========================================================
def show_terminal(results):
    print(f"\n========== RESULTADO ==========\n{COPYRIGHT}")
    print(json.dumps(results, indent=2))
    print("================================\n")

def generate_report(results, rtype):
    os.makedirs("reports", exist_ok=True)
    base = f"reports/mindosint_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"

    if rtype in ("json", "all"):
        with open(base + ".json", "w") as f:
            json.dump(results, f, indent=2)

    if rtype in ("txt", "all"):
        with open(base + ".txt", "w") as f:
            f.write(f"{COPYRIGHT}\n\n")
            f.write(json.dumps(results, indent=2))

    if rtype in ("pdf", "all"):
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet

        pdf = SimpleDocTemplate(base + ".pdf")
        styles = getSampleStyleSheet()
        story = [
            Paragraph(COPYRIGHT, styles["Normal"]),
            Spacer(1, 12),
            Paragraph(json.dumps(results, indent=2), styles["Normal"])
        ]
        pdf.build(story)

    print(f"[+] Relatório gerado em reports/ - {COPYRIGHT}")

# =========================================================
# MAIN
# =========================================================
def main():
    banner()
    args = parse_args()

    if not (args.password or args.ip or args.hash):
        print("[!] Informe --password, --ip ou --hash")
        sys.exit(1)

    cfg = load_config()
    results = run_osint(args, cfg)

    if args.report:
        generate_report(results, args.report)
    else:
        show_terminal(results)

if __name__ == "__main__":
    main()
