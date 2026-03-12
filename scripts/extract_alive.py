#!/usr/bin/env python3
"""
Extrait les domaines/IPs uniques des fichiers de resultats BugScanX.

Usage:
    python3 scripts/extract_alive.py results/MON_FICHIER.txt
    python3 scripts/extract_alive.py results/MON_FICHIER.txt -o data/domains/alive.txt
    python3 scripts/extract_alive.py results/MON_FICHIER.txt --code 200
    python3 scripts/extract_alive.py results/MON_FICHIER.txt --code 200,301
    python3 scripts/extract_alive.py results/MON_FICHIER.txt --server cloudflare
"""

import os
import sys
import re
import argparse


def extract_from_ping(filepath):
    """Extrait les hosts depuis un resultat ping."""
    hosts = set()
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(('Scan Time', 'File Scanned', 'Port', '----', '===', '---', 'RESU', 'Total', 'Dure')):
                continue
            parts = line.split()
            if len(parts) >= 3:
                host = parts[-1]
                if re.match(r'^[a-zA-Z0-9]', host) and '.' in host and host != 'Host':
                    hosts.add(host)
    return sorted(hosts)


def extract_from_direct(filepath, code_filter=None, server_filter=None):
    """Extrait les hosts depuis un resultat direct/directnon302."""
    hosts = set()
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(('Scan Time', 'File Scanned', 'Method', '------', '===', '---', 'RESU', 'Total', 'Dure')):
                continue
            parts = line.split()
            if len(parts) >= 6:
                method, code, server = parts[0], parts[1], parts[2]
                host = parts[-1]

                if code_filter and code not in code_filter:
                    continue
                if server_filter and server_filter.lower() not in server.lower():
                    continue

                if re.match(r'^[a-zA-Z0-9]', host) and '.' in host and host != 'Host':
                    hosts.add(host)
    return sorted(hosts)


def extract_from_proxy(filepath, code_filter=None):
    """Extrait les hosts depuis un resultat proxy."""
    hosts = set()
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(('Scan Time', 'File Scanned', 'Proxy', '------', '===', '---', 'RESU', 'Total', 'Dure', '    ')):
                continue
            parts = line.split()
            if len(parts) >= 2:
                host_port = parts[0]
                code = parts[1] if len(parts) > 1 else ""
                if ':' in host_port:
                    host = host_port.split(':')[0]
                    if code_filter and code not in code_filter:
                        continue
                    if re.match(r'^[a-zA-Z0-9]', host) and '.' in host:
                        hosts.add(host)
    return sorted(hosts)


def detect_format(filepath):
    """Detecte le format du fichier de resultats."""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read(2000)
        if 'Proxy:Port' in content:
            return 'proxy'
        elif 'Method' in content and 'Code' in content and 'Server' in content:
            return 'direct'
        elif 'TLS' in content and 'SNI' in content:
            return 'ssl'
        elif 'Port' in content and 'Host' in content:
            return 'ping'
    return 'unknown'


def main():
    parser = argparse.ArgumentParser(description="Extrait les domaines des resultats BugScanX")
    parser.add_argument("input", help="Fichier de resultats a traiter")
    parser.add_argument("-o", "--output", help="Fichier de sortie (defaut: stdout)")
    parser.add_argument("--code", help="Filtrer par code HTTP (ex: 200 ou 200,301)")
    parser.add_argument("--server", help="Filtrer par serveur (ex: cloudflare)")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"\033[31mFichier non trouve: {args.input}\033[0m", file=sys.stderr)
        sys.exit(1)

    code_filter = set(args.code.split(',')) if args.code else None
    fmt = detect_format(args.input)

    print(f"\033[36mFormat detecte: {fmt}\033[0m", file=sys.stderr)

    if fmt == 'ping':
        hosts = extract_from_ping(args.input)
    elif fmt in ('direct',):
        hosts = extract_from_direct(args.input, code_filter, args.server)
    elif fmt == 'proxy':
        hosts = extract_from_proxy(args.input, code_filter)
    else:
        hosts = extract_from_ping(args.input)

    print(f"\033[32m{len(hosts)} domaines extraits\033[0m", file=sys.stderr)

    if args.output:
        with open(args.output, 'w') as f:
            for h in hosts:
                f.write(h + '\n')
        print(f"\033[32mSauvegarde dans: {args.output}\033[0m", file=sys.stderr)
    else:
        for h in hosts:
            print(h)


if __name__ == "__main__":
    main()
