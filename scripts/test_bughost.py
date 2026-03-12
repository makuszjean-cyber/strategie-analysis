#!/usr/bin/env python3
"""
Test de Bug Host - A lancer SANS FORFAIT sur le reseau Orange.

Teste chaque domaine du fichier pour voir lequel passe sans forfait.
Les domaines qui repondent = BUG HOSTS.

Usage:
    python test_bughost.py domains_20260307_205425.txt
    python test_bughost.py domains_20260307_205425.txt --threads 50
    python test_bughost.py domains_20260307_205425.txt --timeout 3 --ports 80,443
"""

import os
import sys
import socket
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

PORTS = [80, 443]
TIMEOUT = 3
THREADS = 100
OUTPUT = "BUGHOSTS_TROUVES.txt"


def test_host(host, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return host, port, True
    except (socket.gaierror, socket.timeout, OSError):
        pass
    return host, port, False


def main():
    parser = argparse.ArgumentParser(description="Test de Bug Host SANS FORFAIT")
    parser.add_argument("file", help="Fichier de domaines a tester")
    parser.add_argument("--ports", default="80,443", help="Ports (defaut: 80,443)")
    parser.add_argument("--threads", type=int, default=THREADS, help="Threads (defaut: 100)")
    parser.add_argument("--timeout", type=int, default=TIMEOUT, help="Timeout sec (defaut: 3)")
    parser.add_argument("-o", "--output", default=OUTPUT, help="Fichier sortie")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"  ERREUR: {args.file} non trouve")
        sys.exit(1)

    ports = [int(p) for p in args.ports.split(",")]

    domains = []
    with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith(('#', '-', 'T', ' ')):
                if '.' in line:
                    domains.append(line)

    total = len(domains) * len(ports)
    print(f"""
  ============================================
    TEST BUG HOST - SANS FORFAIT
  ============================================
    Fichier  : {args.file}
    Domaines : {len(domains):,}
    Ports    : {', '.join(str(p) for p in ports)}
    Tests    : {total:,}
    Threads  : {args.threads}
    Timeout  : {args.timeout}s
    Sortie   : {args.output}
  ============================================
""")

    found = []
    tested = 0
    start = datetime.now()

    with open(args.output, 'w') as out:
        out.write(f"# Bug Hosts trouves - {datetime.now()}\n\n")

        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = {}
            for domain in domains:
                for port in ports:
                    fut = pool.submit(test_host, domain, port, args.timeout)
                    futures[fut] = (domain, port)

            for fut in as_completed(futures):
                tested += 1
                host, port, alive = fut.result()

                if tested % 500 == 0 or alive:
                    pct = tested / total * 100
                    elapsed = (datetime.now() - start).total_seconds()
                    speed = tested / max(elapsed, 1)
                    eta = (total - tested) / max(speed, 1)
                    sys.stdout.write(
                        f"\r  [{pct:5.1f}%] {tested:,}/{total:,} | "
                        f"BUG HOSTS: {len(found)} | "
                        f"{speed:.0f}/s | ETA: {eta/60:.0f}min  "
                    )
                    sys.stdout.flush()

                if alive:
                    entry = f"{host}:{port}"
                    if entry not in [f"{h}:{p}" for h, p in found]:
                        found.append((host, port))
                        out.write(f"{host}:{port}\n")
                        out.flush()
                        print(f"\n  >>> BUG HOST TROUVE: {host}:{port} <<<")

    elapsed = datetime.now() - start
    print(f"""

  ============================================
    TERMINE !
  ============================================
    Duree        : {elapsed}
    Testes       : {tested:,}
    BUG HOSTS    : {len(found)}
    Fichier      : {args.output}
  ============================================
""")

    if found:
        print("  BUG HOSTS TROUVES :")
        for host, port in found:
            print(f"    >>> {host}:{port}")
        print(f"""
  Prochaine etape :
  Configure DTunnel/HTTP Injector avec ce payload :

    GET / HTTP/1.1[crlf]
    Host: {found[0][0]}[crlf]
    Connection: Upgrade[crlf]
    Upgrade: websocket[crlf][crlf]

    SNI : {found[0][0]}
""")
    else:
        print("  Aucun bug host trouve.")
        print("  Verifie que tu es bien sur Orange SANS forfait.")


if __name__ == "__main__":
    main()
