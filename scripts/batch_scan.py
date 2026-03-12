#!/usr/bin/env python3
"""
BugScanX Batch Scanner
Scanne automatiquement tous les fichiers .txt d'un dossier avec plusieurs ports.

Usage:
    python3 scripts/batch_scan.py
    python3 scripts/batch_scan.py --data-dir data/generated --ports 80,443,8080 --mode ping
    python3 scripts/batch_scan.py --data-dir data/cidr --mode direct --threads 100
    python3 scripts/batch_scan.py --help
"""

import os
import sys
import glob
import argparse
import ipaddress
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUGSCANX_DIR = os.path.join(PROJECT_ROOT, "BugScanX")
sys.path.insert(0, BUGSCANX_DIR)

from bugscanx.modules.scanners.scanners.direct import HostDirectScanner, CIDRDirectScanner
from bugscanx.modules.scanners.scanners.ssl import HostSSLScanner, CIDRSSLScanner
from bugscanx.modules.scanners.scanners.ping import HostPingScanner, CIDRPingScanner
from bugscanx.modules.scanners.scanners.proxy_check import HostProxyScanner, CIDRProxyScanner


DEFAULT_PORTS = ["80", "443", "8080", "8443"]
DEFAULT_METHODS = ["GET", "HEAD"]
DEFAULT_THREADS = 50
DEFAULT_TIMEOUT = 3
DEFAULT_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "generated")
DEFAULT_OUTPUT_DIR = os.path.join(PROJECT_ROOT, "results")

SUPPORTED_MODES = ["direct", "directnon302", "ssl", "ping", "proxy"]

BANNER = """
\033[36m╔══════════════════════════════════════════════════════════════╗
║           BugScanX Batch Scanner v2.0                        ║
║     Scanne automatiquement TOUS les fichiers d'un dossier    ║
╚══════════════════════════════════════════════════════════════╝\033[0m
"""


def is_cidr_file(filepath):
    """Detecte si un fichier contient des plages CIDR ou des domaines/IPs."""
    cidr_count = 0
    host_count = 0
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '/' in line:
                    try:
                        ipaddress.ip_network(line, strict=False)
                        cidr_count += 1
                        continue
                    except ValueError:
                        pass
                host_count += 1
    except (IOError, UnicodeDecodeError):
        return False
    return cidr_count > host_count


def count_lines(filepath):
    """Compte le nombre de lignes non-vides dans un fichier."""
    count = 0
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip() and not line.strip().startswith('#'):
                    count += 1
    except (IOError, UnicodeDecodeError):
        pass
    return count


def read_cidrs(filepath):
    """Lit les plages CIDR depuis un fichier."""
    cidrs = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    ipaddress.ip_network(line, strict=False)
                    cidrs.append(line)
                except ValueError:
                    pass
    except (IOError, UnicodeDecodeError):
        pass
    return cidrs


def get_files_to_scan(data_dir):
    """Recupere tous les fichiers .txt du dossier."""
    pattern = os.path.join(data_dir, "*.txt")
    files = sorted(glob.glob(pattern))
    return [f for f in files if count_lines(f) > 0]


def create_output_filename(output_dir, input_file, mode, suffix=""):
    """Genere un nom de fichier de sortie."""
    base = os.path.splitext(os.path.basename(input_file))[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"{base}_{mode}_{timestamp}{suffix}.txt"
    return os.path.join(output_dir, name)


def print_header(filepath, mode, ports=None, methods=None, threads=None, output_file=None):
    """Affiche l'en-tete d'un scan."""
    print(f"\n\033[33m{'='*60}\033[0m")
    print(f"\033[36m  Fichier : {os.path.basename(filepath)}\033[0m")
    print(f"\033[36m  Mode    : {mode}\033[0m")
    if ports:
        print(f"\033[36m  Ports   : {', '.join(ports)}\033[0m")
    if methods:
        print(f"\033[36m  Methods : {', '.join(methods)}\033[0m")
    if threads:
        print(f"\033[36m  Threads : {threads}\033[0m")
    if output_file:
        print(f"\033[36m  Output  : {os.path.basename(output_file)}\033[0m")
    print(f"\033[33m{'='*60}\033[0m")


def create_scanner(filepath, scanner_factory_host, scanner_factory_cidr, **kwargs):
    """Cree le scanner adapte au type de fichier (hosts ou CIDR)."""
    if is_cidr_file(filepath):
        cidrs = read_cidrs(filepath)
        if not cidrs:
            print(f"\033[31m  Aucun CIDR valide dans {filepath}\033[0m")
            return None
        print(f"\033[35m  Type: CIDR ({len(cidrs)} plages)\033[0m")
        return scanner_factory_cidr(cidrs, **kwargs)
    else:
        line_count = count_lines(filepath)
        print(f"\033[35m  Type: Hosts/IPs ({line_count} entrees)\033[0m")
        return scanner_factory_host(filepath, **kwargs)


def scan_file_direct(filepath, ports, methods, threads, timeout, no302, output_dir):
    """Scanne un fichier en mode Direct."""
    mode_name = "directnon302" if no302 else "direct"
    output_file = create_output_filename(output_dir, filepath, mode_name)
    print_header(filepath, "DirectNon302" if no302 else "Direct", ports, methods, threads, output_file)

    def make_host(fp, **kw):
        return HostDirectScanner(method_list=methods, input_file=fp, port_list=ports,
                                 no302=no302, timeout=timeout, output_file=output_file)

    def make_cidr(cidrs, **kw):
        return CIDRDirectScanner(method_list=methods, cidr_ranges=cidrs, port_list=ports,
                                 no302=no302, timeout=timeout, output_file=output_file)

    scanner = create_scanner(filepath, make_host, make_cidr)
    if not scanner:
        return None
    scanner.threads = threads
    scanner.start()
    return output_file


def scan_file_ssl(filepath, threads, output_dir):
    """Scanne un fichier en mode SSL/SNI."""
    output_file = create_output_filename(output_dir, filepath, "ssl")
    print_header(filepath, "SSL/SNI", threads=threads, output_file=output_file)

    def make_host(fp, **kw):
        return HostSSLScanner(input_file=fp, output_file=output_file)

    def make_cidr(cidrs, **kw):
        return CIDRSSLScanner(cidr_ranges=cidrs, output_file=output_file)

    scanner = create_scanner(filepath, make_host, make_cidr)
    if not scanner:
        return None
    scanner.threads = threads
    scanner.start()
    return output_file


def scan_file_ping(filepath, ports, threads, output_dir):
    """Scanne un fichier en mode Ping."""
    output_file = create_output_filename(output_dir, filepath, "ping")
    print_header(filepath, "Ping", ports, threads=threads, output_file=output_file)

    def make_host(fp, **kw):
        return HostPingScanner(input_file=fp, port_list=ports, output_file=output_file)

    def make_cidr(cidrs, **kw):
        return CIDRPingScanner(port_list=ports, cidr_ranges=cidrs, output_file=output_file)

    scanner = create_scanner(filepath, make_host, make_cidr)
    if not scanner:
        return None
    scanner.threads = threads
    scanner.start()
    return output_file


def scan_file_proxy(filepath, ports, threads, target, payload, output_dir):
    """Scanne un fichier en mode Proxy."""
    output_file = create_output_filename(output_dir, filepath, "proxy")
    print_header(filepath, "ProxyTest", ports, threads=threads, output_file=output_file)

    def make_host(fp, **kw):
        return HostProxyScanner(input_file=fp, port_list=ports, target=target,
                                payload=payload, output_file=output_file)

    def make_cidr(cidrs, **kw):
        return CIDRProxyScanner(cidr_ranges=cidrs, port_list=ports, target=target,
                                payload=payload, output_file=output_file)

    scanner = create_scanner(filepath, make_host, make_cidr)
    if not scanner:
        return None
    scanner.threads = threads
    scanner.start()
    return output_file


def merge_results(output_files, output_dir):
    """Fusionne tous les resultats dans un fichier combine."""
    combined_file = os.path.join(
        output_dir,
        f"RESULTATS_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )
    total_lines = 0
    with open(combined_file, 'w', encoding='utf-8') as out:
        out.write(f"{'='*60}\n")
        out.write(f"  RESULTATS COMBINES - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write(f"{'='*60}\n\n")
        for f in output_files:
            if f and os.path.exists(f):
                out.write(f"\n--- {os.path.basename(f)} ---\n")
                with open(f, 'r', encoding='utf-8') as inp:
                    for line in inp:
                        out.write(line)
                        total_lines += 1
                out.write("\n")

    print(f"\n\033[32m  Resultats combines: {os.path.basename(combined_file)}\033[0m")
    print(f"\033[32m  Total lignes      : {total_lines}\033[0m")
    return combined_file


def parse_args():
    parser = argparse.ArgumentParser(
        description="BugScanX Batch Scanner - Scanne TOUS les fichiers d'un dossier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Scanner les IPs generees (mode rapide ping)
  python3 scripts/batch_scan.py --data-dir data/generated --mode ping --ports 80,443

  # Scanner les CIDR directement
  python3 scripts/batch_scan.py --data-dir data/cidr --mode direct --threads 100

  # Scanner les domaines
  python3 scripts/batch_scan.py --data-dir data/domains --mode directnon302

  # Scanner en SSL
  python3 scripts/batch_scan.py --data-dir data/domains --mode ssl

  # Scanner en mode proxy
  python3 scripts/batch_scan.py --data-dir data/generated --mode proxy --ports 80,8080

Workflow recommande:
  1. python3 scripts/generate_ips.py --info          # Voir les stats
  2. python3 scripts/generate_ips.py --split 500     # Generer les IPs
  3. python3 scripts/batch_scan.py --mode ping        # Scan rapide
  4. python3 scripts/batch_scan.py --mode direct      # Scan approfondi
        """
    )
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR,
                        help="Dossier des fichiers a scanner (defaut: data/generated)")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                        help="Dossier pour les resultats (defaut: results)")
    parser.add_argument("--ports", default=",".join(DEFAULT_PORTS),
                        help="Ports a tester (defaut: 80,443,8080,8443)")
    parser.add_argument("--mode", default="direct", choices=SUPPORTED_MODES,
                        help="Mode de scan (defaut: direct)")
    parser.add_argument("--methods", default=",".join(DEFAULT_METHODS),
                        help="Methodes HTTP (defaut: GET,HEAD)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help="Nombre de threads (defaut: 50)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="Timeout en secondes (defaut: 3)")
    parser.add_argument("--no302", action="store_true", default=True,
                        help="Exclure les 302 (defaut)")
    parser.add_argument("--include-302", action="store_true", default=False,
                        help="Inclure les reponses 302")
    parser.add_argument("--proxy-target", default="in1.wstunnel.site",
                        help="URL cible pour le mode proxy")
    parser.add_argument("--proxy-payload", default=None,
                        help="Payload pour le mode proxy")
    parser.add_argument("--files", default=None,
                        help="Fichiers specifiques (virgules), sinon tous les .txt")
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    no302 = args.no302 and not args.include_302
    data_dir = args.data_dir
    output_dir = args.output_dir
    ports = [p.strip() for p in args.ports.split(",")]
    methods = [m.strip().upper() for m in args.methods.split(",")]
    threads = args.threads
    timeout = args.timeout
    mode = args.mode.lower()

    if not os.path.isdir(data_dir):
        print(f"\033[31m  ERREUR: Le dossier '{data_dir}' n'existe pas.\033[0m")
        print(f"\033[33m  Commence par generer les IPs:\033[0m")
        print(f"\033[37m    python3 scripts/generate_ips.py\033[0m")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    if args.files:
        files = [os.path.join(data_dir, f.strip()) for f in args.files.split(",")]
        files = [f for f in files if os.path.isfile(f)]
    else:
        files = get_files_to_scan(data_dir)

    if not files:
        print(f"\033[31m  ERREUR: Aucun fichier .txt valide dans '{data_dir}'\033[0m")
        print(f"\033[33m  Genere d'abord les IPs:\033[0m")
        print(f"\033[37m    python3 scripts/generate_ips.py\033[0m")
        sys.exit(1)

    total_lines_all = sum(count_lines(f) for f in files)

    print(f"\033[36m  Configuration:\033[0m")
    print(f"\033[36m  ├── Dossier source : {data_dir}\033[0m")
    print(f"\033[36m  ├── Dossier output : {output_dir}\033[0m")
    print(f"\033[36m  ├── Mode           : {mode}\033[0m")
    print(f"\033[36m  ├── Ports          : {', '.join(ports)}\033[0m")
    if mode not in ("ssl",):
        print(f"\033[36m  ├── Methodes       : {', '.join(methods)}\033[0m")
    print(f"\033[36m  ├── Threads        : {threads}\033[0m")
    print(f"\033[36m  ├── Timeout        : {timeout}s\033[0m")
    print(f"\033[36m  ├── No302          : {no302}\033[0m")
    print(f"\033[36m  ├── Fichiers       : {len(files)}\033[0m")
    print(f"\033[36m  └── Total entrees  : {total_lines_all:,}\033[0m")
    print()

    for i, f in enumerate(files, 1):
        lc = count_lines(f)
        ft = "CIDR" if is_cidr_file(f) else "Hosts/IPs"
        print(f"\033[36m      {i}. {os.path.basename(f)} ({lc:,} lignes, {ft})\033[0m")

    combos = total_lines_all * len(ports)
    if mode not in ("ssl",):
        combos *= len(methods)
    est_time = combos * timeout / threads
    print(f"\n\033[35m  Combinaisons totales : ~{combos:,}\033[0m")
    print(f"\033[35m  Temps estime         : ~{format_time(est_time)}\033[0m")

    print(f"\n\033[33m  Lancement du scan...\033[0m")
    start_time = datetime.now()
    output_files = []

    for i, filepath in enumerate(files, 1):
        print(f"\n\033[1;33m  [{i}/{len(files)}] {os.path.basename(filepath)}\033[0m")

        try:
            if mode in ("direct", "directnon302"):
                effective_no302 = True if mode == "directnon302" else no302
                result = scan_file_direct(filepath, ports, methods, threads, timeout,
                                          effective_no302, output_dir)
            elif mode == "ssl":
                result = scan_file_ssl(filepath, threads, output_dir)
            elif mode == "ping":
                result = scan_file_ping(filepath, ports, threads, output_dir)
            elif mode == "proxy":
                default_payload = (
                    "GET / HTTP/1.1[crlf]Host: [host][crlf]"
                    "Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]"
                )
                result = scan_file_proxy(filepath, ports, threads,
                                         args.proxy_target,
                                         args.proxy_payload or default_payload,
                                         output_dir)
            else:
                continue

            if result:
                output_files.append(result)
        except KeyboardInterrupt:
            print(f"\n\033[33m  Scan interrompu (Ctrl+C)\033[0m")
            break
        except Exception as e:
            print(f"\033[31m  Erreur: {e}\033[0m")
            continue

    elapsed = datetime.now() - start_time

    print(f"\n\033[33m{'='*60}\033[0m")
    print(f"\033[1;32m  SCAN TERMINE !\033[0m")
    print(f"\033[36m  Duree totale     : {elapsed}\033[0m")
    print(f"\033[36m  Fichiers scannes : {len(output_files)}/{len(files)}\033[0m")
    print(f"\033[33m{'='*60}\033[0m")

    if output_files:
        merge_results(output_files, output_dir)
        print(f"\n\033[36m  Resultats individuels:\033[0m")
        for f in output_files:
            if f and os.path.exists(f):
                size = os.path.getsize(f)
                print(f"\033[36m    - {os.path.basename(f)} ({size:,} octets)\033[0m")
    else:
        print(f"\n\033[33m  Aucun resultat.\033[0m")
    print()


def format_time(seconds):
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.0f}min"
    else:
        return f"{seconds/3600:.1f}h"


if __name__ == "__main__":
    main()
