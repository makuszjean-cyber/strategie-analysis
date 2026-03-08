#!/usr/bin/env python3
"""
BugScanX Batch Scanner
Scanne automatiquement tous les fichiers du dossier 'data/' avec plusieurs ports.

Usage:
    python batch_scan.py
    python batch_scan.py --data-dir data --ports 80,443,8080,8443 --mode direct
    python batch_scan.py --help
"""

import os
import sys
import glob
import argparse
import ipaddress
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bugscanx.modules.scanners.scanners.direct import HostDirectScanner, CIDRDirectScanner
from bugscanx.modules.scanners.scanners.ssl import HostSSLScanner, CIDRSSLScanner
from bugscanx.modules.scanners.scanners.ping import HostPingScanner, CIDRPingScanner
from bugscanx.modules.scanners.scanners.proxy_check import HostProxyScanner, CIDRProxyScanner


DEFAULT_PORTS = ["80", "443", "8080", "8443"]
DEFAULT_METHODS = ["GET", "HEAD"]
DEFAULT_THREADS = 50
DEFAULT_TIMEOUT = 3
DEFAULT_DATA_DIR = "data"
DEFAULT_OUTPUT_DIR = "results"

SUPPORTED_MODES = ["direct", "directnon302", "ssl", "ping", "proxy"]

BANNER = """
\033[36m╔══════════════════════════════════════════════════════════╗
║          BugScanX Batch Scanner                          ║
║          Scan tous les fichiers du dossier data/         ║
╚══════════════════════════════════════════════════════════╝\033[0m
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
    """Recupere tous les fichiers .txt du dossier data."""
    pattern = os.path.join(data_dir, "*.txt")
    files = sorted(glob.glob(pattern))
    return files


def create_output_filename(output_dir, input_file, mode, suffix=""):
    """Genere un nom de fichier de sortie base sur le fichier d'entree."""
    base = os.path.splitext(os.path.basename(input_file))[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"{base}_{mode}_{timestamp}{suffix}.txt"
    return os.path.join(output_dir, name)


def scan_file_direct(filepath, ports, methods, threads, timeout, no302, output_dir):
    """Scanne un fichier en mode Direct ou DirectNon302."""
    mode_name = "directnon302" if no302 else "direct"
    output_file = create_output_filename(output_dir, filepath, mode_name)

    print(f"\n\033[33m{'='*60}\033[0m")
    print(f"\033[36m  Fichier : {os.path.basename(filepath)}\033[0m")
    print(f"\033[36m  Mode    : {'DirectNon302' if no302 else 'Direct'}\033[0m")
    print(f"\033[36m  Ports   : {', '.join(ports)}\033[0m")
    print(f"\033[36m  Methods : {', '.join(methods)}\033[0m")
    print(f"\033[36m  Threads : {threads}\033[0m")
    print(f"\033[36m  Output  : {output_file}\033[0m")
    print(f"\033[33m{'='*60}\033[0m")

    if is_cidr_file(filepath):
        cidrs = read_cidrs(filepath)
        if not cidrs:
            print(f"\033[31m  Aucun CIDR valide dans {filepath}\033[0m")
            return None
        print(f"\033[35m  Type: CIDR ({len(cidrs)} plages)\033[0m")
        scanner = CIDRDirectScanner(
            method_list=methods,
            cidr_ranges=cidrs,
            port_list=ports,
            no302=no302,
            timeout=timeout,
            output_file=output_file
        )
    else:
        line_count = count_lines(filepath)
        print(f"\033[35m  Type: Hosts ({line_count} entrees)\033[0m")
        scanner = HostDirectScanner(
            method_list=methods,
            input_file=filepath,
            port_list=ports,
            no302=no302,
            timeout=timeout,
            output_file=output_file
        )

    scanner.threads = threads
    scanner.start()
    return output_file


def scan_file_ssl(filepath, threads, output_dir):
    """Scanne un fichier en mode SSL/SNI."""
    output_file = create_output_filename(output_dir, filepath, "ssl")

    print(f"\n\033[33m{'='*60}\033[0m")
    print(f"\033[36m  Fichier : {os.path.basename(filepath)}\033[0m")
    print(f"\033[36m  Mode    : SSL/SNI\033[0m")
    print(f"\033[36m  Threads : {threads}\033[0m")
    print(f"\033[36m  Output  : {output_file}\033[0m")
    print(f"\033[33m{'='*60}\033[0m")

    if is_cidr_file(filepath):
        cidrs = read_cidrs(filepath)
        if not cidrs:
            print(f"\033[31m  Aucun CIDR valide dans {filepath}\033[0m")
            return None
        print(f"\033[35m  Type: CIDR ({len(cidrs)} plages)\033[0m")
        scanner = CIDRSSLScanner(
            cidr_ranges=cidrs,
            output_file=output_file
        )
    else:
        line_count = count_lines(filepath)
        print(f"\033[35m  Type: Hosts ({line_count} entrees)\033[0m")
        scanner = HostSSLScanner(
            input_file=filepath,
            output_file=output_file
        )

    scanner.threads = threads
    scanner.start()
    return output_file


def scan_file_ping(filepath, ports, threads, output_dir):
    """Scanne un fichier en mode Ping."""
    output_file = create_output_filename(output_dir, filepath, "ping")

    print(f"\n\033[33m{'='*60}\033[0m")
    print(f"\033[36m  Fichier : {os.path.basename(filepath)}\033[0m")
    print(f"\033[36m  Mode    : Ping\033[0m")
    print(f"\033[36m  Ports   : {', '.join(ports)}\033[0m")
    print(f"\033[36m  Threads : {threads}\033[0m")
    print(f"\033[36m  Output  : {output_file}\033[0m")
    print(f"\033[33m{'='*60}\033[0m")

    if is_cidr_file(filepath):
        cidrs = read_cidrs(filepath)
        if not cidrs:
            print(f"\033[31m  Aucun CIDR valide dans {filepath}\033[0m")
            return None
        print(f"\033[35m  Type: CIDR ({len(cidrs)} plages)\033[0m")
        scanner = CIDRPingScanner(
            port_list=ports,
            cidr_ranges=cidrs,
            output_file=output_file
        )
    else:
        line_count = count_lines(filepath)
        print(f"\033[35m  Type: Hosts ({line_count} entrees)\033[0m")
        scanner = HostPingScanner(
            input_file=filepath,
            port_list=ports,
            output_file=output_file
        )

    scanner.threads = threads
    scanner.start()
    return output_file


def scan_file_proxy(filepath, ports, threads, target, payload, output_dir):
    """Scanne un fichier en mode Proxy."""
    output_file = create_output_filename(output_dir, filepath, "proxy")

    print(f"\n\033[33m{'='*60}\033[0m")
    print(f"\033[36m  Fichier : {os.path.basename(filepath)}\033[0m")
    print(f"\033[36m  Mode    : ProxyTest\033[0m")
    print(f"\033[36m  Ports   : {', '.join(ports)}\033[0m")
    print(f"\033[36m  Target  : {target}\033[0m")
    print(f"\033[36m  Threads : {threads}\033[0m")
    print(f"\033[36m  Output  : {output_file}\033[0m")
    print(f"\033[33m{'='*60}\033[0m")

    if is_cidr_file(filepath):
        cidrs = read_cidrs(filepath)
        if not cidrs:
            print(f"\033[31m  Aucun CIDR valide dans {filepath}\033[0m")
            return None
        print(f"\033[35m  Type: CIDR ({len(cidrs)} plages)\033[0m")
        scanner = CIDRProxyScanner(
            cidr_ranges=cidrs,
            port_list=ports,
            target=target,
            payload=payload,
            output_file=output_file
        )
    else:
        line_count = count_lines(filepath)
        print(f"\033[35m  Type: Hosts ({line_count} entrees)\033[0m")
        scanner = HostProxyScanner(
            input_file=filepath,
            port_list=ports,
            target=target,
            payload=payload,
            output_file=output_file
        )

    scanner.threads = threads
    scanner.start()
    return output_file


def merge_results(output_files, output_dir):
    """Fusionne tous les resultats dans un fichier combine."""
    combined_file = os.path.join(
        output_dir,
        f"combined_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )
    total_lines = 0
    with open(combined_file, 'w', encoding='utf-8') as out:
        out.write(f"=== Resultats combines - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")
        for f in output_files:
            if f and os.path.exists(f):
                out.write(f"\n--- {os.path.basename(f)} ---\n")
                with open(f, 'r', encoding='utf-8') as inp:
                    for line in inp:
                        out.write(line)
                        total_lines += 1
                out.write("\n")

    print(f"\n\033[32m  Resultats combines dans : {combined_file}\033[0m")
    print(f"\033[32m  Total lignes : {total_lines}\033[0m")
    return combined_file


def parse_args():
    parser = argparse.ArgumentParser(
        description="BugScanX Batch Scanner - Scanne tous les fichiers du dossier data/",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python batch_scan.py
  python batch_scan.py --data-dir data --ports 80,443,8080 --mode direct
  python batch_scan.py --mode ssl --threads 100
  python batch_scan.py --mode ping --ports 80,443
  python batch_scan.py --mode proxy --proxy-target in1.wstunnel.site
        """
    )
    parser.add_argument(
        "--data-dir", default=DEFAULT_DATA_DIR,
        help=f"Dossier contenant les fichiers a scanner (defaut: {DEFAULT_DATA_DIR})"
    )
    parser.add_argument(
        "--output-dir", default=DEFAULT_OUTPUT_DIR,
        help=f"Dossier pour les resultats (defaut: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--ports", default=",".join(DEFAULT_PORTS),
        help=f"Ports a tester, separes par des virgules (defaut: {','.join(DEFAULT_PORTS)})"
    )
    parser.add_argument(
        "--mode", default="direct", choices=SUPPORTED_MODES,
        help="Mode de scan (defaut: direct)"
    )
    parser.add_argument(
        "--methods", default=",".join(DEFAULT_METHODS),
        help=f"Methodes HTTP, separees par des virgules (defaut: {','.join(DEFAULT_METHODS)})"
    )
    parser.add_argument(
        "--threads", type=int, default=DEFAULT_THREADS,
        help=f"Nombre de threads (defaut: {DEFAULT_THREADS})"
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT,
        help=f"Timeout en secondes (defaut: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "--no302", action="store_true", default=True,
        help="Exclure les reponses 302 (active par defaut)"
    )
    parser.add_argument(
        "--include-302", action="store_true", default=False,
        help="Inclure les reponses 302"
    )
    parser.add_argument(
        "--proxy-target", default="in1.wstunnel.site",
        help="URL cible pour le mode proxy (defaut: in1.wstunnel.site)"
    )
    parser.add_argument(
        "--proxy-payload", default=None,
        help="Payload personnalise pour le mode proxy"
    )
    parser.add_argument(
        "--files", default=None,
        help="Fichiers specifiques a scanner (separes par des virgules), sinon tous les .txt"
    )
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
        print(f"\033[33m  Cree le dossier et ajoute tes fichiers .txt dedans.\033[0m")
        print(f"\033[33m  Exemple: mkdir {data_dir}\033[0m")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    if args.files:
        files = [os.path.join(data_dir, f.strip()) for f in args.files.split(",")]
        files = [f for f in files if os.path.isfile(f)]
    else:
        files = get_files_to_scan(data_dir)

    if not files:
        print(f"\033[31m  ERREUR: Aucun fichier .txt trouve dans '{data_dir}'\033[0m")
        print(f"\033[33m  Ajoute des fichiers avec des domaines ou des CIDR.\033[0m")
        sys.exit(1)

    print(f"\033[36m  Configuration:\033[0m")
    print(f"\033[36m  ├── Dossier data  : {data_dir}\033[0m")
    print(f"\033[36m  ├── Dossier output: {output_dir}\033[0m")
    print(f"\033[36m  ├── Mode          : {mode}\033[0m")
    print(f"\033[36m  ├── Ports         : {', '.join(ports)}\033[0m")
    print(f"\033[36m  ├── Methodes      : {', '.join(methods)}\033[0m")
    print(f"\033[36m  ├── Threads       : {threads}\033[0m")
    print(f"\033[36m  ├── Timeout       : {timeout}s\033[0m")
    print(f"\033[36m  ├── No302         : {no302}\033[0m")
    print(f"\033[36m  └── Fichiers      : {len(files)}\033[0m")
    print()

    for i, f in enumerate(files, 1):
        line_count = count_lines(f)
        file_type = "CIDR" if is_cidr_file(f) else "Hosts"
        print(f"\033[36m      {i}. {os.path.basename(f)} ({line_count} lignes, type: {file_type})\033[0m")

    print(f"\n\033[33m  Debut du scan...\033[0m")
    start_time = datetime.now()

    output_files = []

    for i, filepath in enumerate(files, 1):
        print(f"\n\033[1;33m  [{i}/{len(files)}] Scan de {os.path.basename(filepath)}\033[0m")

        try:
            if mode in ("direct", "directnon302"):
                effective_no302 = True if mode == "directnon302" else no302
                result = scan_file_direct(
                    filepath, ports, methods, threads, timeout,
                    effective_no302, output_dir
                )
            elif mode == "ssl":
                result = scan_file_ssl(filepath, threads, output_dir)
            elif mode == "ping":
                result = scan_file_ping(filepath, ports, threads, output_dir)
            elif mode == "proxy":
                default_payload = (
                    "GET / HTTP/1.1[crlf]"
                    "Host: [host][crlf]"
                    "Connection: Upgrade[crlf]"
                    "Upgrade: websocket[crlf][crlf]"
                )
                result = scan_file_proxy(
                    filepath, ports, threads,
                    args.proxy_target,
                    args.proxy_payload or default_payload,
                    output_dir
                )
            else:
                print(f"\033[31m  Mode '{mode}' non supporte\033[0m")
                continue

            if result:
                output_files.append(result)
        except KeyboardInterrupt:
            print(f"\n\033[33m  Scan interrompu par l'utilisateur\033[0m")
            break
        except Exception as e:
            print(f"\033[31m  Erreur lors du scan de {filepath}: {e}\033[0m")
            continue

    elapsed = datetime.now() - start_time

    print(f"\n\033[33m{'='*60}\033[0m")
    print(f"\033[1;32m  SCAN TERMINE !\033[0m")
    print(f"\033[36m  Duree totale    : {elapsed}\033[0m")
    print(f"\033[36m  Fichiers scannes: {len(output_files)}/{len(files)}\033[0m")
    print(f"\033[33m{'='*60}\033[0m")

    if output_files:
        merge_results(output_files, output_dir)

        print(f"\n\033[36m  Fichiers de resultats individuels:\033[0m")
        for f in output_files:
            if f and os.path.exists(f):
                size = os.path.getsize(f)
                print(f"\033[36m    - {os.path.basename(f)} ({size} octets)\033[0m")
    else:
        print(f"\n\033[33m  Aucun resultat genere.\033[0m")

    print()


if __name__ == "__main__":
    main()
