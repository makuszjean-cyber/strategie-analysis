#!/usr/bin/env python3
"""
Generateur d'IPs a partir de fichiers CIDR.

Lit les fichiers CIDR dans data/cidr/ et genere des listes d'IPs
completes dans data/generated/.

Usage:
    python3 scripts/generate_ips.py                         # Tous les fichiers CIDR
    python3 scripts/generate_ips.py --file orange_rdc.txt   # Un fichier specifique
    python3 scripts/generate_ips.py --split 1000            # Decouper en fichiers de 1000 IPs
    python3 scripts/generate_ips.py --info                  # Afficher les stats sans generer
"""

import os
import sys
import argparse
import ipaddress
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CIDR_DIR = os.path.join(PROJECT_ROOT, "data", "cidr")
GENERATED_DIR = os.path.join(PROJECT_ROOT, "data", "generated")


def parse_cidr_file(filepath):
    """Lit un fichier CIDR et retourne les plages valides."""
    cidrs = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    network = ipaddress.ip_network(line, strict=False)
                    cidrs.append(network)
                except ValueError:
                    print(f"  \033[33m[!] Plage invalide ignoree: {line}\033[0m")
    except (IOError, UnicodeDecodeError) as e:
        print(f"  \033[31m[X] Erreur lecture {filepath}: {e}\033[0m")
    return cidrs


def count_hosts(cidrs):
    """Compte le nombre total d'hotes dans une liste de plages CIDR."""
    total = 0
    for network in cidrs:
        total += max(0, network.num_addresses - 2) if network.prefixlen < 31 else network.num_addresses
    return total


def generate_ips(cidrs):
    """Genere toutes les IPs depuis une liste de plages CIDR."""
    for network in cidrs:
        for ip in network.hosts():
            yield str(ip)


def show_info(cidr_files):
    """Affiche les statistiques de chaque fichier CIDR."""
    grand_total = 0

    print(f"\n\033[36m{'='*65}\033[0m")
    print(f"\033[1;36m  STATISTIQUES DES FICHIERS CIDR\033[0m")
    print(f"\033[36m{'='*65}\033[0m\n")

    for filepath in cidr_files:
        basename = os.path.basename(filepath)
        cidrs = parse_cidr_file(filepath)

        if not cidrs:
            print(f"  \033[33m{basename}: aucune plage valide\033[0m")
            continue

        total = count_hosts(cidrs)
        grand_total += total

        print(f"  \033[1;32m{basename}\033[0m")
        print(f"  \033[36m  Plages CIDR : {len(cidrs)}\033[0m")
        print(f"  \033[36m  Total IPs   : {total:,}\033[0m")

        time_50t = total * 2 / 50
        time_100t = total * 2 / 100

        print(f"  \033[35m  Temps estime (50 threads)  : ~{format_time(time_50t)}\033[0m")
        print(f"  \033[35m  Temps estime (100 threads) : ~{format_time(time_100t)}\033[0m")
        print()

        for network in cidrs:
            hosts = max(0, network.num_addresses - 2) if network.prefixlen < 31 else network.num_addresses
            first = str(list(network.hosts())[0]) if hosts > 0 else "N/A"
            last = str(list(network.hosts())[-1]) if hosts > 0 else "N/A"
            print(f"    \033[37m{str(network):<20} {hosts:>6} IPs  ({first} -> {last})\033[0m")
        print()

    print(f"\033[36m{'='*65}\033[0m")
    print(f"\033[1;32m  TOTAL GENERAL : {grand_total:,} IPs\033[0m")
    print(f"\033[35m  Temps estime scan complet (50 threads, 2s timeout) : ~{format_time(grand_total * 2 / 50)}\033[0m")
    print(f"\033[35m  Temps estime scan complet (100 threads, 2s timeout): ~{format_time(grand_total * 2 / 100)}\033[0m")
    print(f"\033[36m{'='*65}\033[0m\n")


def format_time(seconds):
    """Formate un nombre de secondes en format lisible."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.0f}min"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def process_file(filepath, split_size, output_dir):
    """Traite un fichier CIDR et genere les IPs."""
    basename = os.path.splitext(os.path.basename(filepath))[0]
    cidrs = parse_cidr_file(filepath)

    if not cidrs:
        print(f"  \033[33m[!] Aucune plage valide dans {os.path.basename(filepath)}\033[0m")
        return []

    total = count_hosts(cidrs)
    print(f"\n  \033[1;32m{os.path.basename(filepath)}\033[0m")
    print(f"  \033[36m  Plages: {len(cidrs)} | IPs a generer: {total:,}\033[0m")

    generated_files = []

    if split_size and split_size > 0:
        file_num = 1
        current_batch = []

        for ip in generate_ips(cidrs):
            current_batch.append(ip)
            if len(current_batch) >= split_size:
                outfile = os.path.join(output_dir, f"{basename}_part{file_num:03d}.txt")
                write_ips(outfile, current_batch)
                generated_files.append((outfile, len(current_batch)))
                current_batch = []
                file_num += 1

        if current_batch:
            outfile = os.path.join(output_dir, f"{basename}_part{file_num:03d}.txt")
            write_ips(outfile, current_batch)
            generated_files.append((outfile, len(current_batch)))
    else:
        outfile = os.path.join(output_dir, f"{basename}_all_ips.txt")
        ips = list(generate_ips(cidrs))
        write_ips(outfile, ips)
        generated_files.append((outfile, len(ips)))

    for f, count in generated_files:
        print(f"  \033[32m  -> {os.path.basename(f)} ({count:,} IPs)\033[0m")

    return generated_files


def write_ips(filepath, ips):
    """Ecrit une liste d'IPs dans un fichier."""
    with open(filepath, 'w', encoding='utf-8') as f:
        for ip in ips:
            f.write(ip + '\n')


def get_cidr_files(specific_file=None):
    """Recupere les fichiers CIDR a traiter."""
    if specific_file:
        path = os.path.join(CIDR_DIR, specific_file)
        if not os.path.isfile(path):
            path = specific_file
        if os.path.isfile(path):
            return [path]
        print(f"\033[31m  [X] Fichier non trouve: {specific_file}\033[0m")
        return []

    if not os.path.isdir(CIDR_DIR):
        print(f"\033[31m  [X] Dossier {CIDR_DIR} non trouve\033[0m")
        return []

    files = sorted([
        os.path.join(CIDR_DIR, f) for f in os.listdir(CIDR_DIR)
        if f.endswith('.txt') and os.path.getsize(os.path.join(CIDR_DIR, f)) > 0
    ])

    valid_files = []
    for f in files:
        cidrs = parse_cidr_file(f)
        if cidrs:
            valid_files.append(f)

    return valid_files


def main():
    parser = argparse.ArgumentParser(
        description="Generateur d'IPs a partir de fichiers CIDR",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python3 scripts/generate_ips.py --info
  python3 scripts/generate_ips.py
  python3 scripts/generate_ips.py --file orange_rdc.txt
  python3 scripts/generate_ips.py --split 500
  python3 scripts/generate_ips.py --file orange_rdc.txt --split 1000
        """
    )
    parser.add_argument("--file", help="Fichier CIDR specifique a traiter")
    parser.add_argument("--split", type=int, default=0,
                        help="Decouper en fichiers de N IPs (0 = un seul fichier)")
    parser.add_argument("--output", default=GENERATED_DIR,
                        help=f"Dossier de sortie (defaut: {GENERATED_DIR})")
    parser.add_argument("--info", action="store_true",
                        help="Afficher les statistiques sans generer de fichiers")

    args = parser.parse_args()
    os.makedirs(args.output, exist_ok=True)

    cidr_files = get_cidr_files(args.file)
    if not cidr_files:
        print("\033[31m  [X] Aucun fichier CIDR valide trouve.\033[0m")
        print(f"\033[33m  Ajoute tes fichiers dans {CIDR_DIR}/\033[0m")
        sys.exit(1)

    if args.info:
        show_info(cidr_files)
        return

    print(f"\n\033[36m{'='*65}\033[0m")
    print(f"\033[1;36m  GENERATION DES IPs\033[0m")
    print(f"\033[36m{'='*65}\033[0m")
    print(f"  \033[36mFichiers CIDR : {len(cidr_files)}\033[0m")
    print(f"  \033[36mSortie        : {args.output}\033[0m")
    if args.split:
        print(f"  \033[36mDecoupage     : {args.split} IPs par fichier\033[0m")

    start = datetime.now()
    all_files = []

    for filepath in cidr_files:
        files = process_file(filepath, args.split, args.output)
        all_files.extend(files)

    elapsed = datetime.now() - start

    total_ips = sum(count for _, count in all_files)
    print(f"\n\033[36m{'='*65}\033[0m")
    print(f"\033[1;32m  TERMINE !\033[0m")
    print(f"  \033[36mFichiers generes : {len(all_files)}\033[0m")
    print(f"  \033[36mTotal IPs        : {total_ips:,}\033[0m")
    print(f"  \033[36mDuree            : {elapsed}\033[0m")
    print(f"  \033[36mSortie           : {args.output}/\033[0m")
    print(f"\033[36m{'='*65}\033[0m\n")

    print(f"  \033[33mProchaine etape: lance le scan avec:\033[0m")
    print(f"  \033[37m  python3 scripts/batch_scan.py --data-dir {args.output} --mode ping --ports 80,443,8080\033[0m")
    print()


if __name__ == "__main__":
    main()
