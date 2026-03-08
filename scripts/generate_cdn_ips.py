#!/usr/bin/env python3
"""
Generateur d'IPs CDN pour le scan de Bug Hosts.

Telecharge les plages CIDR officielles de :
  - Cloudflare (AS13335)
  - AWS CloudFront (Edge mondial)
  - Google Cloud / GWS
  - Microsoft Azure CDN
  - Fastly
  - Akamai (plages connues)
  - Incapsula / Imperva
  - Sucuri

Puis genere des fichiers .txt avec toutes les IPs individuelles.

Usage:
    python3 scripts/generate_cdn_ips.py --info              # Stats seulement
    python3 scripts/generate_cdn_ips.py                     # Generer tout
    python3 scripts/generate_cdn_ips.py --provider cloudflare  # Un seul provider
    python3 scripts/generate_cdn_ips.py --split 5000        # Decouper en fichiers
    python3 scripts/generate_cdn_ips.py --cidr-only         # Sauvegarder les CIDR seulement
"""

import os
import sys
import json
import argparse
import ipaddress
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CIDR_DIR = os.path.join(PROJECT_ROOT, "data", "cidr")
GENERATED_DIR = os.path.join(PROJECT_ROOT, "data", "generated")

TIMEOUT = 30

# ============================================================
#  Sources officielles des plages CIDR
# ============================================================

PROVIDERS = {
    "cloudflare": {
        "name": "Cloudflare",
        "description": "CDN + Protection DDoS (AS13335) - Le plus utilise pour les bug hosts",
        "sources": [
            {"url": "https://www.cloudflare.com/ips-v4/", "type": "text"},
        ],
    },
    "cloudfront": {
        "name": "AWS CloudFront",
        "description": "CDN Amazon - Edge servers mondiaux",
        "sources": [
            {
                "url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
                "type": "aws_json",
                "service_filter": "CLOUDFRONT",
            },
        ],
    },
    "google": {
        "name": "Google Cloud / GWS",
        "description": "Google Cloud Platform + Google Web Services",
        "sources": [
            {"url": "https://www.gstatic.com/ipranges/cloud.json", "type": "google_json"},
            {"url": "https://www.gstatic.com/ipranges/goog.json", "type": "google_json"},
        ],
    },
    "azure": {
        "name": "Microsoft Azure",
        "description": "Azure CDN + Azure Front Door",
        "sources": [
            {
                "url": "https://azureipranges.azurewebsites.net/Data/Public.json",
                "type": "azure_json",
                "service_filter": ["AzureFrontDoor.Frontend", "AzureFrontDoor.Backend",
                                   "AzureCDN", "AzureFrontDoor.FirstParty"],
            },
        ],
        "fallback_cidrs": [
            "13.107.246.0/24", "13.107.213.0/24", "147.243.0.0/16",
            "20.37.0.0/16", "20.38.0.0/16", "20.39.0.0/16",
            "20.40.0.0/16", "20.41.0.0/16", "20.42.0.0/16",
            "20.43.0.0/16", "20.44.0.0/16", "20.45.0.0/16",
            "20.46.0.0/16", "20.47.0.0/16", "20.48.0.0/16",
            "20.49.0.0/16", "20.50.0.0/16", "20.51.0.0/16",
        ],
    },
    "fastly": {
        "name": "Fastly",
        "description": "CDN Edge Cloud",
        "sources": [
            {"url": "https://api.fastly.com/public-ip-list", "type": "fastly_json"},
        ],
    },
    "akamai": {
        "name": "Akamai",
        "description": "Plus grand CDN mondial - Edge servers",
        "sources": [],
        "fallback_cidrs": [
            "23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14",
            "23.72.0.0/13", "104.64.0.0/10",
            "184.24.0.0/13", "184.50.0.0/15", "184.84.0.0/14",
            "2.16.0.0/13", "95.100.0.0/15",
            "72.246.0.0/15", "96.6.0.0/15", "96.16.0.0/15",
            "92.122.0.0/15", "23.192.0.0/11",
            "118.214.0.0/16", "184.25.0.0/16",
        ],
    },
    "incapsula": {
        "name": "Incapsula / Imperva",
        "description": "WAF + CDN (racheté par Imperva)",
        "sources": [],
        "fallback_cidrs": [
            "199.83.128.0/21", "198.143.32.0/19",
            "149.126.72.0/21", "103.28.248.0/22",
            "45.64.64.0/22", "185.11.124.0/22",
            "192.230.64.0/18", "107.154.0.0/16",
            "45.60.0.0/16", "45.223.0.0/16",
        ],
    },
    "sucuri": {
        "name": "Sucuri",
        "description": "WAF + Protection de sites web",
        "sources": [],
        "fallback_cidrs": [
            "192.88.134.0/23", "185.93.228.0/22",
            "66.248.200.0/22", "208.109.0.0/22",
            "2a02:fe80::/29",
        ],
    },
}


def fetch_url(url):
    """Telecharge le contenu d'une URL."""
    try:
        req = Request(url, headers={"User-Agent": "BugScanX/2.0"})
        with urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read().decode("utf-8")
    except (URLError, OSError, UnicodeDecodeError) as e:
        print(f"    \033[31m[X] Erreur telechargement {url}: {e}\033[0m")
        return None


def parse_text_cidrs(text):
    """Parse des CIDR depuis du texte brut (un par ligne)."""
    cidrs = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_network(line, strict=False)
            cidrs.append(line)
        except ValueError:
            pass
    return cidrs


def parse_aws_json(text, service_filter):
    """Parse les CIDR depuis le JSON AWS."""
    try:
        data = json.loads(text)
        return [
            p["ip_prefix"] for p in data.get("prefixes", [])
            if p.get("service") == service_filter and "ip_prefix" in p
        ]
    except (json.JSONDecodeError, KeyError):
        return []


def parse_google_json(text):
    """Parse les CIDR depuis le JSON Google."""
    try:
        data = json.loads(text)
        return [
            p["ipv4Prefix"] for p in data.get("prefixes", [])
            if "ipv4Prefix" in p
        ]
    except (json.JSONDecodeError, KeyError):
        return []


def parse_azure_json(text, service_filters):
    """Parse les CIDR depuis le JSON Azure."""
    try:
        data = json.loads(text)
        cidrs = []
        for entry in data.get("values", []):
            name = entry.get("name", "")
            if any(sf in name for sf in service_filters):
                props = entry.get("properties", {})
                for prefix in props.get("addressPrefixes", []):
                    if ":" not in prefix:
                        cidrs.append(prefix)
        return cidrs
    except (json.JSONDecodeError, KeyError):
        return []


def parse_fastly_json(text):
    """Parse les CIDR depuis le JSON Fastly."""
    try:
        data = json.loads(text)
        return data.get("addresses", [])
    except (json.JSONDecodeError, KeyError):
        return []


def fetch_cidrs_for_provider(provider_key):
    """Telecharge et parse les CIDR pour un provider."""
    config = PROVIDERS[provider_key]
    all_cidrs = set()

    for source in config.get("sources", []):
        url = source["url"]
        source_type = source["type"]

        print(f"    \033[37mTelechargement: {url}\033[0m")
        text = fetch_url(url)
        if not text:
            continue

        if source_type == "text":
            cidrs = parse_text_cidrs(text)
        elif source_type == "aws_json":
            cidrs = parse_aws_json(text, source["service_filter"])
        elif source_type == "google_json":
            cidrs = parse_google_json(text)
        elif source_type == "azure_json":
            cidrs = parse_azure_json(text, source["service_filter"])
        elif source_type == "fastly_json":
            cidrs = parse_fastly_json(text)
        else:
            cidrs = []

        all_cidrs.update(cidrs)
        print(f"    \033[32m[OK] {len(cidrs)} plages obtenues\033[0m")

    fallback = config.get("fallback_cidrs", [])
    if not all_cidrs and fallback:
        print(f"    \033[33m[!] Utilisation des plages fallback ({len(fallback)} plages)\033[0m")
        all_cidrs.update(fallback)
    elif fallback and all_cidrs:
        pass

    valid_cidrs = []
    for cidr in all_cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.version == 4:
                valid_cidrs.append(str(net))
        except ValueError:
            pass

    return sorted(valid_cidrs, key=lambda c: ipaddress.ip_network(c, strict=False))


def count_ips_in_cidrs(cidrs):
    """Compte le total d'IPs dans une liste de CIDR."""
    total = 0
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        total += max(0, net.num_addresses - 2) if net.prefixlen < 31 else net.num_addresses
    return total


def generate_ips_from_cidrs(cidrs):
    """Genere toutes les IPs depuis une liste de CIDR."""
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        for ip in net.hosts():
            yield str(ip)


def format_number(n):
    """Formate un nombre avec separateur de milliers."""
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    elif n >= 1_000:
        return f"{n/1_000:.1f}K"
    return str(n)


def format_time(seconds):
    """Formate un temps en format lisible."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.0f}min"
    elif seconds < 86400:
        return f"{seconds/3600:.1f}h"
    else:
        return f"{seconds/86400:.1f} jours"


def write_ips_to_files(ips_generator, total_ips, output_dir, basename, split_size):
    """Ecrit les IPs dans un ou plusieurs fichiers."""
    files_created = []

    if split_size and split_size > 0:
        file_num = 1
        batch = []
        written = 0

        for ip in ips_generator:
            batch.append(ip)
            if len(batch) >= split_size:
                filename = f"{basename}_part{file_num:04d}.txt"
                filepath = os.path.join(output_dir, filename)
                with open(filepath, 'w') as f:
                    f.write('\n'.join(batch) + '\n')
                files_created.append((filepath, len(batch)))
                written += len(batch)
                batch = []
                file_num += 1

                pct = written / total_ips * 100 if total_ips else 0
                sys.stdout.write(f"\r    \033[36m[{pct:5.1f}%] {format_number(written)} IPs ecrites, {file_num-1} fichiers\033[0m")
                sys.stdout.flush()

        if batch:
            filename = f"{basename}_part{file_num:04d}.txt"
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'w') as f:
                f.write('\n'.join(batch) + '\n')
            files_created.append((filepath, len(batch)))
            written += len(batch)

        sys.stdout.write(f"\r    \033[32m[100%] {format_number(written)} IPs ecrites, {len(files_created)} fichiers\033[0m\n")
    else:
        filename = f"{basename}_full.txt"
        filepath = os.path.join(output_dir, filename)
        written = 0
        with open(filepath, 'w') as f:
            for ip in ips_generator:
                f.write(ip + '\n')
                written += 1
                if written % 50000 == 0:
                    pct = written / total_ips * 100 if total_ips else 0
                    sys.stdout.write(f"\r    \033[36m[{pct:5.1f}%] {format_number(written)} IPs ecrites\033[0m")
                    sys.stdout.flush()

        sys.stdout.write(f"\r    \033[32m[100%] {format_number(written)} IPs ecrites -> {filename}\033[0m\n")
        files_created.append((filepath, written))

    return files_created


def save_cidr_file(provider_key, cidrs, output_dir):
    """Sauvegarde les CIDR bruts dans un fichier."""
    config = PROVIDERS[provider_key]
    filename = f"{provider_key}_cidr.txt"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, 'w') as f:
        f.write(f"# {config['name']} - Plages CIDR IPv4\n")
        f.write(f"# {config['description']}\n")
        f.write(f"# Genere le: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total: {len(cidrs)} plages, ~{format_number(count_ips_in_cidrs(cidrs))} IPs\n\n")
        for cidr in cidrs:
            f.write(cidr + '\n')

    return filepath


def show_info(providers_to_process):
    """Affiche les stats de tous les providers."""
    print(f"\n\033[36m{'='*70}\033[0m")
    print(f"\033[1;36m  STATISTIQUES DES PROVIDERS CDN\033[0m")
    print(f"\033[36m{'='*70}\033[0m\n")

    grand_total = 0

    for key in providers_to_process:
        config = PROVIDERS[key]
        print(f"  \033[1;32m{config['name']}\033[0m")
        print(f"  \033[37m{config['description']}\033[0m")

        cidrs = fetch_cidrs_for_provider(key)
        total = count_ips_in_cidrs(cidrs)
        grand_total += total

        print(f"    \033[36mPlages CIDR : {len(cidrs)}\033[0m")
        print(f"    \033[36mTotal IPs   : {total:,} ({format_number(total)})\033[0m")

        time_50 = total * 2 / 50
        time_100 = total * 2 / 100
        print(f"    \033[35mTemps scan (50 threads)  : ~{format_time(time_50)}\033[0m")
        print(f"    \033[35mTemps scan (100 threads) : ~{format_time(time_100)}\033[0m")
        print()

    print(f"\033[36m{'='*70}\033[0m")
    print(f"\033[1;32m  TOTAL GENERAL : {grand_total:,} IPs ({format_number(grand_total)})\033[0m")
    t100 = grand_total * 2 / 100
    print(f"\033[35m  Temps scan complet (100 threads) : ~{format_time(t100)}\033[0m")
    print(f"\033[36m{'='*70}\033[0m\n")

    print(f"  \033[33mRecommandation:\033[0m")
    print(f"  \033[37m  Commence par Cloudflare et Fastly (les plus petits)\033[0m")
    print(f"  \033[37m  puis CloudFront, puis Google/Azure (les plus gros)\033[0m")
    print(f"  \033[37m  Akamai est ENORME, garde-le pour la fin.\033[0m\n")


def main():
    parser = argparse.ArgumentParser(
        description="Generateur d'IPs CDN pour scan de Bug Hosts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Providers disponibles:
  cloudflare  - Cloudflare (AS13335)
  cloudfront  - AWS CloudFront (Edge mondial)
  google      - Google Cloud / GWS
  azure       - Microsoft Azure CDN
  fastly      - Fastly CDN
  akamai      - Akamai (le plus gros CDN)
  incapsula   - Incapsula / Imperva WAF
  sucuri      - Sucuri WAF

Exemples:
  python3 scripts/generate_cdn_ips.py --info
  python3 scripts/generate_cdn_ips.py --provider cloudflare
  python3 scripts/generate_cdn_ips.py --provider cloudflare --split 5000
  python3 scripts/generate_cdn_ips.py --provider cloudflare,fastly,cloudfront
  python3 scripts/generate_cdn_ips.py --cidr-only
  python3 scripts/generate_cdn_ips.py --all --split 10000

Workflow:
  1. python3 scripts/generate_cdn_ips.py --info
  2. python3 scripts/generate_cdn_ips.py --provider cloudflare --split 5000
  3. python3 scripts/batch_scan.py --data-dir data/generated --mode ping --ports 80,443
        """
    )
    parser.add_argument("--info", action="store_true",
                        help="Afficher les stats sans generer")
    parser.add_argument("--provider", default=None,
                        help="Provider(s) specifique(s), virgules (ex: cloudflare,fastly)")
    parser.add_argument("--all", action="store_true",
                        help="Tous les providers")
    parser.add_argument("--split", type=int, default=0,
                        help="Decouper en fichiers de N IPs (0 = un seul fichier)")
    parser.add_argument("--output", default=GENERATED_DIR,
                        help=f"Dossier de sortie (defaut: data/generated)")
    parser.add_argument("--cidr-only", action="store_true",
                        help="Sauvegarder seulement les fichiers CIDR (pas les IPs)")
    parser.add_argument("--cidr-dir", default=CIDR_DIR,
                        help=f"Dossier pour les fichiers CIDR (defaut: data/cidr)")

    args = parser.parse_args()

    if args.provider:
        keys = [k.strip().lower() for k in args.provider.split(",")]
        invalid = [k for k in keys if k not in PROVIDERS]
        if invalid:
            print(f"\033[31m  Providers inconnus: {', '.join(invalid)}\033[0m")
            print(f"\033[33m  Disponibles: {', '.join(PROVIDERS.keys())}\033[0m")
            sys.exit(1)
        providers_to_process = keys
    elif args.all:
        providers_to_process = list(PROVIDERS.keys())
    else:
        providers_to_process = ["cloudflare", "cloudfront", "fastly", "incapsula", "sucuri"]

    if args.info:
        show_info(providers_to_process)
        return

    os.makedirs(args.output, exist_ok=True)
    os.makedirs(args.cidr_dir, exist_ok=True)

    print(f"\n\033[36m{'='*70}\033[0m")
    print(f"\033[1;36m  GENERATION DES IPs CDN\033[0m")
    print(f"\033[36m{'='*70}\033[0m")
    print(f"  \033[36mProviders  : {', '.join(providers_to_process)}\033[0m")
    print(f"  \033[36mSortie IPs : {args.output}\033[0m")
    print(f"  \033[36mSortie CIDR: {args.cidr_dir}\033[0m")
    if args.split:
        print(f"  \033[36mDecoupage  : {args.split} IPs par fichier\033[0m")
    if args.cidr_only:
        print(f"  \033[33mMode CIDR seulement (pas de generation d'IPs)\033[0m")
    print()

    start = datetime.now()
    grand_total_ips = 0
    grand_total_files = 0

    for key in providers_to_process:
        config = PROVIDERS[key]
        print(f"\n  \033[1;33m>> {config['name']}\033[0m")
        print(f"  \033[37m   {config['description']}\033[0m")

        cidrs = fetch_cidrs_for_provider(key)
        if not cidrs:
            print(f"    \033[31m[X] Aucune plage obtenue pour {config['name']}\033[0m")
            continue

        total_ips = count_ips_in_cidrs(cidrs)
        print(f"    \033[32m{len(cidrs)} plages CIDR = {total_ips:,} IPs ({format_number(total_ips)})\033[0m")

        cidr_file = save_cidr_file(key, cidrs, args.cidr_dir)
        print(f"    \033[32mCIDR sauvegarde: {os.path.basename(cidr_file)}\033[0m")

        if args.cidr_only:
            grand_total_ips += total_ips
            continue

        print(f"    \033[36mGeneration des IPs individuelles...\033[0m")
        files = write_ips_to_files(
            generate_ips_from_cidrs(cidrs),
            total_ips,
            args.output,
            key,
            args.split
        )

        grand_total_ips += total_ips
        grand_total_files += len(files)

    elapsed = datetime.now() - start

    print(f"\n\033[36m{'='*70}\033[0m")
    print(f"\033[1;32m  TERMINE !\033[0m")
    print(f"  \033[36mProviders traites : {len(providers_to_process)}\033[0m")
    print(f"  \033[36mTotal IPs         : {grand_total_ips:,} ({format_number(grand_total_ips)})\033[0m")
    if not args.cidr_only:
        print(f"  \033[36mFichiers generes  : {grand_total_files}\033[0m")
    print(f"  \033[36mDuree             : {elapsed}\033[0m")
    print(f"\033[36m{'='*70}\033[0m\n")

    if not args.cidr_only:
        print(f"  \033[33mProchaine etape:\033[0m")
        print(f"  \033[37m  python3 scripts/batch_scan.py --data-dir {args.output} --mode ping --ports 80,443,8080 --threads 100\033[0m\n")


if __name__ == "__main__":
    main()
