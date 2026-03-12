# Free Surfing Scanner

Scan automatise de millions d'IPs CDN (Cloudflare, AWS, Google, Azure, Fastly,
Akamai, Incapsula, Sucuri) pour trouver des bug hosts.

## Installation

```bash
cd BugScanX && pip install -e . && cd ..
```

## Utilisation rapide

```bash
# 1. Voir combien d'IPs par CDN
python3 scripts/generate_cdn_ips.py --info

# 2. Generer les IPs (Cloudflare = 1.5M IPs)
python3 scripts/generate_cdn_ips.py --provider cloudflare --split 10000

# 3. Scanner
python3 scripts/batch_scan.py --data-dir data/generated --mode ping --ports 80,443,8080 --threads 100

# 4. Resultats
cat results/RESULTATS_*.txt
```

## Providers CDN

| Provider | IPs | Temps scan (100 threads) |
|----------|-----|--------------------------|
| Sucuri | 3.6K | 1 min |
| Incapsula | 228K | 1.3h |
| Azure | 190K | 1.1h |
| Fastly | 304K | 1.7h |
| Cloudflare | 1.5M | 8.5h |
| CloudFront | 4.2M | 23h |
| Akamai | 12.5M | 3 jours |
| Google | 38.5M | 9 jours |

## Documentation

- [Guide des commandes](docs/GUIDE_COMMANDES.md)
- [Documentation complete](docs/DOCUMENTATION.md)
