# Free Surfing Scanner - Orange RDC

Outil de scan automatise pour trouver des bug hosts en utilisant BugScanX.

## Installation rapide

```bash
cd BugScanX && pip install -e . && cd ..
```

## Utilisation en 3 etapes

```bash
# 1. Voir combien d'IPs a scanner
python3 scripts/generate_ips.py --info

# 2. Generer les IPs
python3 scripts/generate_ips.py --split 500

# 3. Scanner
python3 scripts/batch_scan.py --data-dir data/generated --mode ping --ports 80,443,8080
```

## Structure

| Dossier | Contenu |
|---------|---------|
| `data/cidr/` | Plages CIDR par operateur (Orange, Airtel, Vodacom) |
| `data/domains/` | Listes de domaines a scanner |
| `data/generated/` | IPs generees depuis les CIDR |
| `results/` | Resultats des scans |
| `scripts/` | Scripts: generate_ips.py + batch_scan.py |
| `docs/` | Documentation complete + guide des commandes |
| `BugScanX/` | Moteur de scan |

## Documentation

- [Guide des commandes](docs/GUIDE_COMMANDES.md) - Toutes les commandes disponibles
- [Documentation complete](docs/DOCUMENTATION.md) - Tout comprendre de A a Z
