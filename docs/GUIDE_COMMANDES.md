# Guide des Commandes

## Structure du Projet

```
/workspace/
├── data/
│   ├── cidr/              ← Fichiers CIDR (telecharges ou manuels)
│   │   ├── orange_rdc.txt           # Plages IP Orange RDC (AS37447)
│   │   ├── cloudflare_cidr.txt      # Genere automatiquement
│   │   ├── cloudfront_cidr.txt      # Genere automatiquement
│   │   └── ...
│   ├── domains/           ← Listes de domaines
│   │   └── orange_rdc.txt
│   └── generated/         ← IPs individuelles generees
│       ├── cloudflare_part0001.txt
│       ├── cloudflare_part0002.txt
│       └── ...
├── results/               ← Resultats des scans
├── scripts/
│   ├── generate_cdn_ips.py    ← Genere les IPs des CDN (Cloudflare, AWS, etc.)
│   ├── generate_ips.py        ← Genere les IPs depuis CIDR locaux
│   └── batch_scan.py          ← Scanne tous les fichiers d'un dossier
├── BugScanX/              ← Moteur de scan
└── docs/                  ← Documentation
```

---

## 1. GENERER LES IPs DES CDN

### Voir les stats (combien d'IPs par CDN)

```bash
# Tous les CDN par defaut
python3 scripts/generate_cdn_ips.py --info

# TOUS les CDN (inclut Google + Akamai = des millions)
python3 scripts/generate_cdn_ips.py --info --all

# Un CDN specifique
python3 scripts/generate_cdn_ips.py --info --provider cloudflare
```

### Generer les IPs

```bash
# Cloudflare seulement (1.5M IPs, ~8h de scan) - COMMENCE PAR CELUI-LA
python3 scripts/generate_cdn_ips.py --provider cloudflare --split 10000

# Cloudflare + Fastly + Incapsula + Sucuri (les plus petits, ~12h total)
python3 scripts/generate_cdn_ips.py --provider cloudflare,fastly,incapsula,sucuri --split 10000

# AWS CloudFront (4.2M IPs, ~1 jour)
python3 scripts/generate_cdn_ips.py --provider cloudfront --split 10000

# Azure CDN seulement (190K IPs, ~1h)
python3 scripts/generate_cdn_ips.py --provider azure --split 10000

# Google Cloud (38.5M IPs, ~9 jours) - ENORME
python3 scripts/generate_cdn_ips.py --provider google --split 10000

# Akamai (12.5M IPs, ~3 jours)
python3 scripts/generate_cdn_ips.py --provider akamai --split 10000

# TOUT (57M+ IPs, ~2 semaines de scan)
python3 scripts/generate_cdn_ips.py --all --split 10000

# Sauvegarder juste les fichiers CIDR (sans generer les IPs)
python3 scripts/generate_cdn_ips.py --all --cidr-only
```

### Providers disponibles

| Provider | IPs | Temps (100 threads) | Priorite |
|----------|-----|---------------------|----------|
| `sucuri` | 3.6K | 1 min | Commence ici (test) |
| `incapsula` | 228K | 1.3h | Haut |
| `azure` | 190K | 1.1h | Haut |
| `fastly` | 304K | 1.7h | Haut |
| `cloudflare` | 1.5M | 8.5h | Tres haut (le meilleur pour bug hosts) |
| `cloudfront` | 4.2M | 23h | Moyen |
| `akamai` | 12.5M | 3 jours | Long |
| `google` | 38.5M | 9 jours | Tres long |

---

## 2. GENERER LES IPs ORANGE RDC (plages locales)

```bash
# Voir les stats Orange RDC
python3 scripts/generate_ips.py --info

# Generer les IPs Orange RDC
python3 scripts/generate_ips.py --split 500
```

---

## 3. SCANNER

### Scan Ping (le plus rapide - COMMENCE TOUJOURS PAR LA)

```bash
# Scanner les IPs generees
python3 scripts/batch_scan.py --data-dir data/generated --mode ping --ports 80,443 --threads 100

# Avec plus de ports
python3 scripts/batch_scan.py --data-dir data/generated --mode ping --ports 80,443,8080,8443 --threads 100

# Scanner directement les fichiers CIDR (sans generer les IPs d'abord)
python3 scripts/batch_scan.py --data-dir data/cidr --mode ping --ports 80,443
```

### Scan HTTP Direct

```bash
# Mode Direct (exclut les 302 par defaut)
python3 scripts/batch_scan.py --data-dir data/generated --mode direct --ports 80,443,8080

# DirectNon302 explicite
python3 scripts/batch_scan.py --data-dir data/generated --mode directnon302 --ports 80,443,8080

# Avec plus de methodes HTTP
python3 scripts/batch_scan.py --data-dir data/generated --mode direct --methods GET,HEAD,OPTIONS
```

### Scan SSL/SNI

```bash
python3 scripts/batch_scan.py --data-dir data/generated --mode ssl --threads 100
python3 scripts/batch_scan.py --data-dir data/domains --mode ssl
```

### Scan Proxy (le plus important pour le free surfing)

```bash
# Scan proxy standard
python3 scripts/batch_scan.py --data-dir data/generated --mode proxy --ports 80,8080,3128

# Avec payload CONNECT
python3 scripts/batch_scan.py --data-dir data/generated --mode proxy --ports 80,8080 \
    --proxy-payload "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf][crlf]"
```

---

## 4. OPTIONS DU SCANNER

| Option | Description | Defaut |
|--------|-------------|--------|
| `--data-dir` | Dossier des fichiers a scanner | `data/generated` |
| `--output-dir` | Dossier des resultats | `results` |
| `--mode` | ping, direct, directnon302, ssl, proxy | `direct` |
| `--ports` | Ports (virgules) | `80,443,8080,8443` |
| `--methods` | Methodes HTTP | `GET,HEAD` |
| `--threads` | Threads paralleles | `50` |
| `--timeout` | Timeout (secondes) | `3` |
| `--files` | Fichiers specifiques | tous |

---

## 5. WORKFLOW COMPLET RECOMMANDE

```bash
# ETAPE 0 : Installer les dependances
cd BugScanX && pip install -e . && cd ..

# ETAPE 1 : Voir les stats
python3 scripts/generate_cdn_ips.py --info

# ETAPE 2 : Commencer petit - generer Sucuri (3600 IPs, test rapide)
python3 scripts/generate_cdn_ips.py --provider sucuri --split 5000

# ETAPE 3 : Scanner Sucuri (1 minute)
python3 scripts/batch_scan.py --data-dir data/generated --mode ping --ports 80,443 --threads 100

# ETAPE 4 : Verifier les resultats
cat results/RESULTATS_*.txt

# ETAPE 5 : Si ca marche, generer Cloudflare (1.5M IPs)
python3 scripts/generate_cdn_ips.py --provider cloudflare --split 10000

# ETAPE 6 : Scanner Cloudflare (8h)
python3 scripts/batch_scan.py --data-dir data/generated --mode ping --ports 80,443,8080 --threads 100

# ETAPE 7 : Scanner en mode Direct les resultats positifs
python3 scripts/batch_scan.py --data-dir data/generated --mode direct --ports 80,443,8080

# ETAPE 8 : Continuer avec les autres CDN...
python3 scripts/generate_cdn_ips.py --provider fastly,incapsula,azure --split 10000
python3 scripts/batch_scan.py --data-dir data/generated --mode ping --ports 80,443,8080 --threads 100
```

---

## 6. ANALYSER LES RESULTATS

```bash
# Lister les fichiers de resultats
ls -la results/

# Voir le resultat combine
cat results/RESULTATS_*.txt

# Compter les hosts trouves
wc -l results/*.txt

# Chercher les codes 200 (les meilleurs)
grep " 200 " results/*.txt

# Chercher les codes 101 (WebSocket, excellent)
grep " 101 " results/*.txt
```

---

## 7. COMBIEN DE TEMPS CA PREND ?

**Formule :** `temps = (nombre_IPs x nombre_ports x timeout) / nombre_threads`

| Scenario | IPs | Ports | Threads | Temps |
|----------|-----|-------|---------|-------|
| Test rapide Sucuri | 3.6K | 2 | 100 | ~1 min |
| Incapsula complet | 228K | 3 | 100 | ~2h |
| Cloudflare complet | 1.5M | 3 | 100 | ~13h |
| CloudFront complet | 4.2M | 3 | 100 | ~1.5 jours |
| Google complet | 38.5M | 3 | 100 | ~13 jours |
| TOUT | 57M | 3 | 100 | ~20 jours |

Tu peux interrompre avec **Ctrl+C** a tout moment. Les resultats deja trouves
sont sauvegardes.
