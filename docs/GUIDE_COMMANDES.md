# Guide des Commandes - BugScanX Free Surfing

## Structure du Projet

```
/workspace/
├── data/
│   ├── cidr/              ← Tes fichiers CIDR (plages IP par operateur)
│   │   ├── orange_rdc.txt
│   │   ├── airtel_rdc.txt
│   │   └── vodacom_rdc.txt
│   ├── domains/           ← Tes listes de domaines
│   │   └── orange_rdc.txt
│   └── generated/         ← IPs generees automatiquement (par generate_ips.py)
│       └── (fichiers generes ici)
├── results/               ← Resultats des scans
├── scripts/
│   ├── generate_ips.py    ← Genere les IPs depuis les fichiers CIDR
│   └── batch_scan.py      ← Lance le scan sur tous les fichiers
├── BugScanX/              ← Le moteur de scan (ne pas modifier)
├── docs/
│   ├── GUIDE_COMMANDES.md ← Ce fichier
│   └── DOCUMENTATION.md   ← Documentation complete
└── DOCUMENTATION_FREESURFING.md
```

---

## Etape 1 : Voir les Statistiques (combien d'IPs a scanner)

```bash
python3 scripts/generate_ips.py --info
```

Cette commande affiche :
- Le nombre de plages CIDR par operateur
- Le nombre total d'IPs a scanner
- Le temps estime pour le scan

---

## Etape 2 : Generer les IPs

### Generer TOUTES les IPs (un seul gros fichier)

```bash
python3 scripts/generate_ips.py
```

### Generer en decoupant en petits fichiers (RECOMMANDE)

```bash
# Fichiers de 500 IPs chacun (plus facile a gerer)
python3 scripts/generate_ips.py --split 500

# Fichiers de 1000 IPs
python3 scripts/generate_ips.py --split 1000

# Fichiers de 250 IPs (plus petit = plus facile si tu veux interrompre)
python3 scripts/generate_ips.py --split 250
```

### Generer depuis un operateur specifique

```bash
python3 scripts/generate_ips.py --file orange_rdc.txt
python3 scripts/generate_ips.py --file orange_rdc.txt --split 500
```

---

## Etape 3 : Scanner

### A) Scan Rapide - Mode PING (RECOMMANDE EN PREMIER)

Le mode ping est le plus rapide. Il teste juste si l'IP repond sur un port.
Commence toujours par la pour eliminer les IPs mortes.

```bash
# Scanner toutes les IPs generees
python3 scripts/batch_scan.py --data-dir data/generated --mode ping --ports 80,443

# Avec plus de threads (plus rapide mais plus agressif)
python3 scripts/batch_scan.py --data-dir data/generated --mode ping --ports 80,443 --threads 100

# Scanner les CIDR directement (sans generer les IPs d'abord)
python3 scripts/batch_scan.py --data-dir data/cidr --mode ping --ports 80,443,8080
```

### B) Scan HTTP Direct (APRES le ping)

Teste les IPs qui repondent avec des requetes HTTP. Exclut les 302 par defaut.

```bash
# Scanner les IPs generees
python3 scripts/batch_scan.py --data-dir data/generated --mode direct --ports 80,443,8080,8443

# Scanner les domaines
python3 scripts/batch_scan.py --data-dir data/domains --mode direct --ports 80,443,8080

# Mode DirectNon302 explicite
python3 scripts/batch_scan.py --data-dir data/generated --mode directnon302 --ports 80,443

# Avec toutes les methodes HTTP
python3 scripts/batch_scan.py --data-dir data/generated --mode direct --methods GET,HEAD,POST,OPTIONS
```

### C) Scan SSL/SNI

Teste si les hosts acceptent une connexion TLS (utile pour les bug hosts SNI).

```bash
# Scanner les domaines en SSL
python3 scripts/batch_scan.py --data-dir data/domains --mode ssl --threads 50

# Scanner les IPs en SSL
python3 scripts/batch_scan.py --data-dir data/generated --mode ssl --threads 100
```

### D) Scan Proxy

Teste si les hosts fonctionnent comme proxy (le plus important pour le free surfing).

```bash
# Scan proxy avec payload par defaut
python3 scripts/batch_scan.py --data-dir data/generated --mode proxy --ports 80,8080,3128

# Avec un payload personnalise
python3 scripts/batch_scan.py --data-dir data/generated --mode proxy --ports 80,8080 \
    --proxy-payload "CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf][crlf]"
```

---

## Options Completes

| Option | Description | Defaut |
|--------|-------------|--------|
| `--data-dir` | Dossier des fichiers a scanner | `data/generated` |
| `--output-dir` | Dossier des resultats | `results` |
| `--mode` | Mode de scan: direct, directnon302, ssl, ping, proxy | `direct` |
| `--ports` | Ports a tester (virgules) | `80,443,8080,8443` |
| `--methods` | Methodes HTTP (virgules) | `GET,HEAD` |
| `--threads` | Threads paralleles | `50` |
| `--timeout` | Timeout par requete (secondes) | `3` |
| `--no302` | Exclure les redirections 302 | `oui` |
| `--include-302` | Inclure les 302 | `non` |
| `--files` | Fichiers specifiques (virgules) | tous |
| `--proxy-target` | Cible pour mode proxy | `in1.wstunnel.site` |
| `--proxy-payload` | Payload proxy personnalise | websocket |

---

## Workflow Recommande (du debut a la fin)

```bash
# 1. Voir combien d'IPs tu vas scanner
python3 scripts/generate_ips.py --info

# 2. Generer les IPs en petits fichiers
python3 scripts/generate_ips.py --split 500

# 3. Scan ping rapide (eliminer les IPs mortes) - ~5min pour 5000 IPs
python3 scripts/batch_scan.py --data-dir data/generated --mode ping --ports 80,443,8080 --threads 100

# 4. Regarder les resultats du ping
cat results/RESULTATS_*.txt

# 5. Scan HTTP sur les domaines
python3 scripts/batch_scan.py --data-dir data/domains --mode directnon302 --ports 80,443,8080,8443

# 6. Scan SSL sur les domaines
python3 scripts/batch_scan.py --data-dir data/domains --mode ssl

# 7. Scan proxy (le plus important)
python3 scripts/batch_scan.py --data-dir data/generated --mode proxy --ports 80,8080,3128,8888

# 8. Analyser les resultats finaux
ls -la results/
cat results/RESULTATS_*.txt
```

---

## Combien de Temps ca Prend ?

Le temps depend de :
- **Nombre d'IPs** x **Nombre de ports** x **Nombre de methodes** = combinaisons
- **Timeout** (secondes par requete)
- **Threads** (requetes en parallele)

**Formule :** `temps ≈ combinaisons × timeout / threads`

### Exemples pour Orange RDC (~5500 IPs)

| Mode | Ports | Threads | Temps estime |
|------|-------|---------|-------------|
| ping | 80,443 | 100 | ~3 min |
| ping | 80,443,8080,8443 | 100 | ~7 min |
| direct | 80,443 | 50 | ~13 min |
| direct | 80,443,8080,8443 | 100 | ~13 min |
| proxy | 80,8080 | 50 | ~7 min |

Tu peux interrompre a tout moment avec **Ctrl+C**. Les resultats deja trouves
seront sauvegardes.

---

## Conseils

1. **Commence toujours par le ping** : ca elimine 80-90% des IPs mortes
2. **Utilise `--split 500`** quand tu generes les IPs : si le scan plante, tu ne perds pas tout
3. **Augmente les threads** (`--threads 100` ou `200`) pour aller plus vite
4. **Les ports importants** : 80, 443, 8080, 8443, 3128
5. **Cherche les codes 200 et 101** dans les resultats : ce sont les meilleurs candidats
6. **Les resultats sont dans** `results/` : chaque scan cree un fichier + un fichier combine
7. **Relance regulierement** : les bug hosts changent souvent
