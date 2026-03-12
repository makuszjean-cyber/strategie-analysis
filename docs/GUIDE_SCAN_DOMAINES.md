# Guide Complet : Scanner 3 Millions de Domaines .cd

## Ton fichier : domains_20260307_205425.txt (~3M domaines)

C'est une liste de domaines du TLD .cd (RDC) generee par DomunxFinder.
C'est la BONNE approche : scanner des domaines, pas des IPs.

---

## Les 5 Modes de Scan expliques simplement

### 1. PING - "Est-ce que ce domaine est vivant ?"

```
Ton PC → ping le domaine → il repond ? OUI / NON
```

- **Ce que ca fait** : Teste si le domaine existe et si le serveur est allume
- **Ce que ca donne** : Une liste de domaines VIVANTS (les morts sont elimines)
- **Forfait necessaire ?** : OUI (ca se fait depuis ton PC avec internet)
- **Vitesse** : Le plus rapide de tous
- **Pourquoi le faire** : Eliminer 80-90% des domaines morts AVANT les autres scans

**Commande :**
```bash
python scripts/batch_scan.py --data-dir data/domains --mode ping --ports 80,443 --threads 200 --files domains_20260307_205425.txt
```

**Temps estime pour 3M domaines** : ~8-17h (200 threads, 2 ports)

**Astuce** : Decoupe le fichier d'abord pour pouvoir interrompre et reprendre :
```bash
# Decouper en fichiers de 50 000 domaines
split -l 50000 data/domains/domains_20260307_205425.txt data/domains/split_cd_
# Renommer en .txt
for f in data/domains/split_cd_*; do mv "$f" "$f.txt"; done

# Scanner tous les morceaux
python scripts/batch_scan.py --data-dir data/domains --mode ping --ports 80,443 --threads 200
```

---

### 2. DIRECT - "Quel code HTTP il retourne ?"

```
Ton PC → GET http://domaine.cd → reponse HTTP (200, 301, 302, 403...)
```

- **Ce que ca fait** : Envoie une vraie requete HTTP et regarde le code de reponse
- **Ce que ca donne** : Le code HTTP, le serveur (Apache, Cloudflare, nginx...), l'IP
- **Forfait necessaire ?** : OUI (depuis ton PC avec internet)
- **Vitesse** : Moyen (plus lent que ping, chaque requete attend une reponse HTTP)
- **Pourquoi le faire** : Savoir QUEL serveur est derriere et s'il repond normalement

**Codes importants :**
| Code | Signification | Pour le free surfing |
|------|--------------|---------------------|
| 200 | OK, le site marche | BON candidat bug host |
| 301 | Redirection permanente | A verifier |
| 302 | Redirection temporaire | Souvent page login operateur (mauvais) |
| 403 | Interdit | Le serveur te bloque |
| 400 | Bad Request | Le serveur ne comprend pas (inutile) |

**Commande** (a lancer sur les resultats du ping, PAS sur les 3M) :
```bash
python scripts/batch_scan.py --data-dir results --mode direct --ports 80,443 --threads 100 --methods GET,HEAD
```

**Ou mode DirectNon302** (exclut les redirections 302, recommande) :
```bash
python scripts/batch_scan.py --data-dir results --mode directnon302 --ports 80,443 --threads 100
```

---

### 3. SSL - "Est-ce qu'il accepte une connexion securisee ?"

```
Ton PC → connexion TLS (HTTPS) au domaine → handshake SSL reussi ? OUI / NON
```

- **Ce que ca fait** : Teste la connexion SSL/TLS et verifie le certificat
- **Ce que ca donne** : La version TLS et le certificat du domaine
- **Forfait necessaire ?** : OUI (depuis ton PC avec internet)
- **Vitesse** : Moyen
- **Pourquoi le faire** : Les domaines avec SSL valide sont souvent des vrais services
  (pas des domaines parkes). Plus fiable comme bug host potentiel.

**Commande :**
```bash
python scripts/batch_scan.py --data-dir results --mode ssl --threads 100
```

---

### 4. PROXY - "Est-ce qu'il peut servir de relais ?"

```
Ton PC → envoie un payload proxy au domaine → il relaie la connexion ? OUI / NON
```

- **Ce que ca fait** : Teste si le serveur accepte de relayer du trafic (proxy ouvert)
- **Ce que ca donne** : Code 101 = WebSocket accepte (JACKPOT), sinon echec
- **Forfait necessaire ?** : OUI (depuis ton PC avec internet)
- **Vitesse** : Lent (chaque test ouvre une connexion TCP complete)
- **Pourquoi le faire** : C'est le test ultime - si code 101, c'est un vrai proxy
  utilisable pour le tunnel. MAIS c'est tres rare (c'est ce que tu as fait
  pendant 2 jours sur Cloudflare → 0 resultats)

**Commande :**
```bash
python scripts/batch_scan.py --data-dir results --mode proxy --ports 80,8080 --threads 100
```

**ATTENTION** : Ne lance PAS le mode proxy sur 3M de domaines. Fais d'abord
ping → direct → puis proxy uniquement sur les domaines qui repondent 200.

---

### 5. TEST MANUEL DEPUIS TELEPHONE - "Est-ce qu'Orange le laisse passer ?"

```
Telephone Orange (SANS forfait) → ouvrir le domaine dans le navigateur → ca charge ?
```

- **Ce que ca fait** : Verifie si Orange RDC autorise le trafic vers ce domaine
  sans forfait data actif
- **Ce que ca donne** : LA reponse definitive - bug host ou pas
- **Forfait necessaire ?** : NON ! C'est le but - tu testes SANS forfait
- **Vitesse** : Manuel, domaine par domaine
- **Pourquoi le faire** : C'est le SEUL test qui compte. Les scans depuis ton PC
  trouvent des domaines vivants, mais seul ce test dit si Orange les autorise.

**Comment faire :**
1. Telephone sur reseau Orange, donnees mobiles activees, PAS de forfait
2. Ouvre le navigateur
3. Tape l'URL du domaine (ex: http://cdn.cd)
4. Si la page charge (meme partiellement) → BUG HOST CONFIRME
5. Note le domaine et configure DTunnel/HTTP Injector avec

---

## Le Workflow Complet pour tes 3M de domaines

### Etape 1 : Mettre le fichier au bon endroit (sur ton PC)

```bash
# Copie le fichier dans data/domains/
copy domains_20260307_205425.txt data\domains\
```

### Etape 2 : PING pour eliminer les domaines morts (~8-17h)

C'est l'etape la plus longue mais la plus importante. Sur 3M de domaines,
probablement 90% sont morts. Le ping va garder seulement les vivants.

```bash
python scripts/batch_scan.py --data-dir data/domains --mode ping --ports 80,443 --threads 200 --files domains_20260307_205425.txt
```

OU decoupe d'abord pour pouvoir interrompre :

```powershell
# Sur Windows PowerShell, decouper le fichier :
$i=0; Get-Content data\domains\domains_20260307_205425.txt -ReadCount 50000 | ForEach-Object { $i++; $_ | Set-Content "data\domains\chunk_$($i.ToString('D3')).txt" }

# Puis scanner tous les morceaux
python scripts/batch_scan.py --data-dir data/domains --mode ping --ports 80,443 --threads 200
```

**Resultat** : Un fichier dans `results/` avec les domaines vivants + IP + port

### Etape 3 : Extraire les domaines vivants

```powershell
# Extraire les noms de domaine du fichier resultat
# (prend la derniere colonne de chaque ligne qui a une IP)
python -c "
import re, sys
seen = set()
for line in open('results/RESULTATS_XXXXXXXX.txt'):  # remplace par ton fichier
    parts = line.strip().split()
    if len(parts) >= 3 and re.match(r'\d+', parts[0]):
        host = parts[-1]
        if host not in seen and host != 'Host':
            seen.add(host)
            print(host)
" > data/domains/alive_cd.txt
```

Ou plus simple, copie manuellement les noms de domaine du fichier resultat
dans un nouveau fichier `alive_cd.txt`.

### Etape 4 : Scan DIRECT sur les vivants (~minutes)

```bash
python scripts/batch_scan.py --data-dir data/domains --mode direct --ports 80,443,8080 --threads 100 --files alive_cd.txt
```

### Etape 5 : Scan SSL sur les vivants (~minutes)

```bash
python scripts/batch_scan.py --data-dir data/domains --mode ssl --threads 100 --files alive_cd.txt
```

### Etape 6 : Trier les meilleurs candidats

Regarde les resultats et cherche :
- **Code 200** + serveur **Cloudflare** = excellent candidat
- **Code 200** + serveur **Apache/nginx** = bon candidat
- **Code 200** + IP **africaine** (154.x, 41.x, 197.x) = tres bon candidat
- **SSL valide** = domaine serieux, plus de chances d'etre autorise

### Etape 7 : TEST DEPUIS TELEPHONE ORANGE (SANS forfait)

Prends les 10-20 meilleurs domaines et teste-les depuis ton telephone
Orange sans forfait. Le premier qui charge = ton bug host.

### Etape 8 : Configurer DTunnel

```
Payload :
GET / HTTP/1.1[crlf]
Host: DOMAINE_QUI_MARCHE[crlf]
Connection: Upgrade[crlf]
Upgrade: websocket[crlf][crlf]

SNI : DOMAINE_QUI_MARCHE
Serveur SSH : (cree sur fastssh.com ou sshmax.net)
```

---

## Resume visuel du processus

```
3 000 000 domaines .cd
        |
        | ETAPE 1 : PING (avec forfait, depuis PC)
        | Elimine les domaines morts
        v
  ~300 000 domaines vivants (estimation ~10%)
        |
        | ETAPE 2 : DIRECT (avec forfait, depuis PC)
        | Garde ceux qui repondent HTTP 200
        v
  ~30 000 domaines avec code 200 (estimation ~10%)
        |
        | ETAPE 3 : SSL (avec forfait, depuis PC)
        | Verifie les certificats SSL
        v
  ~10 000 domaines avec SSL valide
        |
        | ETAPE 4 : Tri manuel (les meilleurs candidats)
        v
  ~50-100 meilleurs candidats
        |
        | ETAPE 5 : TEST TELEPHONE (SANS forfait !)
        | Le seul test qui compte
        v
  1-5 BUG HOSTS CONFIRMES
        |
        | ETAPE 6 : Configurer DTunnel
        v
  FREE SURFING !
```

**Les etapes 1 a 4 se font depuis ton PC AVEC internet.**
**L'etape 5 se fait depuis ton telephone SANS forfait.**
**L'etape 6 se fait depuis ton telephone SANS forfait.**
