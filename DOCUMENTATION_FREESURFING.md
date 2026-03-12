# Guide Complet du Free Surfing - De Zero a Expert

## Table des matieres

1. [Introduction - C'est quoi le Free Surfing ?](#1-introduction)
2. [Les bases du reseau qu'il faut connaitre](#2-les-bases-du-reseau)
3. [Comprendre les Bug Hosts et SNI](#3-comprendre-les-bug-hosts-et-sni)
4. [Comment fonctionne le scan de hosts](#4-comment-fonctionne-le-scan)
5. [Les ports et leur importance](#5-les-ports)
6. [Les plages CIDR - Scanner des reseaux entiers](#6-les-plages-cidr)
7. [Utiliser BugScanX - Guide pratique](#7-utiliser-bugscanx)
8. [Le mode Batch - Scanner tous les fichiers du dossier data](#8-mode-batch)
9. [Methode pour Orange RDC](#9-methode-orange-rdc)
10. [Glossaire](#10-glossaire)

---

## 1. Introduction

### C'est quoi le "Free Surfing" ?

Le **Free Surfing** (navigation gratuite) est une technique qui consiste a utiliser
internet sans consommer de forfait data en exploitant des failles dans la configuration
reseau d'un operateur telecom.

### Comment ca marche en resume ?

Quand tu te connectes a internet via un operateur (Orange, Airtel, etc.), ton trafic
passe par des serveurs intermediaires appeles **proxys** ou **passerelles**. Certains
de ces serveurs laissent passer du trafic vers certaines adresses (les "bug hosts")
sans verifier si tu as un forfait actif.

Le principe est simple :
1. Tu trouves un **bug host** (une adresse qui passe sans forfait)
2. Tu utilises un **tunnel VPN** (HTTP Injector, HA Tunnel, etc.) qui fait croire
   a l'operateur que tu accedes a ce bug host
3. En realite, le tunnel redirige ton trafic vers internet de maniere transparente

### Schema simplifie

```
TON TELEPHONE
    |
    | (connexion sans forfait)
    v
SERVEUR DE L'OPERATEUR (proxy/passerelle)
    |
    | "Je veux acceder a bughost.example.com" (autorise !)
    |
    v
TUNNEL VPN (HTTP Injector / HA Tunnel)
    |
    | (redirige vers internet reel)
    v
INTERNET LIBRE
```

---

## 2. Les bases du reseau

### Qu'est-ce qu'une adresse IP ?

Une **adresse IP** (Internet Protocol) est comme une adresse postale pour les
ordinateurs sur internet. Chaque appareil connecte a internet a une adresse IP unique.

**Exemple :** `192.168.1.1` ou `41.243.0.1`

Une adresse IPv4 est composee de 4 nombres separes par des points, chaque nombre
allant de 0 a 255.

### Qu'est-ce qu'un nom de domaine (hostname) ?

Un **nom de domaine** est un nom lisible par les humains qui correspond a une adresse IP.

- `google.com` → correspond a `142.250.80.46`
- `orange.cd` → correspond a une adresse IP de Orange RDC

Le systeme qui traduit les noms de domaine en adresses IP s'appelle le **DNS**
(Domain Name System).

### Qu'est-ce qu'un port ?

Un **port** est comme une porte d'entree sur un serveur. Chaque serveur a 65535 ports
disponibles. Certains ports sont reserves pour des services specifiques :

| Port | Service | Description |
|------|---------|-------------|
| 80   | HTTP    | Web non securise (le plus utilise pour le free surfing) |
| 443  | HTTPS   | Web securise (SSL/TLS) |
| 8080 | HTTP Alt| Port HTTP alternatif (souvent utilise par les proxys) |
| 8443 | HTTPS Alt| Port HTTPS alternatif |
| 3128 | Proxy   | Port proxy Squid classique |
| 8888 | Proxy   | Autre port proxy courant |

**Pourquoi c'est important ?** Un bug host peut fonctionner sur le port 80 mais pas
sur le port 443, ou vice versa. C'est pour cela qu'on teste plusieurs ports.

### Qu'est-ce qu'un protocole HTTP/HTTPS ?

- **HTTP** (port 80) : Communication non chiffree entre ton appareil et le serveur
- **HTTPS** (port 443) : Communication chiffree (securisee)

Pour le free surfing, on utilise principalement HTTP car les proxys de l'operateur
peuvent lire et rediriger les requetes HTTP.

### Les methodes HTTP

Quand ton navigateur communique avec un serveur, il utilise des **methodes** :

| Methode | Description | Usage en scan |
|---------|-------------|---------------|
| GET     | Demander une page | La plus courante |
| HEAD    | Comme GET mais sans le contenu | Rapide pour tester |
| POST    | Envoyer des donnees | Parfois autorise |
| PUT     | Modifier des donnees | Rarement utilise |
| OPTIONS | Demander les methodes supportees | Utile pour tester |

---

## 3. Comprendre les Bug Hosts et SNI

### Qu'est-ce qu'un Bug Host ?

Un **Bug Host** est un nom de domaine ou une adresse IP que l'operateur autorise
a acceder meme sans forfait data actif. Ce sont generalement :

- Des domaines de l'operateur lui-meme (portail captif, services internes)
- Des partenaires de l'operateur (sites promotionnels)
- Des CDN (Content Delivery Networks) mal configures
- Des domaines lies a des services "zero-rating"

**Exemples typiques :**
- `www.orange.cd` (site de l'operateur)
- `0.gone.cd` (portail de recharge)
- Des sous-domaines de l'operateur

### Qu'est-ce que le SNI ?

Le **SNI** (Server Name Indication) est une extension du protocole TLS/SSL. Quand
ton appareil se connecte en HTTPS a un serveur, il envoie le nom du domaine dans
le SNI pour que le serveur sache quel certificat SSL utiliser.

**Pourquoi c'est crucial pour le free surfing ?**

L'operateur regarde le SNI pour decider s'il autorise ou bloque la connexion.
Si le SNI contient un bug host autorise, la connexion passe meme sans forfait.

```
TON TELEPHONE → "SNI: bughost.orange.cd" → OPERATEUR : "OK, c'est autorise !"
                                               ↓
                                         (mais en realite, le tunnel
                                          redirige vers internet)
```

### Types de Bug Hosts

1. **Bug Host Direct** : Fonctionne en envoyant une requete HTTP directe
2. **Bug Host SNI/SSL** : Fonctionne via le champ SNI dans une connexion TLS
3. **Bug Host Proxy** : Fonctionne en passant par le proxy de l'operateur
4. **Bug Host WebSocket** : Fonctionne via une connexion WebSocket

---

## 4. Comment fonctionne le scan

### Le principe du scan

Scanner des bug hosts, c'est tester systematiquement des domaines ou des adresses
IP pour trouver ceux qui repondent positivement (qui sont "ouverts" ou "autorises").

### Les differents modes de scan dans BugScanX

#### a) Scan Direct

C'est le scan le plus simple. On envoie une requete HTTP a un host sur un port
donne et on regarde la reponse :

```
Ton outil → HTTP GET http://host.example.com:80 → Reponse ?
  - Si reponse avec code 200, 301, etc. → HOST POTENTIELLEMENT VALIDE
  - Si pas de reponse ou erreur → HOST INVALIDE
  - Si reponse 302 (redirection) → Souvent invalide (redirection vers page login)
```

**Code de reponse HTTP important :**
| Code | Signification | Pour le free surfing |
|------|---------------|---------------------|
| 200  | OK | Bon signe - le host repond |
| 101  | Switching Protocols | Excellent pour WebSocket |
| 301  | Redirection permanente | A verifier |
| 302  | Redirection temporaire | Souvent mauvais signe (page de login operateur) |
| 403  | Interdit | Le serveur refuse |
| 404  | Non trouve | Le domaine existe mais pas la page |

#### b) Scan DirectNon302

Comme le scan Direct mais en excluant automatiquement les reponses 302.
Les reponses 302 sont souvent des redirections vers la page de login de l'operateur,
donc elles ne sont pas des vrais bug hosts.

#### c) Scan SSL/SNI

Teste si un host accepte une connexion TLS/SSL :
```
Ton outil → Connexion TLS avec SNI="host.example.com" → Handshake SSL ?
  - Si handshake reussi → HOST SNI VALIDE
  - Si echec → HOST INVALIDE
```

#### d) Scan Proxy (ProxyTest)

Teste si un host fonctionne comme proxy en envoyant un payload personnalise :
```
Ton outil → Connexion TCP au host:port → Envoi du payload → Reponse ?
  - Si code 101 (Switching Protocols) → PROXY FONCTIONNEL !
  - Si autre reponse → A analyser
```

#### e) Scan Ping

Le scan le plus basique - verifie simplement si un host est joignable sur un port :
```
Ton outil → Connexion TCP au host:port → Connexion etablie ?
  - Si oui → HOST ACCESSIBLE
  - Si non → HOST INACCESSIBLE
```

### Le processus complet de scan

```
1. PREPARER LES CIBLES
   ├── Liste de domaines (fichier .txt, un par ligne)
   └── Ou plage CIDR (ex: 41.243.0.0/16)

2. CHOISIR LES PARAMETRES
   ├── Mode de scan (Direct, SSL, Proxy, Ping)
   ├── Ports a tester (80, 443, 8080, 8443...)
   ├── Methodes HTTP (GET, HEAD...)
   └── Nombre de threads (vitesse)

3. LANCER LE SCAN
   └── L'outil teste chaque combinaison host + port + methode

4. ANALYSER LES RESULTATS
   ├── Hosts qui repondent = CANDIDATS
   └── Tester manuellement dans HTTP Injector / HA Tunnel
```

---

## 5. Les ports

### Pourquoi scanner plusieurs ports ?

Un meme host peut etre accessible sur certains ports et pas d'autres.
L'operateur peut bloquer le port 80 mais laisser passer le port 8080.

### Les ports les plus importants pour le free surfing

```
PORTS PRIORITAIRES (a toujours tester) :
  80    → HTTP standard
  443   → HTTPS standard
  8080  → HTTP alternatif (tres souvent utilise par les proxys)
  8443  → HTTPS alternatif

PORTS SECONDAIRES (a tester aussi) :
  3128  → Proxy Squid
  8888  → Proxy alternatif
  8081  → Autre HTTP alternatif
  9090  → Proxy/Admin

PORTS SUPPLEMENTAIRES :
  81, 82, 83, 88, 808, 880, 8008, 8880, 8088
```

### Comment BugScanX gere les ports

Quand tu donnes une liste de ports (ex: `80,443,8080`), BugScanX va tester
**chaque host sur chaque port**. Donc si tu as 100 hosts et 3 ports,
il fera 300 tests (100 x 3).

---

## 6. Les plages CIDR

### Qu'est-ce qu'une plage CIDR ?

**CIDR** (Classless Inter-Domain Routing) est une notation pour representer
un groupe d'adresses IP.

**Format :** `adresse_IP/prefixe`

Le prefixe indique combien de bits de l'adresse sont fixes (le "reseau"),
le reste varie (les "hotes").

### Exemples concrets

| Notation CIDR | Plage d'IP | Nombre d'hotes |
|---------------|-----------|----------------|
| `41.243.0.0/24` | 41.243.0.1 a 41.243.0.254 | 254 |
| `41.243.0.0/16` | 41.243.0.1 a 41.243.255.254 | 65 534 |
| `41.243.0.0/20` | 41.243.0.1 a 41.243.15.254 | 4 094 |
| `197.243.0.0/16` | 197.243.0.1 a 197.243.255.254 | 65 534 |

### Comment trouver les plages CIDR d'un operateur ?

1. **Chercher l'ASN (Autonomous System Number) de l'operateur**
   - Va sur https://bgp.he.net/
   - Cherche "Orange RDC" ou "Africell RDC"
   - Tu trouveras les plages IP allouees

2. **Utiliser des outils en ligne**
   - https://ipinfo.io/
   - https://www.ripe.net/ (pour l'Afrique : https://www.afrinic.net/)
   - https://bgpview.io/

3. **Depuis un telephone connecte**
   - Note ton adresse IP quand tu es connecte (va sur whatismyip.com)
   - Cherche le CIDR correspondant

### Pourquoi scanner des plages CIDR ?

Au lieu de deviner des noms de domaine, tu scannes directement les adresses IP
de l'operateur. C'est plus exhaustif car tu testes TOUTES les IPs possibles
dans la plage.

---

## 7. Utiliser BugScanX

### Installation

```bash
# Installer depuis PyPI
pip install bugscan-x

# Ou cloner depuis GitHub
git clone https://github.com/FreeNetLabs/BugScanX.git
cd BugScanX
pip install -e .
```

### Lancer BugScanX

```bash
bugscanx
# ou
bx
```

### Menu principal

```
[1] HOST SCANNER    → Scanner des bug hosts
[2] SUBFINDER       → Trouver des sous-domaines
[3] IP LOOKUP       → Recherche IP inversee
[4] FILE TOOLKIT    → Outils de gestion de fichiers
[5] PORT SCANNER    → Scanner les ports ouverts
[6] DNS RECORD      → Enregistrements DNS
[7] HOST INFO       → Infos sur un host
[8] HELP            → Aide
[9] UPDATE          → Mise a jour
[0] EXIT            → Quitter
```

### Etapes pour scanner avec BugScanX (version originale)

#### Etape 1 : Preparer un fichier de hosts

Cree un fichier texte (ex: `hosts.txt`) avec un domaine par ligne :

```
www.orange.cd
mail.orange.cd
portal.orange.cd
0.gone.cd
```

#### Etape 2 : Lancer le Host Scanner (option 1)

1. Choisis un mode de scan :
   - **Direct** : Pour tester les requetes HTTP directes
   - **DirectNon302** : Comme Direct mais ignore les redirections 302
   - **ProxyTest** : Pour tester si les hosts fonctionnent comme proxy
   - **SSL** : Pour tester les connexions SSL/SNI
   - **Ping** : Pour verifier l'accessibilite

2. Donne le fichier d'entree : `hosts.txt`
3. Donne le(s) port(s) : `80` ou `80,443,8080`
4. Donne le timeout : `3` (secondes)
5. Donne le fichier de sortie : `results.txt`
6. Donne le nombre de threads : `50`
7. Choisis les methodes HTTP : `GET, HEAD`

#### Etape 3 : Analyser les resultats

Le fichier `results.txt` contiendra les hosts qui ont repondu positivement.

### Probleme de la version originale

**La version originale ne prend qu'un seul fichier a la fois.** Si tu as
plusieurs fichiers dans un dossier `data/`, tu dois les scanner un par un.
C'est la que notre modification intervient !

---

## 8. Mode Batch - Scanner tous les fichiers du dossier data

### Le probleme

Tu as un dossier `data/` avec plusieurs fichiers :

```
data/
  ├── orange_hosts.txt
  ├── airtel_hosts.txt
  ├── vodacom_hosts.txt
  ├── cidr_ranges.txt
  └── subdomains.txt
```

La version originale de BugScanX te demande de specifier UN SEUL fichier.
Tu devrais donc lancer le scan 5 fois separement.

### La solution : batch_scan.py

Nous avons cree un script `batch_scan.py` qui :

1. Detecte automatiquement tous les fichiers `.txt` dans le dossier `data/`
2. Les scanne tous en sequence ou en parallele
3. Teste plusieurs ports par defaut (80, 443, 8080, 8443)
4. Genere un rapport combine dans `results/`

### Utilisation

```bash
# Scanner tout le dossier data/ avec les parametres par defaut
python batch_scan.py

# Specifier un dossier different
python batch_scan.py --data-dir /chemin/vers/tes/fichiers

# Choisir les ports
python batch_scan.py --ports 80,443,8080

# Choisir le mode de scan
python batch_scan.py --mode direct

# Choisir le nombre de threads
python batch_scan.py --threads 100

# Toutes les options ensemble
python batch_scan.py --data-dir data --ports 80,443,8080,8443 --mode direct --threads 50 --timeout 3
```

### Options disponibles

| Option | Description | Defaut |
|--------|-------------|--------|
| `--data-dir` | Dossier contenant les fichiers a scanner | `data` |
| `--output-dir` | Dossier pour les resultats | `results` |
| `--ports` | Ports a tester (separes par des virgules) | `80,443,8080,8443` |
| `--mode` | Mode de scan | `direct` |
| `--methods` | Methodes HTTP | `GET,HEAD` |
| `--threads` | Nombre de threads | `50` |
| `--timeout` | Timeout en secondes | `3` |
| `--no302` | Exclure les reponses 302 | active par defaut |

---

## 9. Methode pour Orange RDC

### Etape 1 : Trouver les informations reseau d'Orange RDC

**ASN Orange RDC :** AS37396 (Orange Democratic Republic of the Congo)

**Plages IP connues d'Orange RDC :**
- `41.243.0.0/16`
- `197.243.0.0/16`
- `196.12.128.0/19`
- `102.215.0.0/18`

> **Note :** Ces plages peuvent changer. Verifie toujours sur
> https://bgp.he.net/AS37396 ou https://bgpview.io/asn/37396

### Etape 2 : Trouver des domaines lies a Orange RDC

Utilise le **Subfinder** (option 2 dans BugScanX) pour trouver des sous-domaines :

```
Domaines a enumerer :
- orange.cd
- orangemoney.cd
- gone.cd
```

Tu peux aussi chercher manuellement :
- `www.orange.cd`
- `my.orange.cd`
- `shop.orange.cd`
- `api.orange.cd`
- `mail.orange.cd`
- `portal.orange.cd`
- `0.gone.cd`
- `free.orange.cd`

### Etape 3 : Preparer tes fichiers

Cree un dossier `data/` et mets-y tes fichiers :

**data/orange_domains.txt :**
```
www.orange.cd
my.orange.cd
shop.orange.cd
api.orange.cd
mail.orange.cd
portal.orange.cd
0.gone.cd
free.orange.cd
```

**data/orange_cidr.txt :**
```
41.243.0.0/24
41.243.1.0/24
197.243.0.0/24
```

> **Attention :** Ne scanne pas des /16 entiers (65000+ IPs) car ca prend
> enormement de temps. Commence par des /24 (254 IPs).

### Etape 4 : Lancer le scan

```bash
# Scanner les domaines
python batch_scan.py --data-dir data --ports 80,443,8080,8443 --mode direct --threads 50

# Scanner avec exclusion des 302
python batch_scan.py --data-dir data --ports 80,443,8080 --mode directnon302 --threads 50

# Scanner les connexions SSL/SNI
python batch_scan.py --data-dir data --mode ssl --threads 50
```

### Etape 5 : Analyser les resultats

Les resultats seront dans le dossier `results/`. Regarde les hosts qui ont
repondu avec un code 200 ou 101.

### Etape 6 : Tester dans HTTP Injector / HA Tunnel

Une fois que tu as trouve des bug hosts potentiels :

1. **Installe HTTP Injector** ou **HA Tunnel Plus** sur ton telephone
2. **Configure le payload** :
   ```
   GET / HTTP/1.1[crlf]
   Host: BUG_HOST_TROUVE[crlf]
   Connection: Upgrade[crlf]
   Upgrade: websocket[crlf][crlf]
   ```
   Remplace `BUG_HOST_TROUVE` par le host qui a repondu positivement.

3. **Configure le SNI** : Mets le bug host dans le champ SNI
4. **Configure le serveur SSH/VPN** : Utilise un serveur SSH gratuit
   (fastssh.com, sshkit.com, etc.)
5. **Teste** : Connecte-toi et verifie si ca fonctionne

### Conseils pour Orange RDC

- Les bug hosts changent regulierement, il faut scanner souvent
- Teste d'abord avec des petites plages CIDR (/24) avant de faire des /16
- Les ports 80 et 8080 sont les plus susceptibles de fonctionner
- Utilise le mode DirectNon302 pour eviter les faux positifs
- Les domaines lies aux services de recharge/paiement sont souvent de bons candidats
- Desactive tes donnees mobiles, garde juste le reseau mobile actif, et teste
  si le bug host passe sans forfait

---

## 10. Glossaire

| Terme | Definition |
|-------|-----------|
| **ASN** | Autonomous System Number - Identifiant unique d'un reseau |
| **Bug Host** | Domaine/IP autorise par l'operateur sans forfait |
| **CIDR** | Notation pour representer un groupe d'IPs |
| **CDN** | Content Delivery Network - Reseau de distribution de contenu |
| **DNS** | Domain Name System - Traduit les noms en IPs |
| **Forfait Data** | Credit internet achete aupres de l'operateur |
| **HTTP Injector** | Application Android pour creer des tunnels VPN |
| **HA Tunnel** | Application similaire a HTTP Injector |
| **Payload** | Donnees envoyees au serveur proxy pour etablir le tunnel |
| **Port** | Numero identifiant un service sur un serveur |
| **Proxy** | Serveur intermediaire entre toi et internet |
| **SNI** | Server Name Indication - Nom du serveur dans une connexion TLS |
| **SSL/TLS** | Protocoles de chiffrement pour securiser les connexions |
| **Thread** | Fil d'execution parallele (plus = plus rapide) |
| **Tunnel** | Connexion qui encapsule du trafic dans un autre protocole |
| **Zero-rating** | Services accessibles sans consommer de data |

---

**Avertissement :** Ce guide est fourni a des fins educatives uniquement.
L'utilisation de ces techniques peut enfreindre les conditions d'utilisation
de votre operateur. Utilisez a vos propres risques.
