# Analyse Complete de Tes Resultats (2 jours de scan)

## Resume de tous tes scans

| Fichier | Mode | Resultats | Codes trouves |
|---------|------|-----------|---------------|
| proxy_071009 | Proxy (CONNECT 443) | 1 hit | 400 uniquement |
| proxy_073338 | Proxy (port 80) | 786 hits | **400 uniquement** |
| ssl_080459 | SSL/SNI | 0 hit | aucun |
| ssl_093531 | SSL/SNI | 0 hit | aucun |
| 065140 | Proxy | 0 hit | aucun |
| 072554 | Combine | 1 hit | 400 |
| 075508 | Combine | 786 hits | 400 |
| 083133 | SSL combine | 0 hit | aucun |
| 092404 | DirectNon302 | 0 hit | aucun |
| 095417 | SSL combine | 0 hit | aucun |

## Le verdict

**TOUS tes resultats sont des code 400 (Bad Request) de serveurs Cloudflare.**

- Aucun code **101** (WebSocket) - c'est celui qu'il te faut
- Aucun code **200** (OK)
- Aucun resultat SSL/SNI - aucun handshake TLS reussi
- Aucun resultat DirectNon302 - aucun serveur HTTP valide

Ca veut dire : **aucun bug host trouve en 2 jours de scan.**

---

## Pourquoi c'est normal (et pourquoi ca ne POUVAIT PAS marcher)

### Raison 1 : Les serveurs Cloudflare ne sont PAS des proxys ouverts

Quand tu fais un scan en mode "proxy", tu envoies a chaque IP un payload
du type CONNECT ou GET en esperant qu'elle agisse comme proxy. Mais les
serveurs Cloudflare sont des **reverse proxys** : ils ne font passer le
trafic que vers les sites de leurs clients. Ils ne vont pas relayer ta
connexion vers un serveur SSH arbitraire.

C'est pour ca que 100% des reponses sont **400 Bad Request** = "je ne
comprends pas ta requete" ou "je refuse de faire ca".

### Raison 2 : Le scan se fait depuis un serveur distant, pas depuis Orange

Meme si tu trouvais une IP qui repond avec code 200, ca ne prouverait pas
qu'elle fonctionne comme bug host chez Orange RDC. Un bug host doit etre
teste **depuis le reseau Orange, sans forfait data actif**.

Le scan te dit : "cette IP est en ligne et repond"
Le scan ne te dit PAS : "Orange autorise le trafic vers cette IP sans forfait"

### Raison 3 : Scanner des IPs individuelles n'est PAS la bonne methode

Le free surfing fonctionne avec des **noms de domaine** (SNI), pas avec des
IPs. Quand Orange autorise un service (ex: Google, un partenaire), il autorise
le **domaine** (ex: *.google.com) via le champ SNI dans le TLS. L'IP derriere
peut etre n'importe laquelle.

---

## La BONNE methode (ce que fait Luka)

Ton ami Luka a la bonne approche. Voici ce qu'il fait :

### 1. Il utilise des domaines, pas des IPs

Son payload utilise `system-948161790989.southamerica-east1.run.app` - c'est
un **nom de domaine** Google Cloud Run. Orange autorise probablement le
trafic vers certains services Google.

### 2. Il a un serveur tunnel derriere

Le domaine *.run.app pointe vers une application qui fait office de relais
WebSocket. Le flux est :

```
Telephone (pas de forfait)
    |
    | SNI = system-xxx.run.app (autorise par Orange)
    v
Google Cloud Run (le bug host)
    |
    | Tunnel WebSocket
    v
Internet libre
```

### 3. Le payload WebSocket est correct

```
GET /app10 HTTP/1.1[crlf]
Host: system-948161790989.southamerica-east1.run.app[crlf]
Connection: Upgrade[crlf]
User-Agent: [ua][crlf]
Upgrade: Websocket[crlf][crlf]
```

- **GET** (pas CONNECT) - requete HTTP normale
- **Host** = le bug host autorise
- **Upgrade: Websocket** = demande de tunnel WebSocket

---

## Ce que tu dois faire MAINTENANT

### Etape 1 : Arrete de scanner des IPs Cloudflare

Tu as passe 2 jours a scanner et c'est 100% code 400. Scanner plus d'IPs
Cloudflare donnera le meme resultat. Les CDN ne sont pas des proxys ouverts.

### Etape 2 : Teste le payload de Luka

1. **Installe DTunnel** sur ton telephone Android
2. **Cree un serveur SSH gratuit** :
   - Va sur https://www.fastssh.com/ ou https://sshmax.net/
   - Choisis un serveur (ex: Singapore, Europe)
   - Cree un compte SSH (username + password, valide 7 jours)

3. **Configure DTunnel** :
   ```
   Mode : SSH + WebSocket (ou SSH over WS)

   Payload :
   GET /app10 HTTP/1.1[crlf]
   Host: system-948161790989.southamerica-east1.run.app[crlf]
   Connection: Upgrade[crlf]
   User-Agent: [ua][crlf]
   Upgrade: Websocket[crlf][crlf]

   Remote Proxy : system-948161790989.southamerica-east1.run.app
   Port proxy : 80 (ou 443)
   SNI : system-948161790989.southamerica-east1.run.app

   Serveur SSH : (celui de fastssh/sshmax)
   Port SSH : 443
   Username : (celui que tu as cree)
   Password : (celui que tu as cree)
   ```

4. **Teste** :
   - Desactive le WiFi
   - Active les donnees mobiles
   - Ne prends PAS de forfait
   - Lance DTunnel
   - Si ca se connecte = ca marche !

### Etape 3 : Si le host de Luka est bloque

Luka a dit "le 2e c'est celui qu'on a bloque". Les bug hosts se font
bloquer regulierement. Si *.run.app ne marche plus, il faut trouver
un autre domaine autorise par Orange.

**Comment trouver d'autres bug hosts (la vraie methode) :**

Depuis ton telephone Orange SANS forfait :

1. Ouvre le navigateur et essaie ces URLs :
   - `http://www.google.com`
   - `http://play.google.com`
   - `http://www.gstatic.com`
   - `http://clients1.google.com`
   - `http://connectivitycheck.gstatic.com`
   - `http://www.orange.cd`
   - `http://0.gone.cd`
   - `http://www.facebook.com` (parfois zero-rated)

2. Si une page charge (meme partiellement ou avec redirection) = c'est un
   bug host potentiel !

3. Note le domaine et utilise-le dans le payload a la place du *.run.app

### Etape 4 : Le scan utile (si tu veux continuer a scanner)

Si tu veux vraiment scanner, scanne des **domaines** pas des IPs :

```bash
# 1. Trouve des sous-domaines de services potentiellement autorises
#    Utilise BugScanX option 2 (SUBFINDER) pour :
bugscanx
# -> Option 2 (SUBFINDER)
# -> Domaines : google.cd, orange.cd, gone.cd

# 2. Ou cree un fichier de domaines a tester
# data/domains/test_bughost.txt avec :
#   www.google.com
#   play.google.com
#   connectivitycheck.gstatic.com
#   www.orange.cd
#   0.gone.cd
#   etc.

# 3. Scanne en mode Direct (pas Proxy)
python3 scripts/batch_scan.py --data-dir data/domains --mode direct --ports 80,443 --threads 50
```

---

## En resume

| Ce que tu as fait | Pourquoi ca marche pas |
|-------------------|----------------------|
| Scan proxy sur IPs Cloudflare | Cloudflare n'est pas un proxy ouvert → 400 |
| Scan SSL sur IPs Cloudflare | Pas de domaine = pas de certificat → echec |
| Scan DirectNon302 | Depuis un serveur distant, pas depuis Orange |
| 2 jours de scan massif | Mauvaise cible (IPs au lieu de domaines) |

| Ce qu'il faut faire | Pourquoi |
|---------------------|----------|
| Utiliser le payload de Luka | Il a un bug host qui marche (*.run.app) |
| Tester depuis le telephone Orange | Seul moyen de verifier si ca passe sans forfait |
| Chercher des domaines autorises | Le free surfing marche avec des noms de domaine, pas des IPs |
| Scanner des domaines (pas des IPs) | Un domaine autorise sur n'importe quelle IP = bug host |
