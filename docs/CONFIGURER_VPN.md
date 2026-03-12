# Configurer le VPN avec ton Bug Host

Tu as trouve un domaine qui charge SANS forfait sur Orange.
Voici comment le transformer en internet gratuit.

---

## Etape 1 : Creer un serveur SSH gratuit

Va sur UN de ces sites (depuis WiFi ou un ami) :

- https://www.fastssh.com/
- https://sshmax.net/
- https://www.sshkit.com/
- https://www.mytunneling.com/

### Sur fastssh.com par exemple :
1. Choisis "SSH Websocket" (important : WEBSOCKET)
2. Choisis un serveur (ex: Singapore, France, USA)
3. Remplis : Username, Password
4. Clique "Create Account"
5. NOTE ces infos :
   - Host : ex `sg1.fastssh.com`
   - Port WS : ex `80`
   - Port WSS/TLS : ex `443`
   - Username : ce que tu as mis
   - Password : ce que tu as mis

---

## Etape 2 : Installer l'application

Installe UNE de ces apps sur ton telephone :

- **HTTP Injector** (Play Store)
- **HA Tunnel Plus** (Play Store)
- **DTunnel** (Play Store / APK)

---

## Etape 3 : Configurer (HTTP Injector)

### 3a. Onglet SSH

```
SSH Host     : sg1.fastssh.com  (celui de fastssh)
SSH Port     : 443
Username     : ton_username
Password     : ton_password
```

### 3b. Onglet Payload

Coche "Payload Mode" et mets :

```
GET / HTTP/1.1[crlf]Host: TON_BUG_HOST[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]
```

Remplace `TON_BUG_HOST` par le domaine que tu as trouve.

### 3c. Onglet SSL

```
SNI Host : TON_BUG_HOST
```

### 3d. Proxy distant

```
Remote Proxy : TON_BUG_HOST
Remote Port  : 80  (ou 443)
```

### 3e. Connecter

1. Ferme le WiFi
2. Active les donnees mobiles (PAS de forfait)
3. Appuie sur CONNECTER
4. Attends "Connected" → Internet gratuit !

---

## Etape 3 BIS : Configurer (HA Tunnel Plus)

1. Methode de connexion : **SSH + Proxy**
2. En haut, coche **Custom SNI/Proxy**
3. SNI/Proxy Host : `TON_BUG_HOST`
4. Port : `80` ou `443`

### Serveur SSH :
```
Host     : sg1.fastssh.com
Port     : 443
Username : ton_username
Password : ton_password
```

### Payload (dans les parametres avances) :
```
GET / HTTP/1.1[crlf]Host: TON_BUG_HOST[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]
```

Connecter.

---

## Etape 3 TER : Configurer (DTunnel)

1. Mode : **SSH**
2. Serveur SSH :
   - Host : `sg1.fastssh.com`
   - Port : `443`
   - Username : ton_username
   - Password : ton_password
3. Network Settings :
   - Connection Mode : `SSH + Proxy`
   - Custom SNI : `TON_BUG_HOST`
4. Payload :
```
GET / HTTP/1.1[crlf]Host: TON_BUG_HOST[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]
```

Connecter.

---

## Si ca ne connecte pas : essayer ces variantes

### Variante 1 : Payload CONNECT
```
CONNECT [ssh_host]:443 HTTP/1.1[crlf]Host: TON_BUG_HOST[crlf][crlf]
```

### Variante 2 : Payload avec injection Host front
```
GET / HTTP/1.1[crlf]Host: TON_BUG_HOST[crlf]X-Online-Host: TON_BUG_HOST[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]
```

### Variante 3 : Payload split (pour contourner DPI)
```
GET / HTTP/1.1[crlf]Host: TON_BUG_HOST[crlf]Connection: Keep-Alive[crlf][crlf]CONNECT [ssh_host]:443 HTTP/1.1[crlf]Host: TON_BUG_HOST[crlf][crlf]
```

### Variante 4 : Port 80 au lieu de 443
Change le port SSH de 443 a 80 et le port proxy de 443 a 80.

### Variante 5 : Changer le serveur SSH
Parfois le probleme vient du serveur SSH. Essaie un autre serveur
(autre pays, autre fournisseur).

---

## Checklist si ca ne marche pas

- [ ] WiFi DESACTIVE ?
- [ ] Donnees mobiles ACTIVEES ?
- [ ] PAS de forfait data actif ?
- [ ] Le bug host est bien celui qui charge sans forfait ?
- [ ] Le serveur SSH est "SSH WebSocket" (pas SSH normal) ?
- [ ] Le payload contient bien ton bug host ?
- [ ] Le SNI contient bien ton bug host ?
- [ ] Tu as essaye les 2 ports (80 et 443) ?
- [ ] Tu as essaye les variantes de payload ?
- [ ] Tu as essaye un autre serveur SSH ?
