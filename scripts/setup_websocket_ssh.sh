#!/bin/bash
# ==================================================
# Setup Serveur WebSocket SSH pour Free Surfing
# Architecture: HTTP Injector → WebSocket → SSH
# ==================================================
#
# Ce que ca fait:
#   - Installe un proxy WebSocket sur le port 80
#   - Ce proxy recoit le payload HTTP, fait l'upgrade WebSocket
#   - Puis relaie vers SSH sur localhost:22
#
# C'est CETTE architecture que les gens utilisent
# quand ils te donnent: host + port + payload + user/pass
#
# Usage:
#   chmod +x setup_websocket_ssh.sh
#   sudo ./setup_websocket_ssh.sh
#
# Config HTTP Injector:
#   Mode     : HTTP Proxy → SSH (Custom Payload)
#   Proxy    : TON_IP:80
#   Payload  : GET / HTTP/1.1[crlf]Host: ram.cd[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]
#   SSH Host : TON_IP
#   SSH Port : 80
#   User/Pass: freesurfer / ton_mot_de_passe
# ==================================================

set -e

echo ""
echo "  ============================================"
echo "    SETUP WEBSOCKET SSH SERVER"
echo "  ============================================"
echo ""

read -p "  Mot de passe pour l'utilisateur SSH : " USER_PASS
echo ""

if [ -z "$USER_PASS" ]; then
    echo "  ERREUR: mot de passe vide"
    exit 1
fi

# 1. Mise a jour + dependances
echo "[1/6] Installation des paquets..."
apt-get update -qq
apt-get install -y -qq openssh-server python3 python3-pip

# 2. Creer l'utilisateur SSH
echo "[2/6] Creation de l'utilisateur SSH..."
if id "freesurfer" &>/dev/null; then
    echo "  Utilisateur freesurfer existe deja"
else
    useradd -m -s /bin/bash freesurfer
fi
echo "freesurfer:$USER_PASS" | chpasswd

# Activer authentification par mot de passe
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
rm -f /etc/ssh/sshd_config.d/60-cloudimg-settings.conf 2>/dev/null
echo "PasswordAuthentication yes" > /etc/ssh/sshd_config.d/99-password.conf

systemctl restart sshd
echo "  SSH configure (port 22, password auth)"

# 3. Creer le proxy WebSocket
echo "[3/6] Creation du proxy WebSocket..."

cat > /opt/ws-ssh-proxy.py << 'PYEOF'
#!/usr/bin/env python3
"""WebSocket SSH Proxy - Ecoute sur port 80, relaie vers SSH port 22."""

import socket
import threading
import sys
import os

LISTEN_PORT = int(os.environ.get("WS_PORT", 80))
SSH_HOST = "127.0.0.1"
SSH_PORT = 22
BUFFER_SIZE = 65536

HTTP_RESPONSE = (
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "\r\n"
)

def relay(src, dst, name=""):
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            dst.sendall(data)
    except (OSError, BrokenPipeError, ConnectionResetError):
        pass
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass

def handle_client(client_sock, addr):
    try:
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = client_sock.recv(4096)
            if not chunk:
                client_sock.close()
                return
            header += chunk

        client_sock.sendall(HTTP_RESPONSE.encode())

        ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssh_sock.connect((SSH_HOST, SSH_PORT))

        t1 = threading.Thread(target=relay, args=(client_sock, ssh_sock, "client->ssh"), daemon=True)
        t2 = threading.Thread(target=relay, args=(ssh_sock, client_sock, "ssh->client"), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    except (OSError, ConnectionRefusedError) as e:
        pass
    finally:
        try: client_sock.close()
        except: pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(100)
    print(f"[WS-SSH] Ecoute sur port {LISTEN_PORT} -> SSH {SSH_HOST}:{SSH_PORT}")

    while True:
        try:
            client_sock, addr = server.accept()
            threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
PYEOF

chmod +x /opt/ws-ssh-proxy.py

# 4. Creer le service systemd
echo "[4/6] Creation du service systemd..."

cat > /etc/systemd/system/ws-ssh-proxy.service << 'EOF'
[Unit]
Description=WebSocket SSH Proxy
After=network.target sshd.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/ws-ssh-proxy.py
Restart=always
RestartSec=3
Environment=WS_PORT=80

[Install]
WantedBy=multi-user.target
EOF

# 5. Arreter les services qui utilisent le port 80
echo "[5/6] Liberation du port 80..."
systemctl stop apache2 2>/dev/null || true
systemctl disable apache2 2>/dev/null || true
systemctl stop nginx 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true

# Demarrer le proxy
systemctl daemon-reload
systemctl enable ws-ssh-proxy
systemctl start ws-ssh-proxy

# 6. Firewall
echo "[6/6] Configuration firewall..."
iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true

# Recuperer l'IP publique
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com 2>/dev/null || echo "TON_IP_EC2")

# Verifier que ca tourne
sleep 2
if systemctl is-active --quiet ws-ssh-proxy; then
    STATUS="EN MARCHE"
else
    STATUS="ERREUR - voir: sudo journalctl -u ws-ssh-proxy"
fi

echo ""
echo "  ============================================"
echo "    SERVEUR PRET ! ($STATUS)"
echo "  ============================================"
echo ""
echo "  Config pour HTTP Injector :"
echo "  ────────────────────────────"
echo ""
echo "  1) Mode: HTTP Proxy -> SSH (Custom Payload)"
echo ""
echo "  2) Payload:"
echo "     GET / HTTP/1.1[crlf]Host: ram.cd[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]"
echo ""
echo "  3) Remote Proxy:"
echo "     Host : $PUBLIC_IP"
echo "     Port : 80"
echo ""
echo "  4) SSH:"
echo "     Host : $PUBLIC_IP"
echo "     Port : 22"
echo "     User : freesurfer"
echo "     Pass : $USER_PASS"
echo ""
echo "  5) SSL/SNI : DESACTIVE"
echo ""
echo "  ============================================"
echo ""
