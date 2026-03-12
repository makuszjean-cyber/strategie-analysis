#!/bin/bash
# ============================================
# Setup Serveur SSH + Stunnel pour Free Surfing
# A lancer sur une instance AWS EC2 Ubuntu
# ============================================
#
# Usage:
#   chmod +x setup_server.sh
#   sudo ./setup_server.sh
#
# Apres l'installation:
#   Host    : ton_ip_publique_ec2
#   Port    : 443 (stunnel/SSL)
#   User    : freesurfer
#   Pass    : (celui que tu choisis)
# ============================================

set -e

echo ""
echo "============================================"
echo "  SETUP SERVEUR FREE SURFING"
echo "============================================"
echo ""

# Demander le mot de passe
read -p "  Choisis un mot de passe pour l'utilisateur SSH : " USER_PASS
echo ""

if [ -z "$USER_PASS" ]; then
    echo "  ERREUR: mot de passe vide"
    exit 1
fi

# 1. Mise a jour
echo "[1/5] Mise a jour du systeme..."
apt-get update -qq && apt-get upgrade -y -qq

# 2. Installer stunnel et openssh
echo "[2/5] Installation de stunnel4 et openssh-server..."
apt-get install -y -qq stunnel4 openssh-server

# 3. Creer l'utilisateur SSH
echo "[3/5] Creation de l'utilisateur 'freesurfer'..."
if id "freesurfer" &>/dev/null; then
    echo "  Utilisateur existe deja, mise a jour du mot de passe"
else
    useradd -m -s /bin/false freesurfer
fi
echo "freesurfer:$USER_PASS" | chpasswd

# Autoriser l'authentification par mot de passe dans SSH
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config

# S'assurer que SSH ecoute sur le port 22
sed -i 's/^#*Port.*/Port 22/' /etc/ssh/sshd_config

systemctl restart sshd

# 4. Configurer stunnel (SSL wrapper sur port 443 → SSH port 22)
echo "[4/5] Configuration de stunnel..."

# Generer un certificat SSL auto-signe
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/CN=stunnel" \
    -keyout /etc/stunnel/stunnel.pem \
    -out /etc/stunnel/stunnel.pem 2>/dev/null

chmod 600 /etc/stunnel/stunnel.pem

# Configurer stunnel
cat > /etc/stunnel/stunnel.conf << 'EOF'
pid = /var/run/stunnel4/stunnel.pid
cert = /etc/stunnel/stunnel.pem
[ssh-ssl]
accept = 443
connect = 127.0.0.1:22
EOF

# Activer stunnel au demarrage
sed -i 's/^ENABLED=0/ENABLED=1/' /etc/default/stunnel4

mkdir -p /var/run/stunnel4
chown stunnel4:stunnel4 /var/run/stunnel4

systemctl enable stunnel4
systemctl restart stunnel4

# 5. Ouvrir les ports (iptables)
echo "[5/5] Configuration du firewall..."
iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true

# Recuperer l'IP publique
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com 2>/dev/null || echo "TON_IP_EC2")

echo ""
echo "============================================"
echo "  SERVEUR PRET !"
echo "============================================"
echo ""
echo "  Tes identifiants :"
echo "  ─────────────────"
echo "  Host     : $PUBLIC_IP"
echo "  Port SSL : 443"
echo "  Port SSH : 22"
echo "  Username : freesurfer"
echo "  Password : $USER_PASS"
echo ""
echo "  Config HTTP Injector :"
echo "  ──────────────────────"
echo "  SSH Host : $PUBLIC_IP"
echo "  SSH Port : 443"
echo "  Username : freesurfer"
echo "  Password : $USER_PASS"
echo "  SSL      : OUI"
echo "  SNI      : ram.cd"
echo "  Payload  : DESACTIVE"
echo "  Proxy    : VIDE"
echo ""
echo "  IMPORTANT : Ouvre le port 443 dans"
echo "  AWS Security Group (voir guide)"
echo "============================================"
echo ""
