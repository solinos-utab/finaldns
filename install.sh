#!/bin/bash

# --- DNS Mars Data Telekomunikasi - Auto Installer ---
# Author: DNS Guardian AI
# Description: Automated setup for DNS, Firewall, Web GUI, and Guardian Service.

set -e # Exit on error

echo "🚀 Starting DNS Mars Auto-Installation..."

# 1. Update & Install Dependencies
echo "📦 Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y dnsmasq unbound python3 python3-pip python3-psutil iptables-persistent curl git re2c

# 2. Setup Directory Structure
echo "📂 Setting up directories..."
mkdir -p /home/dns/web_gui/static/img
mkdir -p /home/dns/web_gui/templates

# 3. Configure DNS (dnsmasq & unbound)
echo "⚙️ Configuring DNS services..."
# Move local configs to system directories
sudo cp /home/dns/dnsmasq_base.conf /etc/dnsmasq.d/00-base.conf
if [ ! -f /etc/dnsmasq.d/upstream.conf ]; then
    echo -e "server=8.8.8.8\nserver=1.1.1.1" | sudo tee /etc/dnsmasq.d/upstream.conf
fi
sudo cp /home/dns/unbound_smartdns.conf /etc/unbound/unbound.conf.d/smartdns.conf

# 4. Setup Firewall
echo "🛡️ Configuring Firewall (Anti-DDoS & ACL)..."
sudo chmod +x /home/dns/setup_firewall.sh
sudo /home/dns/setup_firewall.sh

# 5. Generate SSL Certificates (Self-signed)
echo "🔐 Generating SSL certificates for Web GUI..."
if [ ! -f /home/dns/web_gui/cert.pem ]; then
    openssl req -x509 -newkey rsa:4096 -keyout /home/dns/web_gui/key.pem -out /home/dns/web_gui/cert.pem -days 365 -nodes -subj "/C=ID/ST=Jakarta/L=Jakarta/O=MarsData/OU=IT/CN=dns.mdnet.co.id"
fi

# 6. Setup Systemd Services
echo "🔄 Setting up Systemd services..."

# Guardian Service
sudo tee /etc/systemd/system/guardian.service <<EOF
[Unit]
Description=Intelligent DNS Guardian & Self-Healing Service
After=network.target dnsmasq.service unbound.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/dns
ExecStart=/usr/bin/python3 /home/dns/guardian.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Web GUI Service
sudo tee /etc/systemd/system/dnsmars-gui.service <<EOF
[Unit]
Description=DNS Mars Web Management GUI
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/dns
ExecStart=/usr/bin/python3 /home/dns/web_gui/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 7. Enable & Start Services
echo "✅ Enabling and starting services..."
sudo systemctl daemon-reload
sudo systemctl enable dnsmasq unbound guardian dnsmars-gui
sudo systemctl restart dnsmasq unbound guardian dnsmars-gui

echo "-------------------------------------------------------"
echo "🎉 Installation Complete!"
echo "🌐 Web GUI: https://$(curl -s ifconfig.me):5000"
echo "🔒 Access: Restricted to whitelisted IPs in setup_firewall.sh"
echo "-------------------------------------------------------"
