#!/bin/bash
# ==============================================================================
# FIREWALL TUNING SCRIPT
# ==============================================================================
# Use this script to tune iptables rate limits without editing raw commands.
# Run: sudo ./tune_firewall.sh
# ==============================================================================

# --- CONFIGURATION (Adjust based on Traffic) ---

# UDP DNS (Standard Query)
UDP_LIMIT="2000/sec"    # Max average match rate
UDP_BURST="5000"        # Max initial burst

# TCP DNS (Large Responses / Zone Transfers / DoT)
TCP_LIMIT="500/sec"
TCP_BURST="1000"

# API Sync (Port 5000)
API_LIMIT="10/min"
API_BURST="20"

# ==============================================================================

echo "Applying Firewall Tuning..."

# Flush existing custom chains if any (optional, here we append/replace)
# For safety, we will delete the specific rules we added before adding new ones
# to avoid duplication.

# Delete previous rules if they exist (ignore errors)
iptables -D INPUT -p udp --dport 53 -m hashlimit --hashlimit-name DNS --hashlimit-above $UDP_LIMIT --hashlimit-burst $UDP_BURST --hashlimit-mode srcip -j DROP 2>/dev/null
iptables -D INPUT -p tcp --dport 53 -m hashlimit --hashlimit-name DNS_TCP --hashlimit-above $TCP_LIMIT --hashlimit-burst $TCP_BURST --hashlimit-mode srcip -j DROP 2>/dev/null

# Apply New Rules
echo "Setting DROP for INVALID state (Malformed Traffic)..."
iptables -A INPUT -p udp --dport 53 -m conntrack --ctstate INVALID -j DROP

echo "Setting UDP Limit: $UDP_LIMIT (Burst: $UDP_BURST)"
iptables -A INPUT -p udp --dport 53 -m hashlimit --hashlimit-name DNS --hashlimit-above $UDP_LIMIT --hashlimit-burst $UDP_BURST --hashlimit-mode srcip -j DROP

echo "Setting TCP Limit: $TCP_LIMIT (Burst: $TCP_BURST)"
iptables -A INPUT -p tcp --dport 53 -m hashlimit --hashlimit-name DNS_TCP --hashlimit-above $TCP_LIMIT --hashlimit-burst $TCP_BURST --hashlimit-mode srcip -j DROP

# Save rules
netfilter-persistent save 2>/dev/null || echo "Warning: netfilter-persistent not installed. Rules are active but not saved across reboots."

echo "Done."
