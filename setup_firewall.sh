#!/bin/bash

# Reset rules (Hati-hati: Pastikan port SSH 22 tetap terbuka)
# Kita tidak akan flush semua jika ingin aman, tapi kita tambahkan rule di atas.

echo "Setting up Anti-DDoS and DNS Flood Protection..."

# --- SYSTEM CLEANUP & FIXES ---
# Ensure no stray disabled files in dnsmasq config to prevent "Ghost Blocking"
echo "Cleaning up stray config files..."
rm -f /etc/dnsmasq.d/*.disabled
# ------------------------------

# 1. Port yang diizinkan dengan ACL (SSH & Web GUI)
# Ambil IP server secara otomatis atau dari argumen
if [ ! -z "$1" ]; then
    SERVER_IP=$1
else
    # Improved IP detection (IPv4)
    SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || ip -4 addr show | grep inet | grep -v '127.0.0.1' | head -n1 | awk '{print $2}' | cut -d/ -f1)
fi

# Detect IPv6
SERVER_IPV6=$(ip -6 addr show | grep -v "fe80" | grep -v "::1" | grep "inet6" | awk '{print $2}' | cut -d/ -f1 | head -n1)

echo "Using Server IP (v4): $SERVER_IP"
[ ! -z "$SERVER_IPV6" ] && echo "Using Server IP (v6): $SERVER_IPV6"

# Load Whitelist from file
WHITELIST_FILE="/home/dns/whitelist.conf"
ALLOWED_IPS=("$SERVER_IP" "127.0.0.1")
ALLOWED_IPS_V6=("$SERVER_IPV6" "::1")
ALLOWED_SUBNETS=()
ALLOWED_SUBNETS_V6=()

if [ -f "$WHITELIST_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "$line" ]] && continue
        
        if [[ "$line" == *:* ]]; then
            # IPv6
            if [[ "$line" == */* ]]; then
                ALLOWED_SUBNETS_V6+=("$line")
            else
                ALLOWED_IPS_V6+=("$line")
            fi
        else
            # IPv4
            if [[ "$line" == */* ]]; then
                ALLOWED_SUBNETS+=("$line")
            else
                ALLOWED_IPS+=("$line")
            fi
        fi
    done < "$WHITELIST_FILE"
fi

# Flush existing INPUT rules to apply ACL cleanly
# Set default policy to ACCEPT first to prevent lockout during flush
iptables -P INPUT ACCEPT
ip6tables -P INPUT ACCEPT 2>/dev/null || true

iptables -F INPUT
ip6tables -F INPUT 2>/dev/null || true

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

# --- GLOBAL WHITELIST (PRIORITAS TERTINGGI) ---
# IPv4
echo "Applying Global Whitelist (IPv4)..."
for ip in "${ALLOWED_IPS[@]}"; do
    if [ ! -z "$ip" ]; then
        iptables -A INPUT -s "$ip" -j ACCEPT
    fi
done
for subnet in "${ALLOWED_SUBNETS[@]}"; do
    iptables -A INPUT -s "$subnet" -j ACCEPT
done

# IPv6
echo "Applying Global Whitelist (IPv6)..."
for ip in "${ALLOWED_IPS_V6[@]}"; do
    if [ ! -z "$ip" ] && [ "$ip" != "::1" ]; then
        ip6tables -A INPUT -s "$ip" -j ACCEPT 2>/dev/null || true
    fi
done
for subnet in "${ALLOWED_SUBNETS_V6[@]}"; do
    ip6tables -A INPUT -s "$subnet" -j ACCEPT 2>/dev/null || true
done

# Allow SSH and Web GUI (Port 5000) for trusted IPs
for ip in "${ALLOWED_IPS[@]}"; do
    if [ ! -z "$ip" ]; then
        iptables -A INPUT -s "$ip" -p tcp --dport 22 -j ACCEPT
        iptables -A INPUT -s "$ip" -p tcp --dport 5000 -j ACCEPT
    fi
done
# IPv6 SSH/GUI
for ip in "${ALLOWED_IPS_V6[@]}"; do
    if [ ! -z "$ip" ]; then
        ip6tables -A INPUT -s "$ip" -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
        ip6tables -A INPUT -s "$ip" -p tcp --dport 5000 -j ACCEPT 2>/dev/null || true
    fi
done

# Allow Web GUI (Port 5000) for everyone with Rate Limiting
iptables -A INPUT -p tcp --dport 5000 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 5000 -m state --state NEW -m recent --update --seconds 60 --hitcount 15 -j DROP
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT

ip6tables -A INPUT -p tcp --dport 5000 -j ACCEPT 2>/dev/null || true

# Drop all other SSH attempts
iptables -A INPUT -p tcp --dport 22 -j DROP
ip6tables -A INPUT -p tcp --dport 22 -j DROP 2>/dev/null || true

# Allow HTTP and HTTPS for Block Page (Accessible to all)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true

# 2. Proteksi DNS UDP Flood (ISP Grade - 30Gbps Optimized)
  # Whitelist IPs and subnets from rate limit
  for ip in "${ALLOWED_IPS[@]}"; do
      if [ ! -z "$ip" ]; then
          iptables -A INPUT -s "$ip" -p udp --dport 53 -j ACCEPT
          iptables -A INPUT -s "$ip" -p tcp --dport 53 -j ACCEPT
      fi
  done
  for subnet in "${ALLOWED_SUBNETS[@]}"; do
      iptables -A INPUT -s "$subnet" -p udp --dport 53 -j ACCEPT
      iptables -A INPUT -s "$subnet" -p tcp --dport 53 -j ACCEPT
  done

  # IPv6 Whitelist for DNS
  for ip in "${ALLOWED_IPS_V6[@]}"; do
      if [ ! -z "$ip" ]; then
          ip6tables -A INPUT -s "$ip" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
          ip6tables -A INPUT -s "$ip" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
      fi
  done
  for subnet in "${ALLOWED_SUBNETS_V6[@]}"; do
      ip6tables -A INPUT -s "$subnet" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
      ip6tables -A INPUT -s "$subnet" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
  done

  # DNS Flood Protection (UDP Port 53) - ISP SCALE for 30Gbps
    # Per IP Limit: Increased to 500,000 QPS (For Large NAT/CGNAT/Office/Campus)
    # This ensures a single IP with thousands of users won't be blocked.
    iptables -A INPUT -p udp --dport 53 -m hashlimit --hashlimit-name dns_flood --hashlimit-upto 500000/sec --hashlimit-burst 500000 --hashlimit-mode srcip --hashlimit-htable-expire 300000 -j ACCEPT
    
    # Global Limit: Massive (1 Million QPS total per rule, but since we accept, it basically unlimits it for hardware)
    # Note: iptables hashlimit has a max rate. 50M/sec is too fast for the parser.
    # Setting to 1,000,000/sec which is effectively line rate for software filtering.
    iptables -A INPUT -p udp --dport 53 -m hashlimit --hashlimit-name dns_global --hashlimit-upto 1000000/sec --hashlimit-burst 1000000 --hashlimit-htable-expire 10000 -j ACCEPT

   # IPv6 DNS Flood Protection (High Limit for NAT)
   ip6tables -A INPUT -p udp --dport 53 -m hashlimit --hashlimit-name dns6_flood --hashlimit-upto 500000/sec --hashlimit-burst 500000 --hashlimit-mode srcip --hashlimit-htable-expire 300000 -j ACCEPT 2>/dev/null || true
   ip6tables -A INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
   ip6tables -A INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || true

   # Drop sisanya (IPv4) if exceeding massive limits
   iptables -A INPUT -p udp --dport 53 -j DROP

# 3. Proteksi DNS TCP Flood (Conn Limit: 10,000 connections per source IP - ISP Grade)
# Allows massive concurrency for large NAT deployments or heavy TCP fallback.
iptables -A INPUT -p tcp --dport 53 -m connlimit --connlimit-above 10000 -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp --dport 53 -j ACCEPT

# 4. Proteksi ICMP Flood (Ping Flood) - Relaxed for diagnostic tools
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# --- DNS TRUST CHECK ---
# Cek apakah ada konfigurasi upstream di smartdns.conf
SMARTDNS_CONF="/etc/dnsmasq.d/smartdns.conf"
if [ -f "$SMARTDNS_CONF" ] && grep -q "^server=" "$SMARTDNS_CONF"; then
    DNS_TRUST_ENABLED=true
    echo "DNS Trust is ENABLED. Applying block rules."
else
    DNS_TRUST_ENABLED=false
    echo "DNS Trust is DISABLED. Skipping block rules."
fi

# 5. NAT Interception (Agresif: Menangkap semua trafik DNS dan HTTP luar ke server lokal)
iptables -t nat -F PREROUTING
ip6tables -t nat -F PREROUTING 2>/dev/null || true

# Selalu aktifkan NAT Interception agar Halaman Blokir dan Intersepsi DNS tetap jalan
# meskipun DNS Trust (upstream) sedang dimatikan.
echo "Applying NAT Interception (DNS & HTTP/HTTPS) for Block Page..."

# Redirect trafik UDP port 53 (DNS)
# Disable whitelist bypass for DNS interception to enforce filtering for everyone
# for ip in "${ALLOWED_IPS[@]}"; do
#    [ ! -z "$ip" ] && iptables -t nat -A PREROUTING -p udp -s "$ip" --dport 53 -j ACCEPT
# done
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53

# Redirect trafik UDP port 53 (DNS) IPv6
# for ip in "${ALLOWED_IPS_V6[@]}"; do
#    [ ! -z "$ip" ] && ip6tables -t nat -A PREROUTING -p udp -s "$ip" --dport 53 -j ACCEPT 2>/dev/null
# done
ip6tables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null

# Redirect trafik TCP port 53 (DNS)
# for ip in "${ALLOWED_IPS[@]}"; do
#    [ ! -z "$ip" ] && iptables -t nat -A PREROUTING -p tcp -s "$ip" --dport 53 -j ACCEPT
# done
iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 53

# Redirect trafik TCP port 53 (DNS) IPv6
# for ip in "${ALLOWED_IPS_V6[@]}"; do
#    [ ! -z "$ip" ] && ip6tables -t nat -A PREROUTING -p tcp -s "$ip" --dport 53 -j ACCEPT 2>/dev/null
# done
ip6tables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null

# --- HTTP/HTTPS INTERCEPTION UNTUK HALAMAN BLOKIR ---
# Note: Intersepsi agresif port 80/443 dinonaktifkan untuk menghindari "Sign in to network" popup pada mobile.
# Halaman blokir tetap bekerja melalui resolusi DNS ke IP server.

iptables -t nat -A PREROUTING -p tcp --dport 80 -d $SERVER_IP -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 443 -d $SERVER_IP -j ACCEPT

# IPv6 HTTP/HTTPS Redirect
if [ ! -z "$SERVER_IPV6" ]; then
    ip6tables -t nat -A PREROUTING -p tcp --dport 80 ! -d $SERVER_IPV6 -j REDIRECT --to-ports 80 2>/dev/null || true
    ip6tables -t nat -A PREROUTING -p tcp --dport 443 ! -d $SERVER_IPV6 -j REDIRECT --to-ports 443 2>/dev/null || true
fi

# 6. Restore Persistent Blocks from Guardian
if [ "$DNS_TRUST_ENABLED" = true ]; then
    BANNED_IPS_FILE="/home/dns/banned_ips.txt"
    if [ -f "$BANNED_IPS_FILE" ]; then
        echo "Restoring persistent blocks from $BANNED_IPS_FILE..."
        while IFS= read -r ip || [ -n "$ip" ]; do
            if [ ! -z "$ip" ]; then
                iptables -I INPUT -s "$ip" -j DROP
            fi
        done < "$BANNED_IPS_FILE"
    fi
fi

# 6. Drop Invalid Packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# 6. Proteksi SYN Flood (Kernel Level & iptables)
iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# 7. Sysctl Optimizations (Anti-DDoS)
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_synack_retries=2
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1

# 8. MSS Clamping (Fix MTU issues for Gaming/Streaming)
iptables -t mangle -F POSTROUTING
ip6tables -t mangle -F POSTROUTING 2>/dev/null || true
iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

echo "Firewall rules applied successfully."
