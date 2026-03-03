#!/bin/bash
# -------------------------------------------------------------------------
# KERNEL-LEVEL RATE LIMITING FOR HIGH BANDWIDTH DNS (10Gbps - 200Gbps)
# -------------------------------------------------------------------------
# Script ini menerapkan proteksi anti-DDoS di level kernel menggunakan iptables hashlimit.
# Ini JAUH lebih efisien daripada memblokir via aplikasi (Python/Guardian)
# karena paket didrop sebelum memakan resource CPU userspace.
# -------------------------------------------------------------------------

IPT="/sbin/iptables"
IFACE="eth0" # Ganti sesuai interface public

# Flush existing rules (Safety first - comment out if merging with other rules)
# $IPT -F
# $IPT -X

# 1. DROP INVALID PACKETS (Very low cost)
$IPT -A INPUT -p udp --dport 53 -m conntrack --ctstate INVALID -j DROP
$IPT -A INPUT -p tcp --dport 53 -m conntrack --ctstate INVALID -j DROP

# 2. HASH LIMIT FOR DNS FLOOD (The Heavy Lifter)
# Mengizinkan burst tinggi tapi membatasi rata-rata.
# 10Gbps ~ 83k QPS. Kita set limit di 100k/detik per IP agar aman.
# --hashlimit-upto 100000/sec: Izinkan hingga 100k packet/detik per IP
# --hashlimit-burst 200000: Izinkan burst sesaat hingga 200k packet
# --hashlimit-mode srcip: Tracking per Source IP
# --hashlimit-name DNS_FLOOD: Nama tabel hash di memori

echo "Applying Kernel Rate Limiting for DNS..."

# UDP Flood Protection
$IPT -A INPUT -p udp --dport 53 -m hashlimit \
    --hashlimit-name DNS_FLOOD_UDP \
    --hashlimit-mode srcip \
    --hashlimit-upto 100000/sec \
    --hashlimit-burst 200000 \
    -j ACCEPT

# TCP Flood Protection (Lower limit usually)
$IPT -A INPUT -p tcp --dport 53 --syn -m hashlimit \
    --hashlimit-name DNS_FLOOD_TCP \
    --hashlimit-mode srcip \
    --hashlimit-upto 1000/sec \
    --hashlimit-burst 5000 \
    -j ACCEPT

# LOG & DROP EXCESSIVE TRAFFIC
# Hanya log max 10/menit agar log tidak meledak saat serangan
$IPT -A INPUT -p udp --dport 53 -m limit --limit 10/min -j LOG --log-prefix "DNS_FLOOD_DROP: "
$IPT -A INPUT -p udp --dport 53 -j DROP

$IPT -A INPUT -p tcp --dport 53 -m limit --limit 10/min -j LOG --log-prefix "DNS_FLOOD_DROP: "
$IPT -A INPUT -p tcp --dport 53 -j DROP

echo "Kernel Rate Limiting Applied."
echo "Verify with: iptables -L -v -n"
