#!/bin/bash

# PT MARS DATA TELEKOMUNIKASI
# Advanced Kernel Optimization for DNS Server
# Mitigates: UDP Drops, IRQ Overload, Swap Thrashing, Network Bottlenecks

echo "Applying Kernel Optimizations..."

# 1. NETWORK OPTIMIZATION (Prevent UDP Drops & Bottlenecks)
# Increase buffer sizes for high-speed UDP (DNS)
sysctl -w net.core.rmem_default=8388608
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_default=8388608
sysctl -w net.core.wmem_max=16777216
sysctl -w net.core.netdev_max_backlog=5000
sysctl -w net.core.somaxconn=4096

# Optimize IP range
sysctl -w net.ipv4.ip_local_port_range="1024 65535"

# 2. SWAP THRASHING MITIGATION
# Only use swap if absolutely necessary (RAM > 90% full)
sysctl -w vm.swappiness=10
sysctl -w vm.vfs_cache_pressure=50

# 3. IRQ OVERLOAD & CPU
# Ensure irqbalance is installed and running
if ! dpkg -s irqbalance >/dev/null 2>&1; then
    echo "Installing irqbalance..."
    apt-get update && apt-get install -y irqbalance
fi
systemctl enable --now irqbalance

# 4. MEMORY MANAGEMENT (Prevent OOM Kills on critical services)
# Adjust OOM Score for DNS services to prevent them being killed first
if pidof dnsmasq > /dev/null; then
    echo "-1000" > /proc/$(pidof dnsmasq)/oom_score_adj
fi
if pidof unbound > /dev/null; then
    echo "-1000" > /proc/$(pidof unbound)/oom_score_adj
fi

# 5. PROTECTION AGAINST INTERNAL ATTACKS
# Enable SYN Cookies (already in firewall script, but good redundancy)
sysctl -w net.ipv4.tcp_syncookies=1
# Protect against time-wait assassination
sysctl -w net.ipv4.tcp_rfc1337=1

# Persist settings
echo "Saving to /etc/sysctl.d/99-dns-optimization.conf..."
cat <<EOF > /etc/sysctl.d/99-dns-optimization.conf
net.core.rmem_default=8388608
net.core.rmem_max=16777216
net.core.wmem_default=8388608
net.core.wmem_max=16777216
net.core.netdev_max_backlog=5000
net.core.somaxconn=4096
net.ipv4.ip_local_port_range=1024 65535
vm.swappiness=10
vm.vfs_cache_pressure=50
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
EOF

echo "Kernel Optimization Applied Successfully."
