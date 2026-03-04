#!/bin/bash
# Sync DNS Configuration to Secondary Server
# Usage: ./sync_to_secondary.sh [SECONDARY_IP]

# Fetch Secondary IP from WebGUI Database (cluster_status table)
DB_PATH="/home/dns/traffic_history.db"
# Use 'sqlite3' to fetch value. Ensure sqlite3 is installed.
DB_IP=$(sqlite3 "$DB_PATH" "SELECT value FROM cluster_status WHERE key='secondary_ip';" 2>/dev/null)

# Use Argument if provided, otherwise use Database IP
if [ -n "$1" ]; then
    SECONDARY_IP="$1"
elif [ -n "$DB_IP" ]; then
    SECONDARY_IP="$DB_IP"
else
    echo "Error: No Secondary IP found in database (cluster_status) or arguments."
    exit 1
fi

SSH_USER="root"
SSH_PORT="22"

# Paths to sync
CONFIG_FILES=(
    "/etc/dnsmasq.conf"
    "/etc/unbound/unbound.conf"
    "/home/dns/whitelist.conf"
)
CONFIG_DIRS=(
    "/etc/dnsmasq.d/"
    "/etc/unbound/unbound.conf.d/"
    "/home/dns/blocklists/"
)

echo "[$(date)] Starting Sync to Secondary ($SECONDARY_IP)..."

# Sync Individual Files
for FILE in "${CONFIG_FILES[@]}"; do
    if [ -f "$FILE" ]; then
        echo "Syncing $FILE..."
        rsync -avz -e "ssh -p $SSH_PORT" "$FILE" "$SSH_USER@$SECONDARY_IP:$FILE"
    fi
done

# Sync Directories
for DIR in "${CONFIG_DIRS[@]}"; do
    if [ -d "$DIR" ]; then
        echo "Syncing $DIR..."
        rsync -avz --delete -e "ssh -p $SSH_PORT" "$DIR" "$SSH_USER@$SECONDARY_IP:$DIR"
    fi
done

# Fix IPs on Secondary (Replace Primary IP with Secondary IP)
echo "Fixing IPs in configuration files on Secondary..."
ssh -p $SSH_PORT "$SSH_USER@$SECONDARY_IP" "sudo grep -rl '103.68.213.74' /etc/dnsmasq.d/ /etc/unbound/unbound.conf.d/ | xargs -r sudo sed -i 's/103.68.213.74/$SECONDARY_IP/g'"

# Ensure Local Resolver on Secondary
echo "Enforcing Local Resolver (127.0.0.1) on Secondary..."
ssh -p $SSH_PORT "$SSH_USER@$SECONDARY_IP" "echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf > /dev/null"

# Reload Services on Secondary after IP fix
echo "Reloading services on Secondary..."
# Use try-reload-or-restart to avoid dropping active connections on client side
ssh -p $SSH_PORT "$SSH_USER@$SECONDARY_IP" "sudo systemctl try-reload-or-restart unbound dnsmasq"

echo "[$(date)] Sync Completed!"
