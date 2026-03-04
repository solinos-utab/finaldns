#!/bin/bash
# Script Auto-Update Database Blokir (Hagezi Edition with Overlap Removal)
# 1. Malware/Adware (Hagezi Pro) - Cleaned of any Porn/Gambling domains
# 2. Porn/Gambling (Hagezi Gambling + NSFW) - Managed via Internet Positif Toggle

export LC_ALL=C

SERVER_IP="103.68.213.74"
MALWARE_TARGET="/etc/dnsmasq.d/malware.conf"
PORN_TARGET="/etc/dnsmasq.d/internet_positif.conf"
PORN_DISABLED="/home/dns/blocklists/disabled/internet_positif.conf"

# Ensure disabled directory exists
mkdir -p /home/dns/blocklists/disabled

# Cleanup temp files from previous runs to avoid permission issues
rm -f /tmp/malware_raw /tmp/malware_sorted /tmp/malware_final /tmp/malware_filtered /tmp/malware_filtered_1 /tmp/whitelist_domains.txt
rm -f /tmp/gambling_raw /tmp/nsfw_raw /tmp/porn_sorted

echo "[$(date)] Memulai update database blokir (Hagezi Cleaned)..."

download_convert() {
    local url="$1"
    local output="$2"
    echo "Downloading $url..."
    
    # Validation: Check status code and size
    if ! curl -s -f -o "/tmp/download_temp" "$url"; then
        echo "Error: Download failed for $url. Skipping..."
        return 1
    fi
    
    if [ ! -s "/tmp/download_temp" ]; then
        echo "Error: Downloaded file is empty for $url. Skipping..."
        return 1
    fi
    
    # Validation: Check for HTML error page (case insensitive)
    if grep -q -iE "<html|<!doctype" "/tmp/download_temp"; then
        echo "Error: Downloaded file appears to be HTML (captive portal/error). Skipping..."
        return 1
    fi

    # Convert to dnsmasq format
    cat "/tmp/download_temp" | \
        grep "^local=/" | \
        sed "s|^local=/|address=/|; s|/$|/$SERVER_IP|" > "$output"
        
    # Validation: Check output line count
    local lines
    if [ -f "$output" ]; then
        lines=$(wc -l < "$output")
    else
        lines=0
    fi
    
    if [ "$lines" -lt 100 ]; then
        echo "Error: Converted list is too short ($lines lines). Integrity check failed."
        return 1
    fi
    
    echo "Success: Downloaded and converted $lines domains."
    rm -f "/tmp/download_temp"
}

# --- 1. DOWNLOAD RAW LISTS ---
echo "[$(date)] Downloading lists..."

# Download Malware (Hagezi Pro)
download_convert "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/pro.txt" "/tmp/malware_raw"

# Download Gambling
download_convert "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/gambling.txt" "/tmp/gambling_raw"

# Download NSFW
download_convert "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/nsfw.txt" "/tmp/nsfw_raw"

# --- 2. PREPARE PORN/GAMBLING LIST ---
echo "[$(date)] Merging and sorting Porn/Gambling list..."
cat "/tmp/gambling_raw" "/tmp/nsfw_raw" | sort | uniq > "/tmp/porn_sorted"

# --- 3. PREPARE MALWARE LIST (REMOVE OVERLAPS & WHITELIST) ---
echo "[$(date)] Processing Malware list (removing overlaps and whitelist)..."
sort "/tmp/malware_raw" | uniq > "/tmp/malware_sorted"

# Define Comprehensive Whitelist Pattern (Meta, Apple, Google, Infrastructure)
WHITELIST_PATTERN="facebook|instagram|whatsapp|fbcdn|fb\.me|cdninstagram|messenger|oculus|wa\.me|whatsapp\.biz|facebook\.net|tfbnw\.net|fbsbx\.com|fb\.com|messenger\.com|apple\.com|icloud|itunes|mzstatic|aaplimg|apple-dns|google|gstatic|googleapis|msftconnecttest|msftncsi|connectivitycheck|captive\.apple\.com|akamai|cloudfront|fastly|netseer|ipaddr-assoc"

# Extract domains using Python script (Syncs with Smart Whitelist & Custom Trust)
echo "[$(date)] Syncing Whitelist (Smart Whitelist + Custom Trust)..."
python3 /home/dns/scripts/sync_whitelist.py

# Fetch Global Threat Feeds (URLHaus, Phishing Army, etc.)
echo "[$(date)] Fetching Global Threat Feeds..."
python3 /home/dns/scripts/fetch_threat_feeds.py

# Use the permanent file for processing
cp "/home/dns/whitelist_domains.txt" "/tmp/whitelist_domains.txt"

# Filter out whitelisted domains from Malware sorted
# 1. Filter using Regex Pattern
grep -Ev "$WHITELIST_PATTERN" "/tmp/malware_sorted" > "/tmp/malware_filtered_1"

# 2. Filter using whitelist.conf domains
if [ -s "/tmp/whitelist_domains.txt" ]; then
    # Create regex patterns for grep -E -v -f
    # We want to match domain.com and *.domain.com
    # In dnsmasq format: address=/.../
    # So we match: /domain.com/ OR .domain.com/
    # Regex: (/|\.)domain\.com/
    
    # 1. Escape dots: . -> \.
    # 2. Add regex boundaries
    # Use # as delimiter because replacement string contains |
    sed 's/\./\\./g; s#^#(/|\\.)#; s#$#/# ' "/tmp/whitelist_domains.txt" > "/home/dns/whitelist_regex.txt"
    
    grep -E -v -f "/home/dns/whitelist_regex.txt" "/tmp/malware_filtered_1" > "/tmp/malware_filtered"
    # Keep the regex file for guardian.py use
else
    mv "/tmp/malware_filtered_1" "/tmp/malware_filtered"
    # Create empty regex file if no whitelist
    touch "/home/dns/whitelist_regex.txt"
fi

# Comm -23: Lines in malware_filtered but NOT in porn_sorted
comm -23 "/tmp/malware_filtered" "/tmp/porn_sorted" > "/tmp/malware_final"

# --- 4. DEPLOY MALWARE LIST ---
if [ -f "/etc/dnsmasq.d/malware.conf.disabled" ]; then
    echo "[$(date)] Malware list is DISABLED by user. Skipping update."
    rm -f "/tmp/malware_final"
elif [ -s "/tmp/malware_final" ]; then
    sudo mv "/tmp/malware_final" "$MALWARE_TARGET"
    echo "[$(date)] Malware list updated (Overlap cleaned)."
else
    echo "[$(date)] Error: Malware list empty!"
fi

# --- 5. DEPLOY PORN/GAMBLING LIST ---
if [ -s "/tmp/porn_sorted" ]; then
    # ALWAYS update the disabled/master copy first
    # This ensures we have the latest source for update_trust_list.py
    cp "/tmp/porn_sorted" "$PORN_DISABLED"
    echo "[$(date)] Porn/Gambling list master copy updated."

    # Check current status: Active?
    if [ -f "$PORN_TARGET" ]; then
        # Currently Active -> Run update_trust_list.py to filter and install
        echo "[$(date)] Updating active Porn/Gambling list (applying whitelist)..."
        /usr/bin/python3 /home/dns/scripts/update_trust_list.py
        if [ $? -eq 0 ]; then
             echo "[$(date)] Active list updated successfully."
        else
             echo "[$(date)] Error updating active list."
        fi
    else
        echo "[$(date)] Porn/Gambling list is disabled. Master copy updated only."
    fi
else
    echo "[$(date)] Error: Porn/Gambling list empty!"
fi

# --- 6. CLEANUP & RESTART ---
rm -f /tmp/malware_raw /tmp/malware_sorted /tmp/malware_final
rm -f /tmp/gambling_raw /tmp/nsfw_raw /tmp/porn_sorted

# --- 7. EXTERNAL THREAT FEEDS (Botnet, DDoS, Phishing) ---
echo "[$(date)] Updating External Threat Feeds..."
sudo python3 /home/dns/scripts/fetch_threat_feeds.py

# Safety: Remove any stray .disabled files in active directory to prevent ghost blocks
# rm -f /etc/dnsmasq.d/*.disabled

# --- 8. AUTO-SANITIZER (Remove False Positives) ---
echo "[$(date)] Running Auto-Sanitizer (Protecting Official Domains)..."
sudo python3 /home/dns/sanitize_blocklists.py

# Use try-reload-or-restart to be safer and more efficient than a hard restart
sudo systemctl try-reload-or-restart dnsmasq
echo "[$(date)] Update selesai. Malware list bersih dari domain porno/judi."
