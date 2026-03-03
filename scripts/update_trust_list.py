#!/usr/bin/env python3
import os
import re
import sys
import shutil

# Paths
BLOCKLIST_SOURCE = '/home/dns/blocklists/disabled/internet_positif.conf'
BLOCKLIST_DEST = '/etc/dnsmasq.d/internet_positif.conf'
CUSTOM_TRUST = '/home/dns/blocklists/custom_trust.txt'
SYSTEM_WHITELIST = '/home/dns/blocklists/system_whitelist.txt'

def load_whitelist():
    whitelist = set()
    
    # Load System Whitelist
    if os.path.exists(SYSTEM_WHITELIST):
        try:
            with open(SYSTEM_WHITELIST, 'r') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain and not domain.startswith('#'):
                        whitelist.add(domain)
        except Exception as e:
            print(f"Error reading system whitelist: {e}")

    # Load Custom Trust (User Whitelist)
    if os.path.exists(CUSTOM_TRUST):
        try:
            with open(CUSTOM_TRUST, 'r') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain and not domain.startswith('#'):
                        whitelist.add(domain)
        except Exception as e:
            print(f"Error reading custom trust: {e}")
            
    return whitelist

def process_blocklist():
    if not os.path.exists(BLOCKLIST_SOURCE):
        print(f"Source blocklist not found: {BLOCKLIST_SOURCE}")
        return False

    whitelist = load_whitelist()
    print(f"Loaded {len(whitelist)} whitelisted domains.")
    
    # Pre-compile whitelist for faster lookup (handle subdomains)
    # We will check exact match and parent domains
    # Optimization: whitelist is a set.
    
    # Regex to extract domain from: address=/domain/ip
    # Optimized regex
    pattern = re.compile(r'address=/(.*?)/')
    
    lines_kept = 0
    lines_removed = 0
    
    try:
        # Write to a temporary file in user directory first (to avoid permission issues)
        temp_file = '/home/dns/internet_positif.conf.tmp'
        
        with open(BLOCKLIST_SOURCE, 'r', encoding='utf-8', errors='ignore') as src, \
             open(temp_file, 'w', encoding='utf-8') as dst:
            
            for line in src:
                # Fast check: if line is empty or comment
                if not line.startswith('address=/'):
                    dst.write(line)
                    continue
                
                # Extract domain
                # address=/example.com/1.2.3.4
                # split by '/' is faster than regex
                parts = line.split('/')
                if len(parts) >= 2:
                    domain = parts[1].lower()
                    
                    # Check if domain is whitelisted
                    if domain in whitelist:
                        lines_removed += 1
                        continue
                    
                    # Check parent domains (e.g. cdn.ea.com -> check ea.com)
                    d_parts = domain.split('.')
                    if len(d_parts) > 1:
                        # Check root domain (last 2 parts)
                        if len(d_parts) >= 2:
                            root = '.'.join(d_parts[-2:])
                            if root in whitelist:
                                lines_removed += 1
                                continue
                        
                        # Check 3 parts
                        if len(d_parts) >= 3:
                            root3 = '.'.join(d_parts[-3:])
                            if root3 in whitelist:
                                lines_removed += 1
                                continue
                                
                    # If we got here, write the line
                    dst.write(line)
                    lines_kept += 1
                else:
                    dst.write(line)

        # Move temp file to dest using sudo (NOPASSWD allowed for mv)
        print(f"Blocklist filtered. Kept: {lines_kept}, Removed: {lines_removed}")
        
        # Use sudo mv to move the file to /etc/dnsmasq.d/
        cmd = f"sudo mv {temp_file} {BLOCKLIST_DEST}"
        ret = os.system(cmd)
        if ret != 0:
            print(f"Error moving file to {BLOCKLIST_DEST}")
            return False
            
        return True

    except Exception as e:
        print(f"Error processing blocklist: {e}")
        if os.path.exists('/home/dns/internet_positif.conf.tmp'):
            os.remove('/home/dns/internet_positif.conf.tmp')
        return False

if __name__ == "__main__":
    if process_blocklist():
        # Verify Config Only
        print("Verifying Dnsmasq config...")
        if os.system("sudo dnsmasq --test") == 0:
            print("Config OK.")
            # Service restart is handled by the caller (app.py)
            sys.exit(0)
        else:
            print("Config Check Failed!")
            sys.exit(1)
    else:
        sys.exit(1)
