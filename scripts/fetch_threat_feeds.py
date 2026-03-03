import requests
import os
import re
import subprocess
from datetime import datetime

# Konfigurasi
BLOCKLIST_DIR = "/etc/dnsmasq.d"
COMBINED_FILE = os.path.join(BLOCKLIST_DIR, "external_threats.conf")
TEMP_FILE = "/home/dns/external_threats.tmp"
WHITELIST_FILE = "/etc/dnsmasq.d/whitelist.conf"

# Sumber Feed Terpercaya (Botnet, Malware, Phishing, DDoS Domains)
FEEDS = {
    "URLHaus_Malware": "https://urlhaus.abuse.ch/downloads/hostfile/",
    "Phishing_Army": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "ThreatFox_IOC": "https://threatfox.abuse.ch/downloads/hostfile/",
    "OISD_Small": "https://small.oisd.nl/" # Good balance for ads/trackers/malware
}

def load_whitelist():
    whitelist = set()
    whitelist_file = "/home/dns/whitelist_domains.txt"
    
    if os.path.exists(whitelist_file):
        try:
            with open(whitelist_file, 'r') as f:
                for line in f:
                    dom = line.strip().lower()
                    if dom:
                        whitelist.add(dom)
        except:
            pass
            
    # Fallback / Merge with whitelist.conf just in case
    conf_file = "/etc/dnsmasq.d/whitelist.conf"
    if os.path.exists(conf_file):
        try:
            with open(conf_file, 'r') as f:
                for line in f:
                    match = re.search(r'server=/(.*?)/', line)
                    if match:
                        whitelist.add(match.group(1).lower())
        except:
            pass
            
    return whitelist

def fetch_and_parse():
    print(f"[{datetime.now()}] Starting threat feed update...")
    unique_domains = set()
    whitelist = load_whitelist()
    
    for name, url in FEEDS.items():
        print(f"Downloading {name} from {url}...")
        try:
            # Enforce HTTPS and Verify SSL
            if not url.startswith("https://"):
                print(f"  - SKIPPED {name}: URL must be HTTPS for security.")
                continue
                
            response = requests.get(url, timeout=30, verify=True) # verify=True is default, explicit for clarity
            
            # Integrity Check 1: Status Code
            if response.status_code != 200:
                print(f"  - FAILED {name}: HTTP Status {response.status_code}")
                continue
                
            content = response.text
            
            # Integrity Check 2: Content Validation (Not HTML error page)
            if "<html" in content.lower() or "<!doctype" in content.lower():
                print(f"  - FAILED {name}: Content appears to be HTML (possible captive portal or error page).")
                continue
                
            # Integrity Check 3: Minimum size check
            if len(content) < 100:
                 print(f"  - FAILED {name}: Content too short ({len(content)} bytes).")
                 continue
                 
            lines = content.splitlines()
            count = 0
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse domain depending on format
                # Handle lines starting with IP (0.0.0.0 or 127.0.0.1)
                parts = line.split()
                if not parts:
                    continue
                    
                domain = ""
                if parts[0] in ["0.0.0.0", "127.0.0.1"]:
                    if len(parts) >= 2:
                        domain = parts[1]
                else:
                    domain = parts[0] # Assume first part is domain if not IP
                
                # Clean up domain (Adblock format ||domain^ -> domain)
                domain = domain.replace('||', '').replace('^', '')
                
                # Basic validation
                domain = domain.lower().strip()
                
                # Remove trailing dot
                if domain.endswith('.'):
                    domain = domain[:-1]
                    
                # Filter invalid domains
                # Must contain dot, no slash, no colon, no spaces
                if not domain or '.' not in domain or '/' in domain or ':' in domain:
                    continue
                    
                # Filter non-ascii characters (dnsmasq config safety)
                try:
                    domain.encode('ascii')
                except UnicodeEncodeError:
                    continue
                    
                # Skip whitelisted
                if domain in whitelist:
                    continue
                    
                # Skip whitelisted subdomains check (simple)
                is_whitelisted = False
                parts_dom = domain.split('.')
                for i in range(len(parts_dom)-1):
                    parent = ".".join(parts_dom[i:])
                    if parent in whitelist:
                        is_whitelisted = True
                        break
                
                if is_whitelisted:
                    continue

                unique_domains.add(domain)
                count += 1
            print(f"  - Added {count} domains from {name}")
        except Exception as e:
            print(f"  - Error downloading {name}: {e}")

    # Write to dnsmasq config
    if len(unique_domains) > 1000: # Integrity Check 4: Minimum domains count
        print(f"Writing {len(unique_domains)} unique domains to config...")
        try:
            with open(TEMP_FILE, 'w') as f:
                f.write(f"# Auto-generated threat list at {datetime.now()}\n")
                f.write(f"# Source: Public Threat Feeds (URLHaus, Phishing Army, OISD, etc.)\n")
                f.write(f"# Validated & Filtered against Whitelist\n")
                for domain in unique_domains:
                    f.write(f"address=/{domain}/0.0.0.0\n")
            
            # Atomic move
            subprocess.run(['sudo', 'mv', TEMP_FILE, COMBINED_FILE], check=True)
            
            # Restart dnsmasq
            print("Restarting dnsmasq...")
            subprocess.run(['sudo', 'systemctl', 'restart', 'dnsmasq'], check=True)
            print("Update complete.")
            return True
        except Exception as e:
            print(f"Error writing config: {e}")
            return False
    else:
        print(f"ERROR: Only {len(unique_domains)} domains found. Threshold is 1000. Aborting update to prevent accidental unblocking.")
        return False

if __name__ == "__main__":
    fetch_and_parse()
