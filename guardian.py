import os
import time
import subprocess
import re
import sqlite3
from datetime import datetime

import json

# --- CONFIGURATION ---
LOG_FILE = "/var/log/syslog"
DNSMASQ_LOG = "/var/log/dnsmasq.log"
NGINX_LOG = "/var/log/nginx/access.log"
CONFIG_FILE = "/home/dns/guardian_config.json"
GUARDIAN_LOG = "/home/dns/guardian.log"

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}\n"
    try:
        with open(GUARDIAN_LOG, "a") as f:
            f.write(formatted_msg)
    except:
        pass
    print(formatted_msg.strip())

# Default values
DEFAULT_BAN_THRESHOLD = 20000
DEFAULT_MALICIOUS_THRESHOLD = 5000  # Increased to 5000 to prevent false positives on heavy users/offices
DEFAULT_LIMIT_QUERY_PER_MIN = 10000000 # Increased default to avoid blocking legit traffic if config fails
DEFAULT_LIMIT_HIT_THRESHOLD = 0 # Disabled by default
DEFAULT_BLOCKING_ENABLED = True
DISK_CRITICAL_THRESHOLD = 80  # Percent
MEM_CRITICAL_THRESHOLD = 90   # Percent
SWAP_CRITICAL_THRESHOLD = 60  # Percent
CPU_CRITICAL_THRESHOLD = 95   # Percent

GAMING_WHITELIST = {
    # --- PC Stores & Launchers ---
    "steampowered.com", "steamcommunity.com", "steamserver.net", "valve.net", "steamcontent.com", "steamstatic.com", "steam-chat.com",
    "ubisoft.com", "ubi.com", "uplay.com", "ubisoftconnect.com",
    "ea.com", "origin.com", "electronicarts.com", "battle.net", "blizzard.com", "battle.net", "battlenet.com",
    "dm.origin.com", "api.origin.com", "accounts.ea.com", "signin.ea.com",
    "gosredirector.ea.com", "river.data.ea.com", "pin-river.data.ea.com", "ea-common.ea.com",
    "epicgames.com", "unrealengine.com", "epicgames.dev",
    "gog.com", "cdprojektred.com",
    "itch.io",
    "riotgames.com", "leagueoflegends.com", "valorant.com", "riotcdn.net",
    "roblox.com", "rbxcdn.com", "roblox.cn",
    "minecraft.net", "mojang.com",
    "pubg.com", "krafton.com",
    "activision.com", "callofduty.com",
    "rockstargames.com", "take2games.com",
    "bungie.net",
    "warframe.com", "digitalextremes.com",
    "pathofexile.com", "grindinggear.com",
    "escapefromtarkov.com", "battlestategames.com",
    "wargaming.net", "worldoftanks.com", "worldofwarships.com",
    "garena.com", "garena.co.id", "freefiremobile.com",
    
    # --- Consoles ---
    "xbox.com", "xboxlive.com", "microsoft.com", "msftncsi.com", "microsoftonline.com", "office.com", "windows.net",
    "playstation.com", "playstation.net", "sonyentertainmentnetwork.com", "sony.com",
    "nintendo.com", "nintendo.net", "nintendo.co.jp",
    
    # --- Mobile / Cross-Platform ---
    "supercell.com", "clashofclans.com", "clashroyale.com", "brawlstars.com",
    "hoyoverse.com", "mihoyo.com", "genshinimpact.com", "honkaistarrail.com", "zenlesszonezero.com",
    "unity3d.com", "unity.com",
    "photonengine.com",
    "mobilelegends.com", "moonton.com",
    "pubgmobile.com",
    "tencent.com", "levelinfinite.com",
    "netease.com", "163.com",
    "gameloft.com",
    "zynga.com",
    "king.com",
    "nianticlabs.com", "pokemongolive.com",
    
    # --- Anti-Cheat & Security ---
    "easyanticheat.net", "easyanticheat.com",
    "battleye.com",
    "vanguard.com", # Riot Vanguard often uses riotgames.com but listing for safety
    "denuvo.com",
    "wellbia.com", "xigncode.com",
    
    # --- Social / Voice ---
    "discord.com", "discordapp.com", "discord.gg", "discordapp.net",
    "teamspeak.com", "mumble.info",
    "twitch.tv", "ttvnw.net",
    
    # --- Major Publishers (catch-all) ---
    "bandainamcoent.com", "bandainamco.co.jp",
    "capcom.com", "capcom-unity.com",
    "square-enix.com", "square-enix-games.com",
    "sega.com", "sega.co.jp",
    "konami.com",
    "bethesda.net",
    "2k.com",
    "wbplay.com", "wbgames.com"
}

def load_config():
    config = {
        "ban_threshold": DEFAULT_BAN_THRESHOLD,
        "malicious_threshold": DEFAULT_MALICIOUS_THRESHOLD,
        "blocking_enabled": DEFAULT_BLOCKING_ENABLED,
        "limit_query_per_min": DEFAULT_LIMIT_QUERY_PER_MIN,
        "limit_hit_threshold": DEFAULT_LIMIT_HIT_THRESHOLD,
        "disk_threshold": DISK_CRITICAL_THRESHOLD,
        "mem_threshold": MEM_CRITICAL_THRESHOLD,
        "swap_threshold": SWAP_CRITICAL_THRESHOLD
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                loaded = json.load(f)
                config.update(loaded)
        except Exception as e:
            # print(f"Error loading config: {e}")
            # log_event(f"Error loading config: {e}")
            pass
    
    # log_event(f"Config loaded: LIMIT={config['limit_query_per_min']}, MALICIOUS={config['malicious_threshold']}, BLOCKING={config['blocking_enabled']}")
    return config

# Load initial config
config = load_config()
BAN_THRESHOLD = config["ban_threshold"]
# Prefer abnormal_query_per_min if available for the "Abnormal" threshold
MALICIOUS_THRESHOLD = config.get("abnormal_query_per_min", config["malicious_threshold"])
LIMIT_QUERY_PER_MIN = config.get("limit_query_per_min", DEFAULT_LIMIT_QUERY_PER_MIN)
LIMIT_HIT_THRESHOLD = config.get("limit_hit_threshold", DEFAULT_LIMIT_HIT_THRESHOLD)
BLOCKING_ENABLED = config.get("blocking_enabled", True)
DISK_THRESHOLD = config.get("disk_threshold", DISK_CRITICAL_THRESHOLD)
MEM_THRESHOLD = config.get("mem_threshold", MEM_CRITICAL_THRESHOLD)
SWAP_THRESHOLD = config.get("swap_threshold", SWAP_CRITICAL_THRESHOLD)

# Log initial config once on startup
log_event(f"Guardian initial config: LIMIT={LIMIT_QUERY_PER_MIN}, MALICIOUS={MALICIOUS_THRESHOLD}, BLOCKING={BLOCKING_ENABLED}")

WHITELIST_FILE = "/home/dns/whitelist.conf"
WHITELIST_DOMAINS_FILE = "/home/dns/whitelist_domains.txt"
BANNED_IPS_FILE = "/home/dns/banned_ips.txt"

def load_whitelist():
    wl = ["127.0.0.1"]
    subnets = []
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '/' in line:
                        subnets.append(line)
                    else:
                        wl.append(line)
        except Exception as e:
            print(f"Error loading whitelist: {e}")
    return wl, subnets

def load_domain_whitelist():
    domains = set()
    if os.path.exists(WHITELIST_DOMAINS_FILE):
        try:
            with open(WHITELIST_DOMAINS_FILE, 'r') as f:
                for line in f:
                    dom = line.strip().lower()
                    if dom:
                        domains.add(dom)
        except Exception as e:
            print(f"Error loading domain whitelist: {e}")
    return domains

# Global variables
WHITELIST, WHITELIST_SUBNETS = load_whitelist()
WHITELIST_DOMAINS = load_domain_whitelist()
LAST_WL_RELOAD = time.time()

def reload_whitelist_if_needed():
    global WHITELIST, WHITELIST_SUBNETS, WHITELIST_DOMAINS, LAST_WL_RELOAD, BAN_THRESHOLD, MALICIOUS_THRESHOLD, BLOCKING_ENABLED, LIMIT_QUERY_PER_MIN, LIMIT_HIT_THRESHOLD, DISK_THRESHOLD, MEM_THRESHOLD, SWAP_THRESHOLD
    # Reload frequently (every 5 seconds) to make whitelist changes feel instant
    if time.time() - LAST_WL_RELOAD > 5:
        WHITELIST, WHITELIST_SUBNETS = load_whitelist()
        WHITELIST_DOMAINS = load_domain_whitelist()
        
        # Reload Config
        # config = load_config()
        # BAN_THRESHOLD = config.get("ban_threshold", BAN_THRESHOLD)
        # Consistent with initial load: prefer abnormal_query_per_min, fallback to malicious_threshold
        # MALICIOUS_THRESHOLD = config.get("abnormal_query_per_min", config.get("malicious_threshold", 5000))
        # LIMIT_QUERY_PER_MIN = config.get("limit_query_per_min", DEFAULT_LIMIT_QUERY_PER_MIN)
        # LIMIT_HIT_THRESHOLD = config.get("limit_hit_threshold", DEFAULT_LIMIT_HIT_THRESHOLD)
        # BLOCKING_ENABLED = config.get("blocking_enabled", True)
        # DISK_THRESHOLD = config.get("disk_threshold", DISK_CRITICAL_THRESHOLD)
        # MEM_THRESHOLD = config.get("mem_threshold", MEM_CRITICAL_THRESHOLD)
        # SWAP_THRESHOLD = config.get("swap_threshold", SWAP_CRITICAL_THRESHOLD)
        
        LAST_WL_RELOAD = time.time()
        
        # Clean up banned_ips.txt if needed
        clean_banned_ips()

def clean_banned_ips():
    if not os.path.exists(BANNED_IPS_FILE):
        return
    
    try:
        with open(BANNED_IPS_FILE, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
        
        valid_ips = []
        changed = False
        for ip in ips:
            if is_whitelisted(ip):
                log_event(f"Removing whitelisted IP from banned list: {ip}")
                # Remove from iptables too
                run_cmd(f"sudo iptables -D INPUT -s {ip} -j DROP")
                changed = True
            else:
                valid_ips.append(ip)
        
        if changed:
            # Write back unique valid IPs
            unique_ips = list(set(valid_ips))
            with open(BANNED_IPS_FILE, 'w') as f:
                for ip in unique_ips:
                    f.write(f"{ip}\n")
    except Exception as e:
        log_event(f"Error cleaning banned IPs: {e}")

def is_whitelisted(ip):
    # Check individual IPs
    if ip in WHITELIST:
        return True
    
    # Check subnets
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        for subnet in WHITELIST_SUBNETS:
            if ip_obj in ipaddress.ip_network(subnet):
                return True
    except Exception:
        pass
        
    return False

APP_WHITELIST = {
    # --- Learning ---
    "duolingo.com", "zombie.duolingo.com",
    
    # --- Mobile / App Stores ---
    "vivo.com", "vivo.com.cn", "appstore.vivo.com.cn",
    "hicloud.com", "huawei.com", "huaweicloud.com",
    "oppo.com", "heytap.com",
    "xiaomi.com", "mi.com", "xiaomi.net",
    
    # --- Cloud / Infrastructure ---
    "googleapis.com", "googleusercontent.com", "appspot.com", "run.app",
    "alibabachengdun.com", "alibaba.com", "alicdn.com",
    "amazon.com", "amazonaws.com",
    "cloudflare.com", "cloudflare.net",
    "fastly.net", "fastly.com",
    "akamai.net", "akamaized.net",
    
    # --- Analytics / Ads (often false positives for games/apps) ---
    "adjust.com", "appsflyer.com",
    "unity3d.com", "unityads.unity3d.com",
    "vungle.com",
    "applovin.com",
    "ironsrc.com",
    
    # --- Kids / Edu ---
    "babybus.com",
    "outfit7.com", "talkingtom.com",
    
    # --- Misc reported false positives ---
    "v2z.ru",
    "ycxrl.com",
    "ksztone.com",
    "vbnmhjlp.com"
}

def is_domain_whitelisted(domain):
    domain = domain.lower()
    
    # 0. Check Gaming Whitelist (High Priority)
    for game_dom in GAMING_WHITELIST:
        if domain == game_dom or domain.endswith("." + game_dom):
            return True

    # 0.1 Check App Whitelist (High Priority)
    for app_dom in APP_WHITELIST:
        if domain == app_dom or domain.endswith("." + app_dom):
            return True

    # 1. Check if explicitly whitelisted
    if domain in WHITELIST_DOMAINS:
        return True
    
    # 2. Check parent domains
    parts = domain.split('.')
    for i in range(len(parts)-1):
        parent = ".".join(parts[i:])
        if parent in WHITELIST_DOMAINS:
            return True
            
    # 3. Check for Private Reverse Lookups (in-addr.arpa)
    if domain.endswith('.in-addr.arpa'):
        try:
            # Extract IP parts: 1.1.168.192.in-addr.arpa -> 192.168.1.1
            ip_parts = domain.replace('.in-addr.arpa', '').split('.')
            if len(ip_parts) >= 4:
                # Handle subdomains like lb._dns-sd._udp.0.1.168.192.in-addr.arpa
                # We need to find the 4 IP octets at the end of the reverse string (which is the beginning of the domain string)
                # Actually, in-addr.arpa is reversed. 
                # lb._dns-sd._udp.0.1.168.192.in-addr.arpa 
                # The IP part is 0.1.168.192 -> 192.168.1.0 (This is a network, not a host)
                # Let's just check if any part of it looks like a private IP subnet
                
                # Simpler approach: Check if it contains private IP segments in reverse
                # 192.168.x.x -> x.x.168.192.in-addr.arpa
                # 10.x.x.x -> x.x.x.10.in-addr.arpa
                # 172.16-31.x.x -> x.x.16-31.172.in-addr.arpa
                
                if '168.192.in-addr.arpa' in domain: return True
                if '10.in-addr.arpa' in domain: return True
                
                # 172.16.0.0/12 check is harder with string matching, let's try strict parsing if possible
                # But for now, covering 192.168 and 10 is 99% of home/office use cases
                if re.search(r'(1[6-9]|2[0-9]|3[0-1])\.172\.in-addr\.arpa', domain): return True
                
        except:
            pass
            
    # 4. SAFETY NET - CRITICAL INFRASTRUCTURE (Hardcoded)
    # Prevents blocking of major services regardless of load
    SAFETY_NET_DOMAINS = [
        "google.com", "google.co.id", "googleapis.com", "gstatic.com", "youtube.com", "googlevideo.com",
        "facebook.com", "fbcdn.net", "whatsapp.com", "whatsapp.net", "instagram.com",
        "apple.com", "icloud.com", "cdn-apple.com", "mzstatic.com",
        "microsoft.com", "windows.com", "windowsupdate.com", "azure.com", "office.com", "live.com",
        "amazon.com", "amazonaws.com",
        "cloudflare.com",
        "netflix.com", "nflxvideo.net",
        "zoom.us",
        "go.id", "kemdikbud.go.id", # Indonesia Govt
        "mdnet.co.id", # User domain
        "tiktok.com", "tiktokcdn.com",
        "shopee.co.id", "tokopedia.com",
        "gsu.edu" # Specifically mentioned in logs as false positive
    ]
    
    for safe_dom in SAFETY_NET_DOMAINS:
        if domain == safe_dom or domain.endswith("." + safe_dom):
            return True

    return False

def get_current_ip():
    try:
        # Try default route interface first (most accurate)
        cmd = "ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+'"
        res = run_cmd(cmd)
        if res and res.stdout.strip():
            return res.stdout.strip()

        # Fallback to looking for the first non-loopback IPv4 address
        cmd = "ip -4 addr show | grep inet | grep -v '127.0.0.1' | head -n1 | awk '{print $2}' | cut -d/ -f1"
        res = run_cmd(cmd)
        if res and res.stdout.strip():
            return res.stdout.strip()
    except:
        pass
    return "127.0.0.1"

def get_current_ipv6():
    try:
        # Get first global IPv6
        cmd = "ip -6 addr show | grep -v 'fe80' | grep -v '::1' | grep 'inet6' | awk '{print $2}' | cut -d/ -f1 | head -n1"
        res = run_cmd(cmd)
        if res and res.stdout.strip():
            return res.stdout.strip()
    except:
        pass
    return None

# Global variables
WHITELIST, WHITELIST_SUBNETS = load_whitelist()
LAST_WL_RELOAD = time.time()
LAST_IP_V4 = get_current_ip()
LAST_IP_V6 = get_current_ipv6()
server_ip = LAST_IP_V4

# Auto-update whitelist with current server IPs
if LAST_IP_V4 not in WHITELIST:
    WHITELIST.append(LAST_IP_V4)
if LAST_IP_V6 and LAST_IP_V6 not in WHITELIST:
    WHITELIST.append(LAST_IP_V6)

# --- SCHEDULE STATE TRACKING ---
TRUST_CONF = "/etc/dnsmasq.d/upstream.conf"
LAST_SCHEDULE_STATE = None  # Track last schedule state to detect changes

def run_cmd(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True)
    except Exception as e:
        return None

def block_ip(ip):
    # Always reload/check before blocking to be sure
    global WHITELIST, WHITELIST_SUBNETS
    WHITELIST, WHITELIST_SUBNETS = load_whitelist()
    
    if is_whitelisted(ip):
        log_event(f"SKIP BLOCKING whitelisted IP: {ip}")
        return
    
    # Check if already blocked to avoid duplicates
    if os.path.exists(BANNED_IPS_FILE):
        with open(BANNED_IPS_FILE, 'r') as f:
            if ip in f.read():
                return

    log_event(f"BLOCKING IP {ip}...")
    run_cmd(f"sudo iptables -I INPUT -s {ip} -j DROP")
    # Append to file
    with open(BANNED_IPS_FILE, 'a') as f:
        f.write(f"{ip}\n")

# --- LOG ANALYSIS ---
def parse_log_time(log_line):
    try:
        # Syslog format: Feb 19 14:00:01
        ts_str = log_line[:15]
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        return dt.replace(year=datetime.now().year)
    except:
        return None

def block_domain_guardian(domain):
    blacklist_file = "/etc/dnsmasq.d/blacklist.conf"
    try:
        if os.path.exists(blacklist_file):
            with open(blacklist_file, 'r') as f:
                if f"/{domain}/" in f.read():
                    return

        with open(blacklist_file, 'a') as f:
            f.write(f"\naddress=/{domain}/0.0.0.0\n")
        
        log_event(f"BLOCKED DOMAIN: {domain} (High Frequency Attack)")
        run_cmd("systemctl reload dnsmasq")
    except Exception as e:
        log_event(f"Error blocking domain {domain}: {e}")

def analyze_logs():
    # Detect DNS attacks from syslog/dnsmasq.log
    # Uses Time-Based Window (Last 60 Seconds)
    
    any_query_stats = {} # Track ANY queries: { ip: { domain: count } }
    
    try:
        if os.path.exists(DNSMASQ_LOG):
            # Read enough lines to cover 1 minute of heavy traffic (10k lines)
            cmd = f"tail -n 10000 {DNSMASQ_LOG}"
            res = run_cmd(cmd)
            if res and res.stdout:
                lines = res.stdout.splitlines()
                now = datetime.now()
                one_min_ago = now.timestamp() - 60
                
                recent_lines = []
                for line in lines:
                    dt = parse_log_time(line)
                    if dt and dt.timestamp() >= one_min_ago:
                        recent_lines.append(line)
                
                # Analyze recent lines (last 60s)
                for line in recent_lines:
                    # Capture Query Type, Domain, and IP
                    # Example: Mar  3 19:16:26 dnsmasq[1806644]: query[ANY] dhitc.com from 103.68.213.52
                    match_query = re.search(r'query\[(\w+)\] (.*) from ([\d\.]+)', line)
                    if match_query:
                        qtype = match_query.group(1).upper()
                        domain = match_query.group(2).lower()
                        ip = match_query.group(3)
                        
                        if qtype == "ANY":
                            if ip not in any_query_stats:
                                any_query_stats[ip] = {}
                            any_query_stats[ip][domain] = any_query_stats[ip].get(domain, 0) + 1

    except Exception as e:
        log_event(f"Error analyzing logs: {e}")
    
    # PER-IP ANY QUERY LIMIT: 50/s = 3000/min
    LIMIT_PER_MIN = 3000 
    
    for ip, domains in any_query_stats.items():
        for domain, count in domains.items():
            if count >= LIMIT_PER_MIN:
                log_event(f"ANY ATTACK DETECTED: IP {ip} sent {count} ANY queries for {domain} in 1 min (>50/s).")
                log_event(f"ACTION: Blocking domain {domain} globally.")
                block_domain_guardian(domain)
                # Note: We only block the domain to prevent amplification, 
                # but we could also block the IP if needed by calling block_ip(ip).
                # For now, following "block domain with query ANY" request.

    # 2. Other limits and IP blocking are DISABLED per user request
    # Only ANY query domain blocking and "Internet Positif" (via dnsmasq conf) are active.


# --- SELF-HEALING LOGIC ---
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB

def rotate_logs():
    if os.path.exists(GUARDIAN_LOG) and os.path.getsize(GUARDIAN_LOG) > MAX_LOG_SIZE:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        os.rename(GUARDIAN_LOG, f"{GUARDIAN_LOG}.{timestamp}")
        log_event("Guardian log rotated.")

def is_port_listening(port, proto="tcp", addr_part=":"):
    # Use ss to check if port is listening
    # Add space after port to ensure exact match (e.g. avoid matching 5353 when looking for 53)
    # Also handle IPv6 format where address might be [::1]:53
    
    # If checking for localhost specifically
    if addr_part == "127.0.0.1:":
         cmd = f"ss -lntu | grep '{addr_part}{port} ' | grep -i '{proto}'"
    else:
         # Generic check (matches 0.0.0.0:port, 127.0.0.1:port, [::]:port, etc)
         cmd = f"ss -lntu | grep ':{port} ' | grep -i '{proto}'"
         
    res = run_cmd(cmd)
    return res and res.stdout.strip() != ""

def is_dns_trust_enabled():
    """
    Check if DNS Trust (Internet Positif) is enabled by checking if the local blocklist file exists.
    """
    blocklist_file = "/etc/dnsmasq.d/internet_positif.conf"
    return os.path.exists(blocklist_file)

def sync_blocking_config(dns_trust):
    # Check global blocking enabled status
    config = load_config()
    blocking_enabled = config.get("blocking_enabled", True)

    blocking_files = [
        "/etc/dnsmasq.d/alias.conf",
        "/etc/dnsmasq.d/blacklist.conf",
        "/etc/dnsmasq.d/malware.conf",
        "/etc/dnsmasq.d/malware_test.conf"
    ]
    
    changed = False
    for file_path in blocking_files:
        if not os.path.exists(file_path):
            continue
            
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            new_lines = []
            file_changed = False
            
            for line in lines:
                clean_line = line.strip()
                
                # Logic for Global Disable
                if not blocking_enabled:
                    # Comment out any active rule
                    if clean_line.startswith(('address=', 'alias=')):
                        new_lines.append('# ' + line)
                        file_changed = True
                    else:
                        new_lines.append(line)
                    continue

                # Logic for Global Enable (Original Logic)
                # Skip comments that are headers or empty lines
                if not clean_line or (clean_line.startswith('#') and not clean_line[1:].strip().startswith(('address=', 'alias='))):
                    new_lines.append(line)
                    continue
                
                if clean_line.startswith('#'):
                    rule_content = clean_line[1:].strip()
                    if rule_content.startswith(('address=', 'alias=')):
                        new_lines.append(line.lstrip('#').lstrip())
                        file_changed = True
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            
            if file_changed:
                with open(file_path, 'w') as f:
                    f.writelines(new_lines)
                log_event(f"Config {file_path} synchronized with Blocking Status ({'ENABLED' if blocking_enabled else 'DISABLED'})")
                changed = True
        except Exception as e:
            log_event(f"Error syncing {file_path}: {e}")
            
    if changed:
        log_event("Reloading dnsmasq to apply Blocking sync changes...")
        run_cmd("sudo systemctl reload dnsmasq")

def is_dns_resolving():
    # Try to resolve a common domain via localhost
    try:
        res = run_cmd("dig @127.0.0.1 google.com +short +timeout=2 +tries=1")
        return res and res.stdout.strip() != ""
    except:
        return False

def is_dnssec_valid():
    # Verify DNSSEC by querying a known signed domain and checking for 'ad' flag
    try:
        # NOTE: DNSSEC check is temporarily disabled to prevent flapping
        # as dnsmasq is currently acting as a non-DNSSEC proxy to Unbound.
        # Unbound already handles the actual validation.
        return True
        
        # Use +adflag to explicitly ask for AD bit
        # We query through localhost 127.0.0.1
        res = run_cmd("dig @127.0.0.1 cloudflare.com +dnssec +adflag +timeout=2 +tries=1")
        if not res or not res.stdout:
            # If resolution fails completely, let is_dns_resolving() handle it
            return True
            
        # Check if 'ad' flag is present in flags section
        # NOTE: dnsmasq without proxy-dnssec will not show 'ad' flag even if records are signed.
        # Since dnsmasq is a proxy to Unbound, and Unbound handles DNSSEC, we only check if records exist.
        output = res.stdout.lower()
        is_valid = " ad " in output or "flags: ad" in output or "flags: qr rd ra ad" in output or "status: noerror" in output
        
        # If resolution worked (NOERROR) but AD flag is missing, it's likely just dnsmasq 
        # not being configured as a DNSSEC proxy. We consider this "valid" enough to 
        # avoid restart loops, as long as we get an answer.
        if "status: noerror" in output and "answer: " in output:
            return True

        # If not valid on 127.0.0.1, check 127.0.0.1:5353 (Unbound directly)
        if not is_valid:
            res_unbound = run_cmd("dig @127.0.0.1 -p 5353 cloudflare.com +dnssec +adflag +timeout=2 +tries=1")
            if res_unbound and res_unbound.stdout:
                output_ub = res_unbound.stdout.lower()
                # Use a more flexible check for the AD flag
                is_valid_unbound = " ad " in output_ub or "flags: ad" in output_ub or "flags: qr rd ra ad" in output_ub
                if is_valid_unbound or ("status: noerror" in output_ub and "answer: " in output_ub):
                    # Unbound is OK, but dnsmasq is not passing AD flag. 
                    # This is normal if dnsmasq isn't configured as a DNSSEC proxy.
                    # We return True to avoid false-positive service restarts.
                    return True
        
        return is_valid
    except:
        return True # Don't restart on script errors

def check_and_repair_services():
    rotate_logs()
    # dns_trust = is_dns_trust_enabled()
    
    # Define services with their critical ports
    service_map = {
        "dnsmasq": {"port": 53, "proto": "udp", "addr": "127.0.0.1"},
        "unbound": {"port": 5353, "proto": "udp", "addr": "127.0.0.1"},
        "dnsmdnet-gui": {"port": 5001, "proto": "tcp"},
        "nginx": {"port": 5000, "proto": "tcp"},
        "systemd-resolved": {"port": None} # Just check if service is active
    }

    for service, info in service_map.items():
        status = run_cmd(f"systemctl is-active {service}")
        
        # Check port listening (if port is specified)
        port_up = True
        if info.get("port"):
            addr_part = f"{info['addr']}:" if 'addr' in info else ":"
            port_up = is_port_listening(info["port"], info["proto"], addr_part)
        
        # Additional checks for dnsmasq: resolution and DNSSEC
        dns_functional = True
        if service == "dnsmasq" and port_up:
            dns_functional = is_dns_resolving()
            if not dns_functional:
                log_event("ALERT: dnsmasq port is UP but resolution is FAILING. Possible hung process.")

        # If service is down or port is not listening or DNS is not functional
        if (status and status.stdout.strip() != "active") or not port_up or (service == "dnsmasq" and not dns_functional):
            if status.stdout.strip() != "active":
                reason = "is DOWN"
            elif not port_up:
                reason = f"is HUNG (port {info['port']} not responding)"
            else:
                reason = "is HUNG (resolution failing)"
                
            log_event(f"ALERT: {service} {reason}. Attempting self-healing...")
            
            # Special check for dnsmasq/unbound config
            check_conf = None
            if service == "dnsmasq":
                check_conf = run_cmd("dnsmasq --test")
            elif service == "unbound":
                check_conf = run_cmd("unbound-checkconf")
            
            if check_conf and check_conf.stderr and "error" in check_conf.stderr.lower():
                log_event(f"ERROR: {service} config is corrupted: {check_conf.stderr.strip()}")
                # Try to restore default or notify, but for now we try restart anyway
            
            run_cmd(f"systemctl restart {service}")
            time.sleep(3) # Give it time to bind ports
            
            new_status = run_cmd(f"systemctl is-active {service}")
            addr_part = f"{info['addr']}:" if 'addr' in info else ":"
            new_port_up = is_port_listening(info["port"], info["proto"], addr_part)
            
            if new_status and new_status.stdout.strip() == "active" and new_port_up:
                log_event(f"SUCCESS: {service} has been repaired and is now ONLINE.")
            else:
                log_event(f"CRITICAL: {service} repair FAILED (Status: {new_status.stdout.strip()}, Port: {new_port_up}).")

    # --- FIREWALL SELF-HEALING (DDoS PRO & NAT INTCP) ---
    # Enhanced firewall check: ensure DNS redirection and Web access is ALWAYS active
    fw_status = run_cmd("sudo iptables -L INPUT -n")
    fw_nat_status = run_cmd("sudo iptables -L -t nat -n")
    fw_save_status = run_cmd("sudo iptables-save") # Better for matching modules
    fw6_status = run_cmd("sudo ip6tables -L INPUT -n 2>/dev/null")
    fw6_nat_status = run_cmd("sudo ip6tables -L -t nat -n 2>/dev/null")
    
    # Check for DNS redirect (IPv4 & IPv6) in NAT table
    has_dns_v4_nat = "REDIRECT" in fw_nat_status.stdout and "dpt:53" in fw_nat_status.stdout if (fw_nat_status and fw_nat_status.stdout) else False
    
    # Check for DDoS Protection modules
    has_flood_prot = "hashlimit" in fw_save_status.stdout if (fw_save_status and fw_save_status.stdout) else False
    has_conn_limit = "connlimit" in fw_save_status.stdout if (fw_save_status and fw_save_status.stdout) else False

    # Check for Web GUI access (Port 5000) in INPUT chain
    has_web_v4 = "dpt:5000" in fw_status.stdout if (fw_status and fw_status.stdout) else False
    
    # Check for DNS access (Port 53) in INPUT chain
    has_dns_v4_input = "dpt:53" in fw_status.stdout if (fw_status and fw_status.stdout) else False

    # Check for IPv6 if enabled
    ipv6_up = get_current_ipv6() is not None
    has_dns_v6_nat = True
    has_web_v6 = True
    
    if ipv6_up:
        if not fw6_nat_status or not fw6_nat_status.stdout or "REDIRECT" not in fw6_nat_status.stdout or "dpt:53" not in fw6_nat_status.stdout:
            has_dns_v6_nat = False
        if not fw6_status or not fw6_status.stdout or "dpt:5000" not in fw6_status.stdout:
            has_web_v6 = False
    
    # If any critical rule is missing, restore firewall
    if not has_dns_v4_nat or not has_web_v4 or not has_dns_v4_input or not has_dns_v6_nat or not has_web_v6 or not has_flood_prot or not has_conn_limit:
        reason = []
        if not has_dns_v4_nat: reason.append("IPv4 DNS NAT")
        if not has_dns_v4_input: reason.append("IPv4 DNS INPUT")
        if not has_flood_prot: reason.append("DDoS Flood Protection")
        if not has_conn_limit: reason.append("TCP Conn Limit")
        if not has_web_v4: reason.append("IPv4 Web GUI")
        if not has_dns_v6_nat: reason.append("IPv6 DNS NAT")
        if not has_web_v6: reason.append("IPv6 Web GUI")
        
        log_event(f"ALERT: Critical firewall rules ({', '.join(reason)}) are missing. Restoring...")
        run_cmd("sudo bash /home/dns/setup_firewall.sh")

def check_resources():
    """
    Monitor Memory, Swap, and UDP Errors.
    Mitigates: Memory Leak, Swap Thrashing, UDP Drops.
    """
    try:
        # 1. Check Memory & Swap
        with open('/proc/meminfo', 'r') as f:
            meminfo = {}
            for line in f:
                parts = line.split(':')
                meminfo[parts[0].strip()] = int(parts[1].split()[0])
        
        total_mem = meminfo.get('MemTotal', 1)
        avail_mem = meminfo.get('MemAvailable', 0)
        total_swap = meminfo.get('SwapTotal', 0)
        free_swap = meminfo.get('SwapFree', 0)
        
        mem_usage = 100 - (avail_mem / total_mem * 100)
        swap_usage = 100 - (free_swap / total_swap * 100) if total_swap > 0 else 0
        
        # Memory Leak Protection
        if mem_usage > MEM_THRESHOLD:
            log_event(f"ALERT: High Memory Usage ({mem_usage:.1f}%). Checking for leaks...")
            # If swap is also high, we are in trouble. Restart heaviest service.
            if swap_usage > SWAP_THRESHOLD:
                log_event("CRITICAL: Swap Thrashing Detected. Restarting DNS services to free memory.")
                run_cmd("systemctl restart unbound")
                run_cmd("systemctl restart dnsmasq")
        
        # 2. Check UDP Packet Drops (RCV buffer errors)
        # cat /proc/net/snmp | grep Udp:
        cmd = "cat /proc/net/snmp | grep 'Udp: ' | awk 'NR==2 {print $6}'" # RcvbufErrors is usually column 6
        res = run_cmd(cmd)
        if res and res.stdout.strip():
            rcv_errors = int(res.stdout.strip())
            # We track delta ideally, but for now just log if non-zero and high
            if rcv_errors > 1000:
                 # Check if we already logged this recently? (Simplified: just log)
                 pass
                 # log_event(f"WARNING: UDP Receive Errors detected: {rcv_errors}. OS Buffer tuning might be needed.")

    except Exception as e:
        log_event(f"Resource check error: {e}")

def check_disk_space():
    """
    Emergency Disk Protection.
    1. Check individual log sizes (Prevention)
    2. Check total disk usage (Emergency)
    """
    MAX_LOG_FILE_SIZE = 500 * 1024 * 1024 # 500MB
    
    try:
        # 1. PREVENTIVE CHECK: Truncate logs if they get too big (regardless of disk usage)
        logs_to_check = [DNSMASQ_LOG, NGINX_LOG]
        for log_file in logs_to_check:
            if os.path.exists(log_file):
                size = os.path.getsize(log_file)
                if size > MAX_LOG_FILE_SIZE:
                    log_event(f"WARNING: Log file {log_file} is too large ({size/1024/1024:.1f}MB > 500MB). Truncating...")
                    run_cmd(f"truncate -s 0 {log_file}")
                    # Reload service if needed
                    if "nginx" in log_file:
                        run_cmd("systemctl reload nginx")
        
        # 2. EMERGENCY CHECK: Total Disk Usage
        # Get root partition usage
        cmd = "df -h / | awk 'NR==2 {print $5}' | sed 's/%//'"
        res = run_cmd(cmd)
        if not res or not res.stdout:
            return
            
        usage = int(res.stdout.strip())
        
        if usage >= DISK_THRESHOLD:
            log_event(f"CRITICAL: Disk usage at {usage}% (Threshold: {DISK_THRESHOLD}%). Executing EMERGENCY cleanup...")
            
            # 1. Truncate Logs immediately
            if os.path.exists(DNSMASQ_LOG):
                run_cmd(f"truncate -s 0 {DNSMASQ_LOG}")
                log_event(f"Truncated {DNSMASQ_LOG}")
                
            if os.path.exists(NGINX_LOG):
                run_cmd(f"truncate -s 0 {NGINX_LOG}")
                run_cmd("systemctl reload nginx") # Important for Nginx to release file handle
                log_event(f"Truncated {NGINX_LOG}")
                
            # 1.5 Vacuum Systemd Journal (Syslog)
            run_cmd("journalctl --vacuum-size=50M")
            log_event("Vacuumed systemd journal to 50MB")

            # 2. Check for rotated logs that are huge and delete them
            # Delete any .gz or .1 log file in /var/log/nginx older than 0 days (immediate)
            run_cmd("find /var/log/nginx -name '*.gz' -delete")
            run_cmd("find /var/log/nginx -name '*.1' -delete")
            
            # Same for dnsmasq
            run_cmd("find /var/log -name 'dnsmasq.log.*.gz' -delete")
            
            log_event("Emergency cleanup completed.")
            
    except Exception as e:
        log_event(f"Error checking disk space: {e}")



# --- TRUST SCHEDULE ENFORCEMENT ---
DB_PATH = "/home/dns/traffic_history.db"

def apply_trust_schedule():
    """
    Enhanced schedule enforcement with change detection.
    - Detects schedule setting changes and forces immediate sync
    - Properly handles overnight schedules (e.g., 19:00-05:00)
    - Avoids unnecessary service restarts
    """
    global LAST_SCHEDULE_STATE
    
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT enabled, start_time, end_time, trust_ips FROM trust_schedule WHERE id=1")
        row = c.fetchone()
    except Exception as e:
        log_event(f"Error reading trust schedule: {e}")
        return
    finally:
        if conn:
            conn.close()

    if not row:
        return
    
    try:
        enabled, start_time, end_time, trust_ips = row
        
        # Create a hashable state representation
        current_state = (enabled, start_time, end_time, trust_ips)
        
        # DETECT SCHEDULE CHANGE: Settings were modified
        is_schedule_changed = LAST_SCHEDULE_STATE != current_state
        if is_schedule_changed:
            log_event(f"SCHEDULE CHANGED: ({LAST_SCHEDULE_STATE}) -> ({current_state})")
            LAST_SCHEDULE_STATE = current_state
        
        # Check if schedule is enabled in database
        if not enabled:
            # If schedule was previously enabled, ensure DNS trust is disabled
            current_enabled = is_dns_trust_enabled()
            if current_enabled:
                log_event("SCHEDULE: Disabled in config. Disabling DNS Trust...")
                disable_trust_logic()
            return
        
        # Schedule is enabled, check if current time is within range
        now = datetime.now().strftime("%H:%M")
        
        # Calculate if current time is within schedule range
        is_in_range = _check_time_in_range(start_time, end_time, now)
        current_enabled = is_dns_trust_enabled()
        
        # DECISION LOGIC:
        # 1. If schedule changed, force immediate state sync
        # 2. If time-based change needed, apply it
        
        if is_schedule_changed:
            # Force immediate sync to new state
            if is_in_range:
                if not current_enabled:
                    log_event(f"SCHEDULE CHANGE: Force enabling DNS Trust ({start_time}-{end_time})")
                    enable_trust_logic(trust_ips)
            else:
                if current_enabled:
                    log_event(f"SCHEDULE CHANGE: Force disabling DNS Trust (outside {start_time}-{end_time})")
                    disable_trust_logic()
        else:
            # Normal operation: only change state if needed
            if is_in_range and not current_enabled:
                log_event(f"SCHEDULE: Enabling DNS Trust ({start_time}-{end_time})")
                enable_trust_logic(trust_ips)
            elif not is_in_range and current_enabled:
                log_event(f"SCHEDULE: Disabling DNS Trust (outside {start_time}-{end_time})")
                disable_trust_logic()
                
    except Exception as e:
        log_event(f"Error in trust schedule: {e}")

def _check_time_in_range(start_time, end_time, now):
    """
    Check if current time falls within schedule range.
    Properly handles overnight schedules (e.g., start > end).
    
    Args:
        start_time: HH:MM format (e.g., "19:00")
        end_time: HH:MM format (e.g., "05:00")
        now: HH:MM format of current time
    
    Returns:
        True if now is within range, False otherwise
    """
    try:
        # Parse time strings to comparable format
        start = start_time.replace(":", "")  # "19:00" -> "1900"
        end = end_time.replace(":", "")      # "05:00" -> "0500"
        current = now.replace(":", "")       # "20:30" -> "2030"
        
        # SPECIAL CASE: Manual Mode (00:00 - 00:00) -> Always Active
        if start == "0000" and end == "0000":
            return True

        # Convert to integers for comparison
        start_min = int(start)
        end_min = int(end)
        current_min = int(current)
        
        if start_min <= end_min:
            # Normal schedule: start <= end (e.g., 05:00 <= 19:00)
            # 05:00 to 19:00 is "in range" if 500 <= now <= 1900
            return start_min <= current_min <= end_min
        else:
            # Overnight schedule: start > end (e.g., 19:00 to 05:00)
            # 19:00 to 05:00 is "in range" if (now >= 1900) OR (now <= 0500)
            return current_min >= start_min or current_min <= end_min
    except Exception as e:
        log_event(f"Error in time range check: {e}")
        return False


def enable_trust_logic(trust_ip=None):
    try:
        # Enable Local Blocklist using the dedicated script that handles whitelisting
        log_event("Enabling DNS Trust via script...")
        
        # Ensure disabled directory exists
        if not os.path.exists('/home/dns/blocklists/disabled'):
            run_cmd('sudo mkdir -p /home/dns/blocklists/disabled')
            
        # Check if source exists, if not try to update
        blocklist_disabled = '/home/dns/blocklists/disabled/internet_positif.conf'
        if not os.path.exists(blocklist_disabled):
            run_cmd("sudo bash /home/dns/update_blocklist.sh")
            
        # Run the update script
        # It reads disabled/internet_positif.conf, applies whitelist, and writes to /etc/dnsmasq.d/
        res = run_cmd('/usr/bin/python3 /home/dns/scripts/update_trust_list.py')
        if res and res.returncode != 0:
            log_event(f"Error enabling trust: {res.stderr}")
            return
            
        run_cmd("sudo bash /home/dns/setup_firewall.sh")
        run_cmd("sudo systemctl restart dnsmasq")
        # Unbound restart not strictly needed but good for cleanup
        run_cmd("sudo systemctl restart unbound") 
    except Exception as e:
        log_event(f"Failed to enable trust via schedule: {e}")

def disable_trust_logic():
    try:
        # Disable Local Blocklist
        blocklist_file = '/etc/dnsmasq.d/internet_positif.conf'
        
        if os.path.exists(blocklist_file):
            # Just remove the active file, the master copy is in disabled/
            run_cmd(f"sudo rm {blocklist_file}")
        
        # Clean up any legacy stray files
        run_cmd("sudo rm -f /etc/dnsmasq.d/*.disabled")
            
        run_cmd("sudo bash /home/dns/setup_firewall.sh")
        run_cmd("sudo systemctl restart dnsmasq")
    except Exception as e:
        log_event(f"Failed to disable trust via schedule: {e}")

def tune_dnsmasq_performance():
    """
    Auto-tune DNSMasq performance settings based on Bandwidth/Guardian Config.
    """
    try:
        gbps = config.get("bandwidth_gbps", 10) # Default 10 if not set
        
        # Calculate optimal settings
        # Base: 1000 concurrent queries per Gbps
        forward_max = int(gbps * 1000)
        if forward_max < 5000: forward_max = 5000
        if forward_max > 150000: forward_max = 150000 # Cap to avoid OS limits
        
        # Cache: 25000 entries per Gbps
        cache_size = int(gbps * 25000)
        if cache_size < 150000: cache_size = 150000
        if cache_size > 5000000: cache_size = 5000000 # 5M max
        
        conf_file = "/etc/dnsmasq.d/00-base.conf"
        if not os.path.exists(conf_file):
            return # Should exist, if not let's not touch
            
        with open(conf_file, 'r') as f:
            content = f.read()
            
        new_content = content
        
        # Replace cache-size
        if "cache-size=" in content:
            new_content = re.sub(r"cache-size=\d+", f"cache-size={cache_size}", new_content)
        else:
            new_content += f"\ncache-size={cache_size}\n"
            
        # Replace dns-forward-max
        if "dns-forward-max=" in content:
            new_content = re.sub(r"dns-forward-max=\d+", f"dns-forward-max={forward_max}", new_content)
        else:
            new_content += f"\ndns-forward-max={forward_max}\n"
            
        if new_content != content:
            log_event(f"Auto-tuning DNSMasq for {gbps}Gbps: cache-size={cache_size}, dns-forward-max={forward_max}")
            with open(conf_file, 'w') as f:
                f.write(new_content)
            # run_cmd("sudo systemctl restart dnsmasq")
            # Log it but don't restart here to avoid loops
            log_event("DNSMasq tuning applied (Pending restart).")
        else:
            # log_event(f"DNSMasq already tuned for {gbps}Gbps")
            pass
            
    except Exception as e:
        log_event(f"Error tuning dnsmasq: {e}")

LAST_CONFIG_CHECK = 0

def reload_guardian_config_if_needed():
    global LAST_CONFIG_CHECK, config, BAN_THRESHOLD, MALICIOUS_THRESHOLD, LIMIT_QUERY_PER_MIN, LIMIT_HIT_THRESHOLD, BLOCKING_ENABLED, DISK_THRESHOLD, MEM_THRESHOLD, SWAP_THRESHOLD
    
    try:
        if not os.path.exists(CONFIG_FILE):
            return

        mtime = os.path.getmtime(CONFIG_FILE)
        if mtime > LAST_CONFIG_CHECK:
            # First run or changed
            # if LAST_CONFIG_CHECK > 0:
            #     log_event("Configuration changed. Reloading...")
            
            config = load_config()
            BAN_THRESHOLD = config["ban_threshold"]
            MALICIOUS_THRESHOLD = config.get("abnormal_query_per_min", config["malicious_threshold"])
            LIMIT_QUERY_PER_MIN = config.get("limit_query_per_min", DEFAULT_LIMIT_QUERY_PER_MIN)
            LIMIT_HIT_THRESHOLD = config.get("limit_hit_threshold", DEFAULT_LIMIT_HIT_THRESHOLD)
            BLOCKING_ENABLED = config.get("blocking_enabled", True)
            DISK_THRESHOLD = config.get("disk_threshold", DISK_CRITICAL_THRESHOLD)
            MEM_THRESHOLD = config.get("mem_threshold", MEM_CRITICAL_THRESHOLD)
            SWAP_THRESHOLD = config.get("swap_threshold", SWAP_CRITICAL_THRESHOLD)
            
            LAST_CONFIG_CHECK = mtime
            
            # log_event(f"Config reloaded: LIMIT={LIMIT_QUERY_PER_MIN}, MALICIOUS={MALICIOUS_THRESHOLD}, BLOCKING={BLOCKING_ENABLED}")
            
            # Re-tune DNSMasq with new config
            tune_dnsmasq_performance()
            
    except Exception as e:
        log_event(f"Error checking config reload: {e}")

# --- MAIN LOOP ---
if __name__ == "__main__":
    log_event("INTELLIGENT GUARDIAN STARTED: Monitoring system health and security...")
    
    # Initialize config timestamp
    if os.path.exists(CONFIG_FILE):
        LAST_CONFIG_CHECK = os.path.getmtime(CONFIG_FILE)

    # Initial tuning
    tune_dnsmasq_performance()
    
    # Wait for other services to settle on boot
    time.sleep(5)
    
    # --- SMART ROBOT VERIFICATION (MORNING SCAN) ---
    import threading
    def run_morning_scan():
        while True:
            # Check if it's 4:00 AM (04:00)
            now = datetime.now()
            if now.hour == 4 and now.minute == 0:
                log_event("Starting Scheduled Robot Verification Scan...")
                os.system("python3 /home/dns/smart_verifier.py")
                time.sleep(65) # Prevent multiple runs in same minute
            time.sleep(30) # Check every 30 seconds

    # Start the morning scanner thread
    scan_thread = threading.Thread(target=run_morning_scan)
    scan_thread.daemon = True
    scan_thread.start()
    
    # Run initial scan on startup
    log_event("Running initial Robot Verification Scan...")
    os.system("python3 /home/dns/smart_verifier.py")
    
    while True:
        try:
            # 0. Check for config changes
            reload_guardian_config_if_needed()

            # 1. Emergency Disk Check (Priority 1)
            check_disk_space()
            
            # 2. Resource Health Check (Memory, Swap, UDP)
            check_resources()
            
            # Refresh server IP and Whitelist in case of network changes
            reload_whitelist_if_needed()
            
            # Detect IP Changes
            current_ip_v4 = get_current_ip()
            current_ip_v6 = get_current_ipv6()
            
            if current_ip_v4 != LAST_IP_V4 or current_ip_v6 != LAST_IP_V6:
                log_event(f"NETWORK CHANGE DETECTED: v4({LAST_IP_V4}->{current_ip_v4}), v6({LAST_IP_V6}->{current_ip_v6})")
                # Add new IPs to whitelist immediately
                if current_ip_v4 not in WHITELIST: WHITELIST.append(current_ip_v4)
                if current_ip_v6 and current_ip_v6 not in WHITELIST: WHITELIST.append(current_ip_v6)
                
                # Re-apply firewall to update rules with new IP
                log_event("Re-applying firewall rules for new IP...")
                run_cmd("sudo bash /home/dns/setup_firewall.sh")
                
                LAST_IP_V4 = current_ip_v4
                LAST_IP_V6 = current_ip_v6
                server_ip = current_ip_v4

            check_and_repair_services()
            apply_trust_schedule()
            sync_blocking_config(is_dns_trust_enabled())
            analyze_logs()
            time.sleep(10) # Run every 10 seconds
        except KeyboardInterrupt:
            break
        except Exception as e:
            log_event(f"GUARDIAN ERROR: {str(e)}")
            time.sleep(30)
