from flask import Flask, render_template, request, jsonify, abort, session, send_file, make_response
import subprocess
import psutil
import socket
import re
import os
import time
import hashlib
import sqlite3
import threading
import json
from datetime import datetime, timedelta
from fpdf import FPDF
import io
import license_manager

app = Flask(__name__, template_folder='/home/dns/web_gui/templates')

# --- CONFIGURATION ---
CONFIG_FILE = "/home/dns/guardian_config.json"
DB_PATH = '/home/dns/traffic_history.db'

# Persistent Secret Key
SECRET_FILE = '/home/dns/web_gui/.flask_secret'
if os.path.exists(SECRET_FILE):
    try:
        with open(SECRET_FILE, 'rb') as f:
            app.secret_key = f.read()
    except:
        app.secret_key = os.urandom(24)
else:
    app.secret_key = os.urandom(24)
    try:
        with open(SECRET_FILE, 'wb') as f:
            f.write(app.secret_key)
    except:
        pass

# --- AUTHENTICATION ---
PASSWORD_FILE = '/home/dns/web_gui/.password.hash'
DEFAULT_PASSWORD = 'admin' # Default password if not set

def get_stored_password():
    if os.path.exists(PASSWORD_FILE):
        try:
            with open(PASSWORD_FILE, 'r') as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception as e:
            print(f"Error reading password file: {e}")
            
    # Default password: admin
    hashed = hashlib.sha256(DEFAULT_PASSWORD.encode()).hexdigest()
    try:
        with open(PASSWORD_FILE, 'w') as f:
            f.write(hashed)
        # Ensure correct ownership
        subprocess.run(['sudo', 'chown', 'dns:dns', PASSWORD_FILE])
    except Exception as e:
        print(f"Error writing default password: {e}")
    return hashed

def verify_password(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return hashed == get_stored_password()

SYNC_TOKEN_FILE = '/home/dns/web_gui/.sync_token'

def get_sync_token():
    # 1. Try to read the dedicated sync token file first
    if os.path.exists(SYNC_TOKEN_FILE):
        try:
            with open(SYNC_TOKEN_FILE, 'r') as f:
                token = f.read().strip()
                if token:
                    return token
        except Exception as e:
            print(f"Error reading sync token file: {e}")
            
    # 2. Fallback: Use the first 16 chars of the hashed password
    return get_stored_password()[:16]

@app.route('/api/ha/status')
def ha_status():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    
    role = "UNKNOWN"
    protocol = "VRRP (Keepalived)"
    vip = "Not Configured"
    
    # Check if keepalived is running
    try:
        if os.system("pidof keepalived > /dev/null") == 0:
            # Try to read local config to find VIP
            vip_addr = ""
            if os.path.exists('/etc/keepalived/keepalived.conf'):
                with open('/etc/keepalived/keepalived.conf', 'r') as f:
                    content = f.read()
                    m = re.search(r'virtual_ipaddress\s*\{\s*([0-9\.]+)', content)
                    if m:
                        vip_addr = m.group(1)
            
            if vip_addr:
                vip = vip_addr
                # Check if this IP is assigned
                if os.system(f"ip addr | grep -q {vip_addr}") == 0:
                    role = "MASTER"
                else:
                    role = "BACKUP"
            else:
                role = "NO VIP"
        else:
            role = "STOPPED"
    except:
        pass
        
    return jsonify({
        'role': role,
        'protocol': protocol,
        'vip': vip
    })

@app.route('/api/install/secondary')
def download_installer():
    """Endpoint to download the secondary installer script directly from Primary"""
    installer_path = '/home/dns/install_ha_secondary.sh'
    if os.path.exists(installer_path):
        try:
            with open(installer_path, 'r') as f:
                content = f.read()
            # Inject Primary IP and Token dynamically into the installer script
            # Find the line that starts with SYNC_TOKEN=$2 and replace it
            # Actually we can just keep it as is, but we could also provide a pre-filled one
            return content, 200, {'Content-Type': 'text/plain'}
        except Exception as e:
            return f"Error reading installer: {str(e)}", 500
    return "Installer not found", 404

@app.route('/api/sync/config')
def sync_config():
    token = request.args.get('token')
    if not token or token != get_sync_token():
        return jsonify({'status': 'error', 'message': 'Invalid sync token'}), 401
    
    # Track sync activity
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        remote_ip = request.remote_addr
        c.execute("UPDATE cluster_status SET value = ? WHERE key = 'last_sync_received'", (now,))
        c.execute("UPDATE cluster_status SET value = ? WHERE key = 'secondary_ip'", (remote_ip,))
        conn.commit()
        conn.close()
    except:
        pass

    # Collect essential config files for secondary sync
    configs = {}
    files_to_sync = {
        'blacklist': '/etc/dnsmasq.d/blacklist.conf',
        'whitelist_dnsmasq': '/etc/dnsmasq.d/whitelist.conf',
        'upstream': '/etc/dnsmasq.d/upstream.conf',
        'alias': '/etc/dnsmasq.d/alias.conf',
        'whitelist_firewall': '/home/dns/whitelist.conf'
    }
    
    # Check Trust Status
    trust_info = get_trust_info()
    
    for key, path in files_to_sync.items():
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    configs[key] = f.read()
            except:
                configs[key] = ""
        else:
            configs[key] = ""
            
    return jsonify({
        'status': 'success',
        'timestamp': datetime.now().isoformat(),
        'configs': configs,
        'trust_config': {
            'enabled': trust_info['enabled']
        }
    })

def is_authenticated():
    return session.get('authenticated', False)



def get_high_traffic_candidates():
    """
    Analyzes logs for high traffic domains (potential Rate Limit candidates).
    Used for UI display only. Blocking is handled by Guardian.
    """
    # Load Blacklist to filter results
    blacklist = set()
    try:
        if os.path.exists('/etc/dnsmasq.d/blacklist.conf'):
            with open('/etc/dnsmasq.d/blacklist.conf', 'r') as f:
                for line in f:
                    match = re.search(r'address=/(.*?)/', line)
                    if match:
                        blacklist.add(match.group(1).lower())
    except:
        pass

    # Load Whitelist to prevent False Positives
    whitelist = load_whitelist_domains()

    results = []
    try:
        # STRICT MODE: Only detect Rate Limiting (High Volume)
        # Keyword and Pattern detection REMOVED per user request.

        # Get Top 50 queried domains from recent logs
        cmd = "sudo tail -n 50000 /var/log/dnsmasq.log | grep 'query\\[' | awk '{print $6}' | sort | uniq -c | sort -nr | head -n 50"
        output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
        
        # Get configured limit
        guardian_config = {}
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    guardian_config = json.load(f)
            except:
                pass
        limit_query = guardian_config.get("limit_query_per_min", 1000)
        abnormal_query = guardian_config.get("abnormal_query_per_min", 500)

        for line in output.split('\n'):
            parts = line.strip().split()
            if len(parts) >= 2:
                count = int(parts[0])
                domain = parts[1]
                domain_lower = domain.lower()
                
                # --- FILTERS ---
                
                # 1. Skip Whitelisted (Critical)
                if domain_lower in whitelist: continue
                
                # Check parent domains against whitelist
                is_whitelisted = False
                parts_dom = domain_lower.split('.')
                for i in range(len(parts_dom)-1):
                    parent = ".".join(parts_dom[i:])
                    if parent in whitelist:
                        is_whitelisted = True
                        break
                if is_whitelisted: continue

                # 2. Skip already Blocked
                if domain_lower in blacklist: continue
                
                # Check parent domains against blacklist
                is_blacklisted = False
                for i in range(len(parts_dom)-1):
                    parent = ".".join(parts_dom[i:])
                    if parent in blacklist:
                        is_blacklisted = True
                        break
                if is_blacklisted: continue

                # --- ANALYSIS ---
                # Check for High Volume (Rate Limit) OR Abnormal
                if count >= abnormal_query:
                    status_type = "ABNORMAL"
                    if count >= limit_query:
                        status_type = f"HIGH TRAFFIC (> {limit_query}/min)"
                    
                    results.append({
                        'domain': domain,
                        'type': status_type,
                        'count': count
                    })

        return results

    except Exception as e:
        print(f"Error analyzing traffic: {e}")
        return []

    return results

# --- CATEGORY DEFINITIONS ---
DOMAIN_CATEGORIES = {
    'Mobile Analytics': {
        'keywords': ['appsflyer', 'adjust', 'branch.io', 'kochava', 'singular', 'umeng', 'app-measurement'],
        'domains': ['appsflyer.com', 'adjust.com', 'branch.io', 'kochava.com', 'singular.net', 'umeng.com']
    },
    'Ads Network': {
        'keywords': ['doubleclick', 'googleadservices', 'unity3d', 'applovin', 'ironsource', 'vungle', 'adcolony', 'chartboost', 'pangle', 'facebook', 'admob', 'ads', 'adsystem'],
        'domains': ['doubleclick.net', 'googleadservices.com', 'unity3d.com', 'applovin.com', 'ironsrc.com', 'vungle.com', 'adcolony.com', 'chartboost.com', 'pangle.io', 'facebook.com', 'admob.com']
    },
    'Telemetry & Crash Report': {
        'keywords': ['crashlytics', 'sentry', 'bugsnag', 'firebase', 'hockeyapp', 'bugsplat'],
        'domains': ['crashlytics.com', 'sentry.io', 'bugsnag.com', 'firebaseio.com', 'hockeyapp.net']
    },
    'Tracking SDK': {
        'keywords': ['mixpanel', 'amplitude', 'segment', 'clevertap', 'leanplum'],
        'domains': ['mixpanel.com', 'amplitude.com', 'segment.io', 'clevertap.com']
    },
    'CDN Log & Monitoring': {
        'keywords': ['datadog', 'newrelic', 'splunk', 'loggly', 'sumologic'],
        'domains': ['datadoghq.com', 'newrelic.com', 'splunk.com', 'loggly.com']
    }
}

def categorize_domain(domain):
    for cat, data in DOMAIN_CATEGORIES.items():
        # Check keywords
        for keyword in data['keywords']:
            if keyword in domain.lower():
                return cat
    return 'Uncategorized'

@app.route('/api/logs/blacklist_deprecated')
def get_blacklist_logs_deprecated():
    return jsonify({'status': 'deprecated'})

@app.route('/api/stats/extended_info')
def extended_stats_info_api():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
        
    ub_stats = get_unbound_stats()
    bl_rate = get_blacklist_rate()
    any_rate = get_any_attack_rate()
    frontend_qps, _ = get_traffic_stats()
    
    # Reload config to get latest limits
    guardian_config = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                guardian_config = json.load(f)
        except: pass
    limit_query = guardian_config.get("limit_query_per_min", 1000)

    if ub_stats:
        ub_stats['blacklist'] = bl_rate
        ub_stats['any_attack'] = any_rate
        ub_stats['frontend_qps'] = frontend_qps
        
        backend_qps = ub_stats['queries']
        frontend_hits = max(0, frontend_qps - backend_qps)
        
        return jsonify({
            'status': 'success',
            'data': ub_stats,
            'limit_query': limit_query,
            'formatted': {
                'frontend_qps': f"{int(frontend_qps)} queries/s",
                'frontend_hits': f"{int(frontend_hits)} queries/s",
                'queries': f"{int(ub_stats['queries'])} queries/s",
                'cachehits': f"{int(ub_stats['cachehits'])} queries/s",
                'cachemiss': f"{int(ub_stats['cachemiss'])} queries/s",
                'blacklist': f"{int(bl_rate)} queries/s",
                'any_attack': f"{int(any_rate)} attack/s",
                'recursive': f"{int(ub_stats['recursive'])} queries/s",
                'expired': f"{int(ub_stats['expired'])} queries/s",
                'reqlist': f"{ub_stats['reqlist_avg']:.5f} avg, {int(ub_stats['reqlist_max'])} max",
                'rectime': f"{ub_stats['rectime_avg']:.6f} avg, {ub_stats['rectime_med']:.6e} med"
            }
        })
    else:
        return jsonify({
             'status': 'success',
             'data': {
                 'queries': 0, 'cachehits': 0, 'cachemiss': 0, 'recursive': 0, 'expired': 0,
                 'reqlist_avg': 0, 'reqlist_max': 0, 'rectime_avg': 0, 'rectime_med': 0,
                 'blacklist': bl_rate, 'any_attack': any_rate, 'frontend_qps': frontend_qps
             },
             'limit_query': limit_query,
             'formatted': {
                'frontend_qps': f"{int(frontend_qps)} queries/s",
                'frontend_hits': "0 queries/s",
                'queries': "0 queries/s", 'cachehits': "0 queries/s", 'cachemiss': "0 queries/s",
                'blacklist': f"{int(bl_rate)} queries/s", 
                'any_attack': f"{int(any_rate)} attack/s",
                'recursive': "0 queries/s", 'expired': "0 queries/s",
                'reqlist': "0 avg, 0 max", 'rectime': "0 avg, 0 med"
             }
        })

@app.route('/api/analysis/abnormal', methods=['GET'])
def get_abnormal_analysis_api():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Re-use the logic from get_high_traffic_candidates
        # but formatted for the analysis view
        results = get_high_traffic_candidates()
        
        # Sort by count desc
        results.sort(key=lambda x: x['count'], reverse=True)
        
        return jsonify({'status': 'success', 'logs': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

CATEGORY_STATUS_FILE = '/home/dns/category_status.json'
BLOCKLIST_FILES = ['/etc/dnsmasq.d/blacklist.conf', '/etc/dnsmasq.d/malware.conf', '/etc/dnsmasq.d/external_threats.conf']

def remove_domains_from_blocklists(domains):
    removed_lines = []
    
    for file_path in BLOCKLIST_FILES:
        if not os.path.exists(file_path):
            continue
            
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            new_lines = []
            file_changed = False
            
            for line in lines:
                should_keep = True
                
                # Parse domain from line: address=/domain/ip or server=/domain/ip
                # Typical format: address=/example.com/0.0.0.0
                parts = line.strip().split('/')
                if len(parts) >= 2:
                    blocked_domain = parts[1].strip().lower()
                    
                    for domain in domains:
                        domain = domain.strip().lower()
                        if not domain: continue
                        
                        # 1. Exact match
                        if blocked_domain == domain:
                            should_keep = False
                            break
                        
                        # 2. Subdomain match (if whitelisting parent, remove child blocks)
                        # e.g. whitelisting 'google.com' removes 'ads.google.com'
                        if blocked_domain.endswith('.' + domain):
                            should_keep = False
                            break
                            
                    if not should_keep:
                        file_changed = True
                        removed_lines.append(line.strip())
                
                if should_keep:
                    new_lines.append(line)
            
            if file_changed:
                with open(file_path, 'w') as f:
                    f.writelines(new_lines)
                    
        except Exception as e:
            print(f"Error processing blocklist {file_path}: {e}")
            
    return removed_lines

def load_category_status():
    if os.path.exists(CATEGORY_STATUS_FILE):
        try:
            with open(CATEGORY_STATUS_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}

def save_category_status(status):
    try:
        with open(CATEGORY_STATUS_FILE, 'w') as f:
            json.dump(status, f, indent=4)
    except Exception as e:
        print(f"Error saving category status: {e}")

@app.route('/api/category/status', methods=['GET'])
def get_category_status_endpoint():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    status = load_category_status()
    # Ensure all categories are present in the response
    response = {}
    for cat in DOMAIN_CATEGORIES:
        response[cat] = status.get(cat, {'enabled': False})
    return jsonify(response)

@app.route('/api/category/toggle', methods=['POST'])
def toggle_category():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    category = data.get('category')
    enabled = data.get('enabled')
    
    if not category or category not in DOMAIN_CATEGORIES:
        return jsonify({'error': 'Invalid category'}), 400
        
    status = load_category_status()
    current_cat_status = status.get(category, {'enabled': False, 'domains': []})
    
    whitelist_path = '/etc/dnsmasq.d/whitelist.conf'
    blacklist_path = '/etc/dnsmasq.d/blacklist.conf'
    
    if enabled:
        # ENABLE: Add to whitelist
        print(f"Enabling category: {category}")
        
        # 1. Get domains (Static + Dynamic from logs)
        domains_to_whitelist = set(DOMAIN_CATEGORIES[category]['domains'])
        
        # Scan logs for more
        try:
            keywords = DOMAIN_CATEGORIES[category]['keywords']
            escaped_keywords = [re.escape(k) for k in keywords]
            pattern = "|".join(escaped_keywords)
            
            # Use grep to find matching domains in recent logs
            # Increased log lines for better discovery
            cmd = f"sudo tail -n 50000 /var/log/dnsmasq.log | grep -E '{pattern}' | awk '{{print $6}}' | sort | uniq"
            output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
            
            for line in output.split('\n'):
                domain = line.strip()
                if domain and '.' in domain:
                    if any(k in domain.lower() for k in keywords):
                        domains_to_whitelist.add(domain)
        except Exception as e:
            print(f"Log scan error: {e}")
            
        domain_list = list(domains_to_whitelist)
        
        # 2. Add to whitelist.conf
        current_whitelist_content = ""
        if os.path.exists(whitelist_path):
            with open(whitelist_path, 'r') as f:
                current_whitelist_content = f.read()
        
        new_entries = []
        added_count = 0
        
        for domain in domain_list:
            # Check if already whitelisted (simple string check)
            if f"/{domain}/" not in current_whitelist_content:
                new_entries.append(f"server=/{domain}/8.8.8.8")
                added_count += 1
        
        if new_entries:
            with open(whitelist_path, 'a') as f:
                f.write('\n' + '\n'.join(new_entries) + '\n')
                
        # 3. Remove from all blocklists (including malware.conf)
        removed_lines = remove_domains_from_blocklists(domain_list)
                    
        # 4. Update Status
        status[category] = {
            'enabled': True,
            'domains': domain_list, # Store what we added/tracked
            'restorable_lines': removed_lines
        }
        save_category_status(status)
        
        # 5. Sync to Guardian (Text File)
        update_whitelist_domains_txt()

        # 6. Restart SAFELY
        success, msg = safe_service_restart()
        if not success:
             # If restart fails, we should probably revert changes, but for now just warn
             print(f"Service restart failed after enabling category {category}: {msg}")
             return jsonify({'error': f'Service restart failed: {msg}'}), 500
        
        return jsonify({'success': True, 'enabled': True, 'count': len(domain_list)})
        
    else:
        # DISABLE: Remove from whitelist
        print(f"Disabling category: {category}")
        
        # Get domains to remove
        stored_domains = current_cat_status.get('domains', [])
        if not stored_domains:
            stored_domains = DOMAIN_CATEGORIES[category]['domains']
            
        # 1. Remove from whitelist.conf
        if os.path.exists(whitelist_path):
            with open(whitelist_path, 'r') as f:
                lines = f.readlines()
            
            new_lines = []
            removed_count = 0
            for line in lines:
                should_keep = True
                for domain in stored_domains:
                    if f"/{domain}/" in line:
                        should_keep = False
                        removed_count += 1
                        break
                if should_keep:
                    new_lines.append(line)
            
            with open(whitelist_path, 'w') as f:
                f.writelines(new_lines)
        
        # 2. Restore blacklist lines
        restorable_lines = current_cat_status.get('restorable_lines', [])
        if restorable_lines and os.path.exists(blacklist_path):
            try:
                with open(blacklist_path, 'r') as f:
                    current_content = f.read()
                
                lines_to_add = []
                for line in restorable_lines:
                    if line not in current_content:
                        lines_to_add.append(line)
                
                if lines_to_add:
                    with open(blacklist_path, 'a') as f:
                        f.write('\n' + '\n'.join(lines_to_add) + '\n')
            except Exception as e:
                print(f"Error restoring blacklist lines: {e}")
        
        # 3. Update Status
        status[category] = {
            'enabled': False,
            'domains': [],
            'restorable_lines': []
        }
        save_category_status(status)
        
        # 4. Sync to Guardian (Text File)
        # We need to rebuild the text file to reflect removals
        if os.path.exists('/home/dns/whitelist_domains.txt'):
             try:
                 os.remove('/home/dns/whitelist_domains.txt')
             except: pass
        update_whitelist_domains_txt()
        
        # 5. Restart SAFELY
        success, msg = safe_service_restart()
        if not success:
             print(f"Service restart failed after disabling category {category}: {msg}")
             return jsonify({'error': f'Service restart failed: {msg}'}), 500
        
        return jsonify({'success': True, 'enabled': False, 'count': removed_count})

@app.route('/api/botnet/acs')
def get_acs_candidates():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        results = get_high_traffic_candidates()
        return jsonify({'candidates': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat/keywords', methods=['GET', 'POST', 'DELETE'])
def threat_keywords_api():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    if request.method == 'GET':
        return jsonify({'keywords': []})

    if request.method == 'POST':
        return jsonify({'status': 'error', 'message': 'Keyword blocking is disabled'})

    if request.method == 'DELETE':
        return jsonify({'status': 'error', 'message': 'Keyword blocking is disabled'})

def block_domains_internal(domains_to_block):
    if not domains_to_block:
        return 0, "No domains provided"
        
    server_ip = get_server_ip()
    blocked_count = 0
    
    try:
        # Read existing blacklist to avoid duplicates
        existing_blacklist = set()
        if os.path.exists('/etc/dnsmasq.d/blacklist.conf'):
            with open('/etc/dnsmasq.d/blacklist.conf', 'r') as f:
                existing_blacklist = set(line.strip() for line in f)

        new_entries = []
        for domain in domains_to_block:
            domain = domain.strip()
            if not domain: continue
            
            # Sanitize
            # Allow pipe | for some botnet domains, but be careful
            domain = re.sub(r'[^a-zA-Z0-9.\-\|]', '', domain)
            
            entry = f"address=/{domain}/0.0.0.0"
            
            # Check if already exists in file content or new entries
            is_duplicate = False
            for existing in existing_blacklist:
                if f"/{domain}/" in existing:
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                new_entries.append(entry)
                blocked_count += 1

        if not new_entries:
             return 0, "All domains were already blocked"

        # Append all new entries at once
        with open('/etc/dnsmasq.d/blacklist.conf', 'a') as f:
            f.write('\n' + '\n'.join(new_entries) + '\n')
        
        # Use background restart to prevent browser timeout
        success, msg = safe_service_restart(background=True)
        if not success:
            return 0, msg
            
        return blocked_count, f"{blocked_count} domains blocked successfully"
    except Exception as e:
        return 0, str(e)

@app.route('/api/block', methods=['POST'])
def block_domain_endpoint():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    data = request.json
    
    # Handle single domain or bulk domains
    domains_to_block = []
    
    if 'domains' in data and isinstance(data['domains'], list):
        domains_to_block = data['domains']
    elif 'domain' in data:
        domains_to_block = [data['domain']]
    
    count, message = block_domains_internal(domains_to_block)
    
    if count > 0 or "already blocked" in message:
        return jsonify({'status': 'success', 'message': message})
    else:
        return jsonify({'status': 'error', 'message': message})



@app.route('/api/blocked-domains', methods=['GET'])
def get_blocked_domains():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        
    blocked = []
    try:
        files = ['/etc/dnsmasq.d/blacklist.conf', '/etc/dnsmasq.d/malware.conf']
        for file_path in files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        # Support both active and commented lines (if currently disabled)
                        clean_line = line.lstrip('#').strip()
                        if clean_line.startswith('address=/'):
                            # Format: address=/domain/ip
                            match = re.search(r'address=/(.*?)/', clean_line)
                            if match:
                                domain = match.group(1)
                                blocked.append({'domain': domain, 'source': os.path.basename(file_path)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
        
    return jsonify({'domains': blocked})

def update_whitelist_domains_txt():
    """
    Syncs the Guardian's whitelist_domains.txt with whitelist.conf, custom_trust.txt,
    and enabled Smart Whitelist categories.
    This ensures that domains whitelisted via UI are also respected by Guardian.
    """
    domains = set()
    whitelist_path = '/etc/dnsmasq.d/whitelist.conf'
    custom_trust_path = '/home/dns/blocklists/custom_trust.txt'
    wl_domains_path = '/home/dns/whitelist_domains.txt'
    
    # 1. Read existing whitelist.conf (server=/domain/ip)
    if os.path.exists(whitelist_path):
        try:
            with open(whitelist_path, 'r') as f:
                for line in f:
                    match = re.search(r'server=/(.*?)/', line)
                    if match:
                        domains.add(match.group(1).lower())
        except: pass
        
    # 2. Read custom_trust.txt (raw domains)
    if os.path.exists(custom_trust_path):
        try:
            with open(custom_trust_path, 'r') as f:
                for line in f:
                    dom = line.strip().lower()
                    if dom:
                        domains.add(dom)
        except: pass

    # 3. Read Enabled Categories (Smart Whitelist)
    # This ensures that even if whitelist.conf parsing fails, these are included.
    try:
        status = load_category_status()
        for cat, data in status.items():
            if data.get('enabled', False):
                # Add static domains
                if cat in DOMAIN_CATEGORIES:
                    for d in DOMAIN_CATEGORIES[cat]['domains']:
                        domains.add(d.lower())
                # Add dynamic domains found in logs
                for d in data.get('domains', []):
                    domains.add(d.lower())
    except Exception as e:
        print(f"Error reading category status: {e}")

    # 4. Write back combined unique domains
    try:
        with open(wl_domains_path, 'w') as f:
            for domain in sorted(list(domains)):
                f.write(f"{domain}\n")
        # Ensure correct ownership
        subprocess.run(['sudo', 'chown', 'dns:dns', wl_domains_path])
    except Exception as e:
        print(f"Error updating whitelist_domains.txt: {e}")

def load_whitelist_domains():
    """
    Helper to load all whitelisted domains for analysis filtering.
    Prioritizes reading from the synced text file for speed.
    """
    whitelist_txt = '/home/dns/whitelist_domains.txt'
    domains = set()
    
    if os.path.exists(whitelist_txt):
        try:
            with open(whitelist_txt, 'r') as f:
                for line in f:
                    dom = line.strip().lower()
                    if dom:
                        domains.add(dom)
        except: pass
    else:
        # Fallback if txt doesn't exist yet
        update_whitelist_domains_txt()
        if os.path.exists(whitelist_txt):
             try:
                with open(whitelist_txt, 'r') as f:
                    for line in f:
                        dom = line.strip().lower()
                        if dom:
                            domains.add(dom)
             except: pass
        
    return domains

@app.route('/api/whitelist/add', methods=['POST'])
def add_to_whitelist():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        
    data = request.json
    domains = data.get('domains', [])
    
    if not domains:
        return jsonify({'status': 'error', 'message': 'No domains provided'})
        
    try:
        # 1. Add to DNS Whitelist (dnsmasq)
        whitelist_path = '/etc/dnsmasq.d/whitelist.conf'
        current_whitelist = set()
        
        if os.path.exists(whitelist_path):
            with open(whitelist_path, 'r') as f:
                for line in f:
                    # Parse server=/domain/8.8.8.8
                    match = re.search(r'server=/(.*?)/', line)
                    if match:
                        current_whitelist.add(match.group(1))

        added_count = 0
        new_entries = []
        for domain in domains:
            domain = domain.strip()
            if not domain: continue
            
            # Sanitize
            domain = re.sub(r'[^a-zA-Z0-9.\-\|]', '', domain)
            
            if domain not in current_whitelist:
                # Use Google DNS as upstream for whitelisted domains
                new_entries.append(f"server=/{domain}/8.8.8.8")
                current_whitelist.add(domain)
                added_count += 1
        
        if new_entries:
            with open(whitelist_path, 'a') as f:
                f.write('\n' + '\n'.join(new_entries) + '\n')

        # 1.5 Add to Custom Trust (Internet Positif Whitelist)
        custom_trust_file = '/home/dns/blocklists/custom_trust.txt'
        try:
            if not os.path.exists(os.path.dirname(custom_trust_file)):
                os.makedirs(os.path.dirname(custom_trust_file))
                
            existing_trust = set()
            if os.path.exists(custom_trust_file):
                with open(custom_trust_file, 'r') as f:
                    existing_trust = set(line.strip() for line in f if line.strip())
            
            trust_added = False
            with open(custom_trust_file, 'a') as f:
                for domain in domains:
                    domain = domain.strip()
                    if domain and domain not in existing_trust:
                        f.write(f"{domain}\n")
                        existing_trust.add(domain)
                        trust_added = True
        except Exception as e:
            print(f"Error updating custom trust: {e}")

        # 2. Remove from ALL Blocklists (blacklist.conf, malware.conf)
        remove_domains_from_blocklists(domains)

        # 3. Update Internet Positif Blocklist if active (Apply Whitelist)
        if os.path.exists('/etc/dnsmasq.d/internet_positif.conf'):
             try:
                 subprocess.run(['/usr/bin/python3', '/home/dns/scripts/update_trust_list.py'])
             except Exception as e:
                 print(f"Error running trust list update: {e}")
                    
        # Trigger reload
        subprocess.run(['sudo', 'systemctl', 'restart', 'dnsmasq'])
        
        # Sync to Guardian
        update_whitelist_domains_txt()
        
        return jsonify({'status': 'success', 'message': f"Whitelisted {added_count} domains"})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/system/status')
def get_system_status():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
        
    status = {}
    
    # Check services
    services = ['dnsmasq', 'unbound', 'nginx']
    for svc in services:
        res = subprocess.run(['systemctl', 'is-active', svc], capture_output=True, text=True)
        status[svc] = res.stdout.strip()
        
    # Check Blocking Status
    config_path = '/home/dns/guardian_config.json'
    blocking_enabled = True
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                cfg = json.load(f)
                blocking_enabled = cfg.get('blocking_enabled', True)
        except: pass
        
    status['blocking_enabled'] = blocking_enabled
    
    return jsonify(status)

# --- AUTO BLOCK SYSTEM ---

def get_autoblock_config():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT threat_type, enabled FROM auto_block_config")
        rows = c.fetchall()
        conn.close()
        
        config = {}
        for r in rows:
            config[r[0]] = bool(r[1])
        return config
    except Exception as e:
        print(f"Error reading autoblock config: {e}")
        return {}

def auto_block_worker():
    """
    Auto-blocking is now handled exclusively by guardian.py service.
    This worker is disabled to prevent conflicts.
    """
    while True:
        time.sleep(3600) # Sleep forever (1 hour)

def schedule_worker():
    # Wait for system to stabilize
    time.sleep(45)
    
    last_status = None
    
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT enabled, start_time, end_time FROM trust_schedule WHERE id=1")
            row = c.fetchone()
            conn.close()
            
            if row:
                enabled = bool(row[0])
                start_time_str = row[1]
                end_time_str = row[2]
                
                # If schedule is disabled in DB, do nothing (Manual mode overrides or stays as is)
                # Wait, if schedule is enabled, we enforce time.
                # If schedule is disabled, we assume manual control and do NOT touch it.
                # BUT, the user toggles "enabled" in the UI to turn ON the feature.
                # The "schedule" feature implies "Time Based Activation".
                
                # Logic Refinement (Fixed for Manual Override):
                # If start_time == end_time (00:00 - 00:00): MANUAL MODE.
                # If start_time != end_time: SCHEDULE MODE.
                # If Manual Mode is set, Scheduler should NOT interfere with the 'enabled' state.
                
                should_be_active = False
                is_schedule_mode = (start_time_str != end_time_str)
                
                if is_schedule_mode:
                    # Schedule Mode: Enforce time window
                    now = datetime.now()
                    current_time = now.strftime('%H:%M')
                    
                    if start_time_str > end_time_str:
                        if current_time >= start_time_str or current_time < end_time_str:
                            should_be_active = True
                    else:
                        if start_time_str <= current_time < end_time_str:
                            should_be_active = True
                    
                    # Apply State ONLY if in Schedule Mode
                    # Logic Fix: If Schedule Mode is active, we MUST enforce the calculated state (should_be_active)
                    # regardless of the current 'enabled' flag in DB (which reflects the last manual/auto state).
                    # We update the DB to match the new state so the UI reflects it.
                    
                    # Logic Fix: Use PHYSICAL file check for actual state in Scheduler
                    # Because get_trust_info() now returns DB state, we need to check the file directly
                    # to know if we need to toggle the system.
                    
                    is_currently_active = os.path.exists('/etc/dnsmasq.d/internet_positif.conf')
                    
                    if should_be_active and not is_currently_active:
                        print(f"Schedule: Activating Trust (Time: {start_time_str}-{end_time_str})")
                        if perform_trust_toggle(True):
                            # Update DB to reflect state
                            try:
                                conn_update = sqlite3.connect(DB_PATH)
                                c_update = conn_update.cursor()
                                c_update.execute("UPDATE trust_schedule SET enabled=1 WHERE id=1")
                                conn_update.commit()
                                conn_update.close()
                            except: pass
                            
                    elif not should_be_active and is_currently_active:
                        print(f"Schedule: Deactivating Trust (Time: {start_time_str}-{end_time_str})")
                        if perform_trust_toggle(False):
                            # Update DB to reflect state
                            try:
                                conn_update = sqlite3.connect(DB_PATH)
                                c_update = conn_update.cursor()
                                c_update.execute("UPDATE trust_schedule SET enabled=0 WHERE id=1")
                                conn_update.commit()
                                conn_update.close()
                            except: pass
                else:
                    # Manual Mode: Check if actual state matches DB state
                    # If DB says enabled=1 but actual is disabled, enable it.
                    # If DB says enabled=0 but actual is enabled, disable it.
                    # This fixes the UI toggle issue where refreshing reverts to actual file state instead of DB intent.
                    
                    is_currently_active = os.path.exists('/etc/dnsmasq.d/internet_positif.conf')
                    
                    if enabled and not is_currently_active:
                         print("Manual Mode: Enforcing Enabled State")
                         if perform_trust_toggle(True):
                             try:
                                 conn_update = sqlite3.connect(DB_PATH)
                                 c_update = conn_update.cursor()
                                 c_update.execute("UPDATE trust_schedule SET enabled=1 WHERE id=1")
                                 conn_update.commit()
                                 conn_update.close()
                             except: pass
                    elif not enabled and is_currently_active:
                         print("Manual Mode: Enforcing Disabled State")
                         if perform_trust_toggle(False):
                             try:
                                 conn_update = sqlite3.connect(DB_PATH)
                                 c_update = conn_update.cursor()
                                 c_update.execute("UPDATE trust_schedule SET enabled=0 WHERE id=1")
                                 conn_update.commit()
                                 conn_update.close()
                             except: pass
                        
        except Exception as e:
            print(f"Schedule Worker Error: {e}")
            
        time.sleep(60) # Check every minute

# Start Schedule Thread
schedule_thread = threading.Thread(target=schedule_worker, daemon=True)
schedule_thread.start()

# Start Auto-Block Thread
autoblock_thread = threading.Thread(target=auto_block_worker, daemon=True)
autoblock_thread.start()

def sync_trust_to_secondary(enable):
    """
    Synchronizes the DNS Trust state to the secondary node via SSH.
    Only runs if this node is PRIMARY.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT key, value FROM cluster_status")
        status = dict(c.fetchall())
        conn.close()
        
        role = status.get('role', 'PRIMARY')
        secondary_ip = status.get('secondary_ip', 'None')
        
        if role == 'PRIMARY' and secondary_ip != 'None' and secondary_ip != '127.0.0.1':
            print(f"Syncing Trust state ({enable}) to Secondary: {secondary_ip}")
            
            # Use SSH to trigger the toggle on Secondary
            # We use root as specified by user's authorized_keys location
            # Command triggers the perform_trust_toggle function directly via python
            # Escaped quotes for SSH and Python
            cmd = f"ssh -o StrictHostKeyChecking=no root@{secondary_ip} 'python3 -c \"import sys; sys.path.append(\\\"/home/dns/web_gui\\\"); from app import perform_trust_toggle; perform_trust_toggle({enable})\"'"
            
            def run_ssh():
                try:
                    subprocess.run(cmd, shell=True, capture_output=True, text=True)
                except Exception as e:
                    print(f"SSH Sync Error: {e}")
            
            thread = threading.Thread(target=run_ssh)
            thread.start()
            return True
    except Exception as e:
        print(f"Error in sync_trust_to_secondary: {e}")
    return False

def sync_whitelist_to_secondary():
    """
    Syncs Global Whitelist (IPs and Domains) to Secondary via SSH.
    This ensures firewall and DNS rules are consistent.
    """
    try:
        # Only PRIMARY should sync
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT value FROM cluster_status WHERE key='role' LIMIT 1")
        row = c.fetchone()
        
        if not row or row[0] != 'PRIMARY':
            conn.close()
            return # Not primary
            
        c.execute("SELECT value FROM cluster_status WHERE key='secondary_ip' LIMIT 1")
        row = c.fetchone()
        conn.close()
        
        if not row: return # No secondary found
        
        secondary_ip = row[0]
        
        def sync_task():
            # 1. Sync whitelist.conf
            if os.path.exists('/home/dns/whitelist.conf'):
                run_command(f"scp -o StrictHostKeyChecking=no /home/dns/whitelist.conf root@{secondary_ip}:/home/dns/whitelist.conf")
            
            # 2. Sync custom_trust.txt
            if os.path.exists('/home/dns/blocklists/custom_trust.txt'):
                run_command(f"ssh -o StrictHostKeyChecking=no root@{secondary_ip} 'mkdir -p /home/dns/blocklists'")
                run_command(f"scp -o StrictHostKeyChecking=no /home/dns/blocklists/custom_trust.txt root@{secondary_ip}:/home/dns/blocklists/custom_trust.txt")
            
            # 3. Trigger firewall setup and guardian restart on secondary
            run_command(f"ssh -o StrictHostKeyChecking=no root@{secondary_ip} 'sudo /home/dns/setup_firewall.sh && sudo systemctl restart dnsmdnet-guardian'")
            
            # 4. Trigger DNS Trust update on secondary if possible
            if os.path.exists('/home/dns/scripts/update_trust_list.py'):
                run_command(f"ssh -o StrictHostKeyChecking=no root@{secondary_ip} 'python3 /home/dns/scripts/update_trust_list.py'")
            
            # 5. Restart secondary dnsmasq/unbound for domain changes
            run_command(f"ssh -o StrictHostKeyChecking=no root@{secondary_ip} 'sudo systemctl restart dnsmasq && sudo systemctl restart unbound'")

        threading.Thread(target=sync_task).start()
    except Exception as e:
        print(f"Error syncing whitelist to secondary: {e}")

def perform_trust_toggle(enable):
    blocklist_file = '/etc/dnsmasq.d/internet_positif.conf'
    blocklist_disabled = '/home/dns/blocklists/disabled/internet_positif.conf'
    legacy_disabled = '/etc/dnsmasq.d/internet_positif.conf.disabled'
    
    # Ensure disabled directory exists
    if not os.path.exists('/home/dns/blocklists/disabled'):
        run_command('sudo mkdir -p /home/dns/blocklists/disabled')
        run_command('sudo chown dns:dns /home/dns/blocklists/disabled')

    # Migrate legacy disabled file if present
    if os.path.exists(legacy_disabled):
        run_command(f"sudo mv {legacy_disabled} {blocklist_disabled}")

    # Trigger Sync to Secondary if this is Primary
    sync_trust_to_secondary(enable)

    if enable:
        # Enable Blocklist using the update script which handles whitelisting
        print("Enabling DNS Trust...")
        
        # Check if source exists, if not try to update
        if not os.path.exists(blocklist_disabled):
            run_command("sudo bash /home/dns/update_blocklist.sh")
            
        # Run the update script
        # It reads disabled/internet_positif.conf, applies whitelist, and writes to /etc/dnsmasq.d/
        res = subprocess.run(['/usr/bin/python3', '/home/dns/scripts/update_trust_list.py'], capture_output=True, text=True)
        if res.returncode != 0:
            print(f"Error enabling trust: {res.stderr}")
            return False
            
        run_command("sudo bash /home/dns/setup_firewall.sh")
        safe_service_restart(background=True)
        return True
    else:
        # Disable Blocklist
        if os.path.exists(blocklist_file):
            if not os.path.exists('/home/dns/blocklists/disabled'):
                run_command('sudo mkdir -p /home/dns/blocklists/disabled')
            # We don't move back, we just remove the active file because the master copy is in disabled/
            run_command(f"sudo rm {blocklist_file}")
        
        # Ensure no stray .disabled files
        run_command("sudo rm -f /etc/dnsmasq.d/*.disabled")

        run_command("sudo bash /home/dns/setup_firewall.sh")
        safe_service_restart(background=True)
        return True

@app.route('/api/autoblock/config', methods=['GET', 'POST'])
def autoblock_config_endpoint():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        
    if request.method == 'GET':
        return jsonify(get_autoblock_config())
        
    if request.method == 'POST':
        try:
            data = request.json
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            
            for threat_type, enabled in data.items():
                c.execute("INSERT OR REPLACE INTO auto_block_config (threat_type, enabled) VALUES (?, ?)", 
                          (threat_type, 1 if enabled else 0))
            
            conn.commit()
            conn.close()
            return jsonify({'status': 'success', 'config': get_autoblock_config()})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    password = data.get('password')
    stored_hash = get_stored_password()
    input_hash = hashlib.sha256(password.encode()).hexdigest()
    
    print(f"DEBUG LOGIN: Input='{password}', InputHash='{input_hash}', StoredHash='{stored_hash}'")
    
    if input_hash == stored_hash:
        session['authenticated'] = True
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Invalid password'}), 401

@app.route('/api/system/role', methods=['GET'])
def get_system_role_info():
    """Determine if this node is a License Generator (Master) or Client"""
    # Check if Private Key exists -> Master
    is_master = os.path.exists("/home/dns/web_gui/private_key.pem")
    return jsonify({'status': 'success', 'is_master': is_master})

# --- LICENSE API (HYBRID: GENERATOR & CLIENT) ---

# Client: Check Status
@app.route('/api/license/status', methods=['GET'])
def license_status_client():
    status = license_manager.get_current_license_status()
    return jsonify(status)

# Client: Activate
@app.route('/api/license/activate', methods=['POST'])
def activate_license_client():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        
    data = request.json
    key = data.get('key', '').strip()
    
    success, msg, info = license_manager.activate_client_license(key)
    if success:
        return jsonify({'status': 'success', 'message': msg, 'plan': info['plan']})
    return jsonify({'status': 'error', 'message': msg})

# Generator: List (Only if Master)
@app.route('/api/license/list', methods=['GET'])
def list_licenses_route():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    # Optional: Enforce Master Check
    if not os.path.exists("/home/dns/web_gui/private_key.pem"):
         return jsonify({'status': 'error', 'message': 'Access Denied: Not a License Generator Node'}), 403
         
    licenses = license_manager.list_licenses()
    return jsonify({'status': 'success', 'licenses': licenses})

# Generator: Generate (Only if Master)
@app.route('/api/license/generate', methods=['POST'])
def generate_license_route():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    if not os.path.exists("/home/dns/web_gui/private_key.pem"):
         return jsonify({'status': 'error', 'message': 'Access Denied: Not a License Generator Node'}), 403
    
    data = request.json
    client_name = data.get('client_name', 'Unknown')
    plan = data.get('plan', 'PRO')
    duration = data.get('duration', 365)
    
    result = license_manager.generate_license(client_name, plan, duration)
    if "error" in result:
        return jsonify({'status': 'error', 'message': result['error']}), 500
        
    return jsonify({'status': 'success', 'license': result})

@app.route('/api/license/features', methods=['GET'])
def license_features():
    plan = request.args.get('plan', 'PRO')
    features = license_manager.get_plan_features(plan)
    return jsonify({'status': 'success', 'plan': plan, 'features': features})

@app.route('/api/license/revoke', methods=['POST'])
def revoke_license_route():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    data = request.json
    key = data.get('key')
    
    if license_manager.revoke_license(key):
        return jsonify({'status': 'success', 'message': 'License revoked'})
    return jsonify({'status': 'error', 'message': 'License not found'}), 404

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('authenticated', None)
    return jsonify({'status': 'success'})

@app.route('/api/check_auth')
def check_auth():
    return jsonify({'authenticated': is_authenticated()})

@app.route('/api/change_password', methods=['POST'])
def change_password():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    data = request.json
    new_password = data.get('new_password')
    if not new_password or len(new_password) < 4:
        return jsonify({'status': 'error', 'message': 'Password too short'}), 400
    
    hashed = hashlib.sha256(new_password.encode()).hexdigest()
    with open(PASSWORD_FILE, 'w') as f:
        f.write(hashed)
    return jsonify({'status': 'success'})

def get_server_ip():
    try:
        # Try ens18 or default route
        cmd = "ip route get 1.1.1.1 | grep -oP 'src \K\S+'"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.stdout.strip():
            return res.stdout.strip()
    except:
        pass
    return "127.0.0.1"

# --- WAF & SECURITY LAYER ---
def get_allowed_ips():
    allowed = ['127.0.0.1', get_server_ip()]
    whitelist_path = '/home/dns/whitelist.conf'
    if os.path.exists(whitelist_path):
        try:
            with open(whitelist_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        allowed.append(line)
        except:
            pass
    return list(set(allowed))

def check_ip():
    client_ip = request.remote_addr
    # Also check X-Forwarded-For if behind a proxy
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0]
    
    allowed_ips = get_allowed_ips()
    
    # Check direct IP match
    if client_ip in allowed_ips:
        return True
        
    # Check subnet match
    try:
        import ipaddress
        client_obj = ipaddress.ip_address(client_ip)
        for entry in allowed_ips:
            if '/' in entry:
                if client_obj in ipaddress.ip_network(entry):
                    return True
    except:
        pass
        
    print(f"DEBUG: Connection attempt from {client_ip} REJECTED")
    return False

def waf_check():
    # Basic protection against common attacks
    path = request.path
    
    # Patterns for SQLi, XSS, Path Traversal
    patterns = [
        r"(['\"%27])", # Single/Double quotes or encoded
        r"(--|%23|#)", # SQL comments
        r"(<script|script>|alert\()", # XSS
        r"(\.\.\/|\.\.\\)", # Path Traversal
        r"(UNION\s+SELECT|SELECT.*FROM|INSERT\s+INTO|DELETE\s+FROM|DROP\s+TABLE)", # SQLi keywords
        r"(eval\(|exec\(|system\()", # RCE
    ]

    # 1. Check Path (only for traversal)
    if re.search(r"(\.\.\/|\.\.\\)", path):
        return True

    # 2. Check Query Parameters (Values only)
    for key, value in request.args.items():
        for pattern in patterns:
            if re.search(pattern, str(value), re.IGNORECASE) or re.search(pattern, str(key), re.IGNORECASE):
                return True

    # 3. Check Request Body
    try:
        data = request.get_data().decode('utf-8', errors='ignore')
        if data:
            for pattern in patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    return True
    except:
        pass

    return False

@app.before_request
def before_request():
    # if not check_ip():
    #     return jsonify({'status': 'error', 'message': 'Access Denied: Your IP is not whitelisted'}), 403
    pass
    
    # Exclude API endpoints from WAF check (prevent false positives blocking Web GUI)
    if request.path.startswith('/api/'):
        # Allow all API paths - WAF patterns can block valid JSON/query params
        return
    if request.path.startswith('/static/') or request.path == '/favicon.ico' or request.path == '/health':
        return

    if waf_check():
        print(f"WAF BLOCK: Path={request.path}, Body={request.get_data().decode('utf-8', errors='ignore')}")
        return jsonify({'status': 'error', 'message': 'Security Block: Malicious activity detected'}), 403

# --- GLOBAL STATS STATE ---
last_unbound_stats = {}

STATS_FILE = '/dev/shm/dns_stats.json'

def get_unbound_stats():
    """
    Get detailed stats from Unbound and calculate rates.
    """
    global last_unbound_stats
    
    # Try to load from file if memory is empty (persistence across restarts)
    if not last_unbound_stats and os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, 'r') as f:
                last_unbound_stats = json.load(f)
        except: pass
    
    try:
        # Get current cumulative stats (try without sudo first, then fallback)
        output = ""
        try:
            res = subprocess.run(['unbound-control', 'stats_noreset'], capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and res.stdout:
                output = res.stdout
        except Exception:
            output = ""
        if not output:
            try:
                res = subprocess.run(['sudo', 'unbound-control', 'stats_noreset'], capture_output=True, text=True, timeout=3)
                if res.returncode == 0 and res.stdout:
                    output = res.stdout
            except Exception:
                output = ""
        if not output:
            raise RuntimeError("unbound-control not accessible")
        
        current_stats = {}
        for line in output.split('\n'):
            if '=' in line:
                key, value = line.split('=')
                try:
                    current_stats[key] = float(value)
                except:
                    pass
        
        now = time.time()
        result = {
            'queries': 0,
            'cachehits': 0,
            'cachemiss': 0,
            'recursive': 0,
            'expired': 0,
            'reqlist_avg': current_stats.get('total.requestlist.avg', 0),
            'reqlist_max': current_stats.get('total.requestlist.max', 0),
            'rectime_avg': current_stats.get('total.recursion.time.avg', 0),
            'rectime_med': current_stats.get('total.recursion.time.median', 0)
        }

        # Calculate Rates if we have previous data
        if last_unbound_stats and 'time' in last_unbound_stats:
            time_diff = now - last_unbound_stats['time']
            
            # If time_diff is valid (> 0.5s)
            if time_diff > 0.5:
                # Check for restart (current < last)
                if current_stats.get('total.num.queries', 0) < last_unbound_stats.get('total.num.queries', 0):
                     # Restart detected, reset baseline
                     pass 
                else:
                    result['queries'] = (current_stats.get('total.num.queries', 0) - last_unbound_stats.get('total.num.queries', 0)) / time_diff
                    result['cachehits'] = (current_stats.get('total.num.cachehits', 0) - last_unbound_stats.get('total.num.cachehits', 0)) / time_diff
                    result['cachemiss'] = (current_stats.get('total.num.cachemiss', 0) - last_unbound_stats.get('total.num.cachemiss', 0)) / time_diff
                    result['recursive'] = (current_stats.get('total.num.recursivereplies', 0) - last_unbound_stats.get('total.num.recursivereplies', 0)) / time_diff
                    result['expired'] = (current_stats.get('total.num.expired', 0) - last_unbound_stats.get('total.num.expired', 0)) / time_diff
                    
                    # Store calculated rates for fallback
                    result['last_rates'] = True
            else:
                 # Time diff too small (refresh spam), return last known rates if available
                 if 'cached_rates' in last_unbound_stats:
                     return last_unbound_stats['cached_rates']
        
        # Update state (store raw cumulative values)
        last_unbound_stats = current_stats
        last_unbound_stats['time'] = now
        # Cache the calculated result for short-term fallbacks
        last_unbound_stats['cached_rates'] = result
        
        # Persist to file
        try:
            with open(STATS_FILE, 'w') as f:
                json.dump(last_unbound_stats, f)
        except: pass
        
        return result
    except Exception as e:
        print(f"Error getting unbound stats: {e}")
        # Fallback: return last cached rates if available, otherwise approximate using frontend QPS
        if last_unbound_stats and 'cached_rates' in last_unbound_stats:
            return last_unbound_stats['cached_rates']
        try:
            frontend_qps, _ = get_traffic_stats()
        except Exception:
            frontend_qps = 0
        return {
            'queries': frontend_qps, 'cachehits': 0, 'cachemiss': 0, 'recursive': 0, 'expired': 0,
            'reqlist_avg': 0, 'reqlist_max': 0, 'rectime_avg': 0, 'rectime_med': 0
        }

def get_blacklist_rate():
    """
    Estimate blacklist hit rate from dnsmasq log (Optimized)
    """
    try:
        # Better: use awk to count matches in last 5 seconds
        cmd = f"sudo tail -n 5000 /var/log/dnsmasq.log | awk -v now=\"$(date +%H:%M:%S)\" -v window=5 '" \
              r'BEGIN { count=0; split(now, n, ":"); now_sec = n[1]*3600 + n[2]*60 + n[3]; } ' \
              r'/config .* is 0.0.0.0|config .* is 103.68.213.74/ { ' \
              r'  split($3, t, ":"); log_sec = t[1]*3600 + t[2]*60 + t[3]; ' \
              r'  if (now_sec - log_sec <= window && now_sec - log_sec >= 0) count++; ' \
              r"} END { print count }'"
              
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2).stdout.strip()
        count = int(result) if result else 0
        return round(count / 5.0, 1) # Per second
    except:
        return 0

def get_any_attack_rate():
    """
    Count ANY queries that are being blocked (Indicative of Attack)
    """
    try:
        # Grep for blocked ANY queries in last 5 seconds
        # A block usually follows the query in the log
        cmd = f"sudo tail -n 5000 /var/log/dnsmasq.log | grep -B 1 -E 'is 0.0.0.0|is 103.68.213.74' | grep -c 'query\\[ANY\\]'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2).stdout.strip()
        count = int(result) if result else 0
        return round(count / 5.0, 1) # Per second
    except:
        return 0

@app.route('/api/stats/extended')
def extended_stats_final_api():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
        
    ub_stats = get_unbound_stats()
    bl_rate = get_blacklist_rate()
    any_rate = get_any_attack_rate()
    frontend_qps, _ = get_traffic_stats()
    
    # Reload config to get latest limits
    guardian_config = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                guardian_config = json.load(f)
        except: pass
    limit_query = guardian_config.get("limit_query_per_min", 1000)

    if ub_stats:
        ub_stats['blacklist'] = bl_rate
        ub_stats['any_attack'] = any_rate
        ub_stats['frontend_qps'] = frontend_qps
        
        # Calculate approximate Frontend Cache Hits (Frontend QPS - Unbound QPS)
        # Ensure non-negative
        backend_qps = ub_stats['queries']
        frontend_hits = max(0, frontend_qps - backend_qps)
        
        # Format for display
        return jsonify({
            'status': 'success',
            'data': ub_stats,
            'limit_query': limit_query,
            'formatted': {
                'frontend_qps': f"{int(frontend_qps)} queries/s",
                'frontend_hits': f"{int(frontend_hits)} queries/s",
                'queries': f"{int(ub_stats['queries'])} queries/s",
                'cachehits': f"{int(ub_stats['cachehits'])} queries/s",
                'cachemiss': f"{int(ub_stats['cachemiss'])} queries/s",
                'blacklist': f"{int(bl_rate)} queries/s",
                'any_attack': f"{int(any_rate)} attack/s",
                'recursive': f"{int(ub_stats['recursive'])} queries/s",
                'expired': f"{int(ub_stats['expired'])} queries/s",
                'reqlist': f"{ub_stats['reqlist_avg']:.5f} avg, {int(ub_stats['reqlist_max'])} max",
                'rectime': f"{ub_stats['rectime_avg']:.6f} avg, {ub_stats['rectime_med']:.6e} med"
            }
        })
    else:
        # Fallback to zeros if stats collection failed (but structure is valid)
        return jsonify({
             'status': 'success',
             'data': {
                 'queries': 0, 'cachehits': 0, 'cachemiss': 0, 'recursive': 0, 'expired': 0,
                 'reqlist_avg': 0, 'reqlist_max': 0, 'rectime_avg': 0, 'rectime_med': 0,
                 'blacklist': bl_rate, 'any_attack': any_rate, 'frontend_qps': frontend_qps
             },
             'limit_query': limit_query,
             'formatted': {
                'frontend_qps': f"{int(frontend_qps)} queries/s",
                'frontend_hits': "0 queries/s",
                'queries': "0 queries/s", 'cachehits': "0 queries/s", 'cachemiss': "0 queries/s",
                'blacklist': f"{int(bl_rate)} queries/s", 
                'any_attack': f"{int(any_rate)} attack/s",
                'recursive': "0 queries/s", 'expired': "0 queries/s",
                'reqlist': "0 avg, 0 max", 'rectime': "0 avg, 0 med"
             }
        })

@app.route('/api/stats/cache')
def cache_stats_endpoint():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get raw stats without rate calculation
        output = ""
        try:
            res = subprocess.run(['unbound-control', 'stats_noreset'], capture_output=True, text=True, timeout=3)
            if res.returncode == 0 and res.stdout:
                output = res.stdout
        except Exception as e:
            print(f"Unbound stats error: {e}")
            pass
            
        stats = {}
        if output:
            for line in output.split('\n'):
                if '=' in line:
                    key, value = line.split('=')
                    try:
                        stats[key] = float(value)
                    except:
                        stats[key] = value
        
        # Extract relevant info
        total_queries = int(stats.get('total.num.queries', 0))
        total_hits = int(stats.get('total.num.cachehits', 0))
        total_misses = int(stats.get('total.num.cachemiss', 0))
        total_prefetch = int(stats.get('total.num.prefetch', 0))
        total_expired = int(stats.get('total.num.expired', 0))
        
        hit_rate = 0
        if total_queries > 0:
            hit_rate = (total_hits / total_queries) * 100
            
        return jsonify({
            'status': 'success',
            'data': {
                'total_queries': total_queries,
                'total_hits': total_hits,
                'total_misses': total_misses,
                'total_prefetch': total_prefetch,
                'total_expired': total_expired,
                'hit_rate': f"{hit_rate:.1f}%",
                'msg_cache_size': read_unbound_setting('msg-cache-size') or 'N/A',
                'rrset_cache_size': read_unbound_setting('rrset-cache-size') or 'N/A'
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/logs/blacklist')
def get_blacklist_logs():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Load Internet Positif List ONLY
        internet_positif_list = set()
        if os.path.exists('/etc/dnsmasq.d/internet_positif.conf'):
            try:
                with open('/etc/dnsmasq.d/internet_positif.conf', 'r') as f:
                    for line in f:
                        m = re.search(r'address=/(.*?)/', line)
                        if m: internet_positif_list.add(m.group(1).lower())
            except: pass

        output = ""
        # Search for 'config' or 'query[ANY]'
        cmds = [
            f"{SUDO_CMD}tail -n 100000 /var/log/dnsmasq.log | grep -E 'config|query\\[ANY\\]' | tail -n 1000"
        ]
        for cmd in cmds:
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                if r.returncode == 0 and r.stdout:
                    output = r.stdout
                    break
            except Exception:
                continue
        
        domain_stats = {}
        any_attack_info = {} # domain -> set(ips)
        
        # Process logs
        if output:
            lines = output.split('\n')
            for line in lines:
                if not line: continue
                
                # Detect ANY query attack and capture IP
                if 'query[ANY]' in line:
                    m_any = re.search(r'query\[ANY\]\s+(.+)\s+from\s+([\d\.]+)', line)
                    if m_any:
                        dom = m_any.group(1).lower()
                        ip = m_any.group(2)
                        if dom not in any_attack_info:
                            any_attack_info[dom] = set()
                        any_attack_info[dom].add(ip)
                    continue

                # Detect config block
                match = re.search(r'^([A-M][a-z]{2}\s+\d+\s+\d+:\d+:\d+).*config\s+(.+)\s+is\s+([0-9.]+)', line)
                if match:
                    ts = match.group(1)
                    dom = match.group(2)
                    d_lower = dom.lower()
                    
                    # STRICT FILTERING: Only include if it's ANY attack or in Internet Positif
                    is_ip = d_lower in internet_positif_list
                    is_any = d_lower in any_attack_info
                    
                    if not (is_ip or is_any):
                        continue

                    if dom not in domain_stats:
                        domain_stats[dom] = {'count': 0, 'latest_ts': ts, 'is_any': is_any, 'is_ip': is_ip, 'ips': []}
                    
                    domain_stats[dom]['count'] += 1
                    domain_stats[dom]['latest_ts'] = ts
                    if is_any: 
                        domain_stats[dom]['is_any'] = True
                        domain_stats[dom]['ips'] = list(any_attack_info[d_lower])
        
        logs = []
        for domain, stats in domain_stats.items():
            if stats['is_any']:
                block_type = "⚠️ ANY QUERY ATTACK DETECTED"
                attacker_ip = ", ".join(stats['ips']) if stats['ips'] else "N/A"
            elif stats['is_ip']:
                block_type = "INTERNET POSITIF"
                attacker_ip = "SYSTEM (DNS TRUST)"
            else:
                continue # Should not happen due to filtering above
                
            logs.append({
                'timestamp': stats['latest_ts'],
                'domain': domain,
                'type': block_type,
                'hits': stats['count'],
                'attacker_ip': attacker_ip
            })
        
        # Newest first
        return jsonify({'status': 'success', 'logs': list(reversed(logs))})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Clear dnsmasq.log
        subprocess.run(['sudo', 'truncate', '-s', '0', '/var/log/dnsmasq.log'], check=False)
        # Clear guardian.log
        subprocess.run(['sudo', 'truncate', '-s', '0', '/home/dns/guardian.log'], check=False)
        return jsonify({'status': 'success', 'message': 'Logs cleared successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# --- BLACKLIST MANAGEMENT APIs ---
@app.route('/api/blacklist/list')
def get_blacklist():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    
    blacklist = []
    if os.path.exists('/etc/dnsmasq.d/blacklist.conf'):
        try:
            with open('/etc/dnsmasq.d/blacklist.conf', 'r') as f:
                for line in f:
                    m = re.search(r'address=/(.*?)/', line)
                    if m: blacklist.append(m.group(1))
        except: pass
    
    return jsonify({'status': 'success', 'blacklist': blacklist})

@app.route('/api/blacklist/manage', methods=['POST'])
def manage_blacklist():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    action = data.get('action') # 'add' or 'remove'
    domain = data.get('domain')
    
    if not domain:
        return jsonify({'status': 'error', 'message': 'Domain required'})
        
    fpath = '/etc/dnsmasq.d/blacklist.conf'
    
    try:
        # Read existing
        lines = []
        if os.path.exists(fpath):
            with open(fpath, 'r') as f:
                lines = f.readlines()
        
        # Filter out duplicates or the target domain
        new_lines = []
        found = False
        
        for line in lines:
            if f"address=/{domain}/" in line:
                found = True
                if action == 'remove':
                    continue # Skip to remove
            new_lines.append(line)
            
        if action == 'add' and not found:
            new_lines.append(f"address=/{domain}/0.0.0.0\n")
            
        # Write back
        with open(fpath, 'w') as f:
            f.writelines(new_lines)
            
        # Restart dnsmasq to apply
        subprocess.run(['sudo', 'systemctl', 'restart', 'dnsmasq'], check=False)
        
        return jsonify({'status': 'success', 'message': f'Domain {domain} {action}ed successfully'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# --- END WAF ---

# SERVFAIL logs - REMOVED per user request
@app.route('/api/logs/servfail')
def get_servfail_logs():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'status': 'success', 'logs': []})

@app.route('/api/logs/threats')
def get_threat_logs():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'status': 'success', 'logs': []})



# Simple in-memory storage for traffic stats
traffic_data = []

# Define sudo command based on user privileges
SUDO_CMD = "sudo " if os.geteuid() != 0 else ""

def get_traffic_stats():
    try:
        # Optimization: Use awk to count queries in the last 5 seconds directly in shell
        # This is much faster than pulling 200k lines into Python
        # FIXED: Use relative time from the log's latest entry to handle logging latency/buffering
        # IMPROVED: Also check against system time to avoid stale stats if log stopped updating
        window_size = 5
        
        # Calculate current second of day in Python (Local Time) to match log timestamps
        now = datetime.now()
        current_sec = now.hour * 3600 + now.minute * 60 + now.second
        
        # Count queries in the last 5 seconds relative to the latest log timestamp
        # We look for 'query[' and check the timestamp (parts[2])
        # Note: dnsmasq logs are in 'Feb 14 18:32:25' format
        # Increased tail to 50000 to handle high traffic (>10k QPS)
        cmd = f"{SUDO_CMD}tail -n 50000 /var/log/dnsmasq.log | awk -v window={window_size} -v current_sec={current_sec} '" \
              r'BEGIN { max_sec=0; count=0; } ' \
              r'/query\[/ { ' \
              r'  split($3, t, ":"); log_sec = t[1]*3600 + t[2]*60 + t[3]; ' \
              r'  times[NR] = log_sec; ' \
              r'  if (log_sec > max_sec) max_sec = log_sec; ' \
              r'} ' \
              r'END { ' \
              r'  diff = current_sec - max_sec; ' \
              r'  if (diff < 0) { ' \
              r'    if (diff > -60) diff = 0; ' \
              r'    else diff += 86400; ' \
              r'  } ' \
              r'  if (diff > 300) { print 0; exit; } ' \
              r'  limit = max_sec - window; ' \
              r'  if (limit < 0) limit += 86400; ' \
              r'  for (i in times) { ' \
              r'    if (max_sec >= window) { ' \
              r'      if (times[i] > limit && times[i] <= max_sec) count++; ' \
              r'    } else { ' \
              r'      if (times[i] <= max_sec || times[i] > limit) count++; ' \
              r'    } ' \
              r'  } ' \
              r'  print count ' \
              r"}'"
        
        # Increase timeout to 5s and add logging
        # print(f"DEBUG CMD: {cmd}", file=sys.stderr)
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        result = proc.stdout.strip()
        
        # Debug logging to journal
        if proc.stderr:
            print(f"Traffic Stats Error: {proc.stderr}")
        
        total_queries = int(result) if result else 0
        qps = round(total_queries / window_size, 1)
        
        # print(f"DEBUG: Traffic Stats QPS={qps}, Total={total_queries}")
        return qps, total_queries
    except Exception as e:
        print(f"Error in get_traffic_stats: {e}")
        return 0, 0

def get_per_ip_traffic_stats(limit=20):
    """
    Get top IPs by query count in last 5 minutes
    Returns: {ip: queries, rate_limit_status}
    """
    try:
        # Fixed: IP is at $8 in dnsmasq log format "Feb 14 18:32:25 dnsmasq[...]: query[A] domain from IP"
        cmd = f"{SUDO_CMD}tail -n 50000 /var/log/dnsmasq.log | grep 'query\\[' | awk '{{print $8}}' | cut -d'#' -f1 | sort | uniq -c | sort -rn | head -n {limit}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        
        if not result:
            return []
        
        per_ip_data = []
        for line in result.split('\n'):
            try:
                parts = line.strip().split()
                if len(parts) >= 2:
                    count = int(parts[0])
                    ip = parts[1]
                    
                    # Check if IP is rate-limited (very high query spike)
                    rate_limit_status = "normal"
                    if count > 10000:  # More than 10000 queries in 5 min window = ~2000 QPS
                        rate_limit_status = "high"
                    elif count > 5000:  # More than 5000 = ~1000 QPS
                        rate_limit_status = "elevated"
                    
                    per_ip_data.append({
                        'ip': ip,
                        'queries': count,
                        'qps': round(count / 5, 1),  # Rough QPS estimate
                        'status': rate_limit_status
                    })
            except:
                continue
        
        return per_ip_data
    except Exception as e:
        print(f"Error in get_per_ip_traffic_stats: {e}")
        return []

def get_servfail_stats(limit=5):
    """
    Get SERVFAIL error statistics
    DISABLED: Returns empty list to prevent confusion with blocking logic
    """
    return []

def get_blocklist_stats(limit=10):
    """
    Get RATE LIMIT hits from dnsmasq logs
    Tracks domains blocked by blacklist configuration (Rate Limit)
    Returns: [{'domain': domain, 'blocked': count, 'percentage': pct}, ...]
    """
    try:
        # Load Whitelist to filter out false positives
        whitelist = load_whitelist_domains()

        # Load Blacklist (Rate Limit List)
        blacklist = set()
        if os.path.exists('/etc/dnsmasq.d/blacklist.conf'):
            with open('/etc/dnsmasq.d/blacklist.conf', 'r') as f:
                for line in f:
                    match = re.search(r'address=/(.*?)/', line)
                    if match:
                        blacklist.add(match.group(1).lower())
                        
        # Get total queries
        # Reduced tail from 100000 to 50000 to prevent timeout
        cmd_total = f"{SUDO_CMD}tail -n 50000 /var/log/dnsmasq.log | grep 'query\\[' | wc -l"
        total_result = subprocess.run(cmd_total, shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        total_queries = int(total_result) if total_result else 1
        
        # Find blocked domains (queries that were denied/replied with NXDOMAIN or 0.0.0.0)
        # dnsmasq marks blocked queries with specific patterns in logs
        server_ip = get_server_ip()
        server_ip_esc = server_ip.replace('.', '\\.')
        
        # Match "config domain is IP" or "reply domain is IP"
        # We look for 0.0.0.0, 127.0.0.1, or the Server IP (for block page redirect)
        cmd_blocked = f"{SUDO_CMD}tail -n 50000 /var/log/dnsmasq.log | grep -E 'config|reply' | grep -E ' is (0\\.0\\.0\\.0|127\\.0\\.0\\.1|{server_ip_esc})$' | awk '{{print $6}}' | sort | uniq -c | sort -rn | head -n {limit * 3}"
        blocked_result = subprocess.run(cmd_blocked, shell=True, capture_output=True, text=True, timeout=5).stdout.strip()

        
        blocklist_data = []
        
        if blocked_result:
            for line in blocked_result.split('\n'):
                try:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        count = int(parts[0])
                        domain = parts[1]
                        domain_lower = domain.lower()
                        
                        # FILTER: Skip if currently whitelisted
                        if domain_lower in whitelist:
                            continue
                        
                        # Check parent domains in whitelist
                        parts_dom = domain_lower.split('.')
                        is_whitelisted = False
                        for i in range(len(parts_dom)-1):
                            parent = ".".join(parts_dom[i:])
                            if parent in whitelist:
                                is_whitelisted = True
                                break
                        if is_whitelisted:
                            continue

                        # FILTER: ONLY include if in blacklist (Rate Limit)
                        in_blacklist = False
                        if domain_lower in blacklist:
                            in_blacklist = True
                        else:
                            # Check parent domains in blacklist
                            for i in range(len(parts_dom)-1):
                                parent = ".".join(parts_dom[i:])
                                if parent in blacklist:
                                    in_blacklist = True
                                    break
                        
                        if not in_blacklist: continue

                        percentage = round((count / total_queries) * 100, 2) if total_queries > 0 else 0
                        
                        blocklist_data.append({
                            'domain': domain,
                            'blocked': count,
                            'percentage': percentage
                        })
                except:
                    continue
        
        return blocklist_data[:limit]
    except Exception as e:
        print(f"Error in get_blocklist_stats: {e}")
        return []

# --- DNS SETTINGS MANAGEMENT ---

def read_dnsmasq_setting(key):
    """Read a setting from dnsmasq config files"""
    try:
        for config_file in ['/etc/dnsmasq.d/00-base.conf', '/etc/dnsmasq.conf']:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    for line in f:
                        if line.strip().startswith(key + '='):
                            value = line.split('=', 1)[1].strip()
                            return value
    except:
        pass
    return None

def read_unbound_setting(key):
    """Read a setting from unbound config files"""
    try:
        # Check all relevant config files
        config_files = [
            '/etc/unbound/unbound.conf.d/smartdns.conf',
            '/etc/unbound/unbound.conf.d/security-hardening.conf',
            '/etc/unbound/unbound.conf'
        ]
        
        for config_file in config_files:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    for line in f:
                        if key + ':' in line and not line.strip().startswith('#'):
                            parts = line.split(':', 1)
                            if len(parts) > 1:
                                value = parts[1].strip()
                                return value
    except:
        pass
    return None

def get_dns_settings():
    """Get current DNS performance settings"""
    return {
        'dnsmasq': {
            'cache_size': read_dnsmasq_setting('cache-size') or '100000',
            'dns_forward_max': read_dnsmasq_setting('dns-forward-max') or '10000',
            'min_cache_ttl': read_dnsmasq_setting('min-cache-ttl') or '300',
            'max_cache_ttl': read_dnsmasq_setting('max-cache-ttl') or '86400',
        },
        'unbound': {
            'num_threads': read_unbound_setting('num-threads') or '8',
            'ratelimit': read_unbound_setting('ratelimit') or '50000',
            'ip_ratelimit': read_unbound_setting('ip-ratelimit') or '2000',
            'msg_cache_size': read_unbound_setting('msg-cache-size') or '100m',
            'rrset_cache_size': read_unbound_setting('rrset-cache-size') or '100m',
        },
        'limits': {
            'qps_alert_threshold': '200',  # Alert when > 200 QPS
            'max_allowed_qps': '2000',
            'cache_hit_target': '70',  # Target 70% cache hit rate
        }
    }

def update_dnsmasq_setting(key, value):
    """Update dnsmasq setting in config file"""
    try:
        config_file = '/etc/dnsmasq.d/00-base.conf'
        if not os.path.exists(config_file):
            return False
        
        with open(config_file, 'r') as f:
            lines = f.readlines()
        
        updated = False
        for i, line in enumerate(lines):
            if line.strip().startswith(key + '='):
                lines[i] = f"{key}={value}\n"
                updated = True
                break
        
        if not updated:
            lines.append(f"{key}={value}\n")
        
        with open(config_file, 'w') as f:
            f.writelines(lines)
        
        return True
    except Exception as e:
        print(f"Error updating dnsmasq setting: {e}")
        return False

def update_unbound_setting(key, value):
    """Update unbound setting in config file"""
    try:
        config_file = '/etc/unbound/unbound.conf.d/smartdns.conf'
        if not os.path.exists(config_file):
            return False
        
        with open(config_file, 'r') as f:
            lines = f.readlines()
        
        updated = False
        for i, line in enumerate(lines):
            if key + ':' in line and not line.strip().startswith('#'):
                indent = len(line) - len(line.lstrip())
                lines[i] = f"{' ' * indent}{key}: {value}\n"
                updated = True
                break
        
        if not updated:
            lines.append(f"    {key}: {value}\n")
        
        with open(config_file, 'w') as f:
            f.writelines(lines)
        
        return True
    except Exception as e:
        print(f"Error updating unbound setting: {e}")
        return False

def restart_dns_services():
    """Restart dnsmasq and unbound services"""
    try:
        # Test configs first
        test_dnsmasq = subprocess.run(['sudo', 'dnsmasq', '--test'], capture_output=True, text=True)
        if test_dnsmasq.returncode != 0:
            return {'status': 'error', 'message': 'Invalid dnsmasq config', 'detail': test_dnsmasq.stderr}
        
        test_unbound = subprocess.run(['unbound-checkconf'], capture_output=True, text=True)
        if test_unbound.returncode != 0:
            return {'status': 'error', 'message': 'Invalid unbound config', 'detail': test_unbound.stderr}
        
        # Restart services
        subprocess.run(['sudo', 'systemctl', 'restart', 'dnsmasq'], timeout=10)
        subprocess.run(['sudo', 'systemctl', 'restart', 'unbound'], timeout=10)
        
        time.sleep(2)
        return {'status': 'success', 'message': 'Services restarted successfully'}
    except Exception as e:
        return {'status': 'error', 'message': f'Error restarting services: {e}'}

# --- TRAFFIC HISTORY DB ---
# DB_PATH moved to top of file


def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS traffic 
                     (timestamp DATETIME PRIMARY KEY, qps REAL, queries INTEGER)''')
        c.execute('''CREATE TABLE IF NOT EXISTS cluster_status
                     (key TEXT PRIMARY KEY, value TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS trust_schedule
                     (id INTEGER PRIMARY KEY, enabled INTEGER, start_time TEXT, end_time TEXT, trust_ips TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS auto_block_config
                     (threat_type TEXT PRIMARY KEY, enabled INTEGER)''')
        c.execute('''CREATE TABLE IF NOT EXISTS threat_keywords
                     (keyword TEXT PRIMARY KEY)''')
        
        # Default schedule (disabled, 00:00 to 00:00, default IPs)
        c.execute("INSERT OR IGNORE INTO trust_schedule (id, enabled, start_time, end_time, trust_ips) VALUES (1, 0, '00:00', '00:00', '8.8.8.8, 1.1.1.1')")
        
        # Default role is PRIMARY
        c.execute("INSERT OR IGNORE INTO cluster_status (key, value) VALUES ('role', 'PRIMARY')")
        c.execute("INSERT OR IGNORE INTO cluster_status (key, value) VALUES ('last_sync_received', 'Never')")
        c.execute("INSERT OR IGNORE INTO cluster_status (key, value) VALUES ('secondary_ip', 'None')")
        
        conn.commit()
        conn.close()
        # Set permissions
        subprocess.run(['sudo', 'chown', 'dns:dns', DB_PATH])
    except Exception as e:
        print(f"DB Init Error: {e}")

init_db()

def background_collector():
    # Delay start to let system stabilize
    time.sleep(10)
    while True:
        try:
            qps, snapshot = get_traffic_stats()
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            # Store data with minute-level precision (every 5 mins)
            timestamp = datetime.now().replace(second=0, microsecond=0).strftime('%Y-%m-%d %H:%M:%S')
            c.execute("INSERT OR REPLACE INTO traffic (timestamp, qps, queries) VALUES (?, ?, ?)", 
                      (timestamp, qps, snapshot))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Background collector error: {e}")
        time.sleep(300) # Record every 5 minutes

# Start background thread
collector_thread = threading.Thread(target=background_collector, daemon=True)
collector_thread.start()

@app.route('/api/traffic/history')
def traffic_history():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    range_type = request.args.get('range', 'daily') # daily, monthly, yearly
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    if range_type == 'monthly':
        # Daily averages for last 30 days
        c.execute('''SELECT strftime('%m-%d', timestamp) as day, AVG(qps), MAX(queries)
                     FROM traffic 
                     WHERE timestamp >= date('now', '-30 days')
                     GROUP BY day ORDER BY timestamp ASC''')
    elif range_type == 'yearly':
        # Monthly averages for last 12 months
        c.execute('''SELECT strftime('%Y-%m', timestamp) as month, AVG(qps), MAX(queries)
                     FROM traffic 
                     WHERE timestamp >= date('now', '-1 year')
                     GROUP BY month ORDER BY timestamp ASC''')
    else:
        # Last 24 hours (hourly averages)
        c.execute('''SELECT strftime('%H:00', timestamp) as hour, AVG(qps), MAX(queries)
                     FROM traffic 
                     WHERE timestamp >= datetime('now', '-24 hours')
                     GROUP BY hour ORDER BY timestamp ASC''')
    
    rows = c.fetchall()
    conn.close()
    
    result = []
    for r in rows:
        result.append({
            'time': r[0],
            'qps': round(r[1], 1),
            'queries': int(r[2])
        })
    return jsonify(result)

@app.route('/api/traffic')
def traffic():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    global traffic_data
    current_time = datetime.now().strftime('%H:%M:%S')
    qps, snapshot = get_traffic_stats()
    
    traffic_data.append({
        'time': current_time, 
        'qps': qps,
        'queries': snapshot
    })
    
    if len(traffic_data) > 20:
        traffic_data.pop(0)
        
    return jsonify(traffic_data)

@app.route('/api/traffic/per-ip')
def traffic_per_ip():
    """Get per-IP traffic analysis for high-performance monitoring"""
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    limit = request.args.get('limit', 20, type=int)
    per_ip_data = get_per_ip_traffic_stats(limit=limit)
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'overall': {
            'qps': get_traffic_stats()[0],
            'total_ips': len(per_ip_data)
        },
        'top_ips': per_ip_data,
        'rate_limits': {
            'global': '100000 QPS',
            'per_ip': '20000 QPS',
            'com_domain': '5000 QPS'
        }
    })

@app.route('/api/traffic/servfail')
def traffic_servfail():
    """Get SERVFAIL error statistics - DISABLED"""
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    # DISABLED: Return empty stats to prevent confusion
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_servfail_errors': 0,
            'affected_domains': 0,
            'error_rate': "0.00%"
        },
        'top_domains': []
    })

@app.route('/api/traffic/blocklist')
def traffic_blocklist():
    """Get blocklist hits and blocked domains"""
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    limit = request.args.get('limit', 10, type=int)
    blocklist_data = get_blocklist_stats(limit=limit)
    
    # Calculate total blocked count
    total_blocked = sum(item['blocked'] for item in blocklist_data)
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_blocked': total_blocked,
            'blocked_domains': len(blocklist_data),
            'block_rate': f"{sum(item['percentage'] for item in blocklist_data):.2f}%"
        },
        'top_domains': blocklist_data
    })

def get_threat_stats(limit=10):
    """
    Get ANY attack and Internet Positif hits from logs.
    STRICTLY filters to only show these two categories as requested by user.
    """
    try:
        # Load Internet Positif List
        internet_positif_list = set()
        if os.path.exists('/etc/dnsmasq.d/internet_positif.conf'):
            try:
                with open('/etc/dnsmasq.d/internet_positif.conf', 'r') as f:
                    for line in f:
                        m = re.search(r'address=/(.*?)/', line)
                        if m: internet_positif_list.add(m.group(1).lower())
            except: pass

        # Get total queries for percentage
        cmd_total = "sudo tail -n 50000 /var/log/dnsmasq.log | grep 'query\\[' | wc -l"
        total_result = subprocess.run(cmd_total, shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        total_queries = int(total_result) if total_result and int(total_result) > 0 else 1
        
        # Get logs with 'config' or 'query[ANY]'
        output = ""
        cmd = f"{SUDO_CMD}tail -n 50000 /var/log/dnsmasq.log | grep -E 'config|query\\[ANY\\]' | tail -n 2000"
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                output = r.stdout
        except: pass

        if not output:
            return []

        # Parse logs for hits
        domain_hits = {}
        any_attack_domains = set()
        
        lines = output.split('\n')
        for line in lines:
            if not line: continue
            
            # Detect ANY query
            if 'query[ANY]' in line:
                m_any = re.search(r'query\[ANY\]\s+(.+)\s+from', line)
                if m_any:
                    any_attack_domains.add(m_any.group(1).lower())
                continue
                
            # Detect block
            match = re.search(r'config\s+(.+)\s+is\s+([0-9.]+)', line)
            if match:
                domain = match.group(1)
                d_lower = domain.lower()
                
                # Check if it's ANY or IP
                is_any = d_lower in any_attack_domains
                is_ip = d_lower in internet_positif_list
                
                if is_any or is_ip:
                    domain_hits[domain] = domain_hits.get(domain, 0) + 1

        threat_data = []
        for domain, count in domain_hits.items():
            d_lower = domain.lower()
            block_type = "⚠️ ANY QUERY ATTACK" if d_lower in any_attack_domains else "INTERNET POSITIF"
            
            percentage = round((count / total_queries) * 100, 2) if total_queries > 0 else 0
            
            threat_data.append({
                'domain': domain,
                'threat': count,
                'type': block_type,
                'percentage': percentage
            })

        # Sort by hit count
        threat_data.sort(key=lambda x: x['threat'], reverse=True)
        return threat_data[:limit]
    except Exception as e:
        print(f"Error in get_threat_stats: {e}")
        return []

@app.route('/api/traffic/threats')
def traffic_threats():
    """Get cyber threat statistics"""
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    try:
        limit = request.args.get('limit', 10, type=int)
        threat_data = get_threat_stats(limit=limit) or []
        
        total_threats = sum(item.get('threat', 0) for item in threat_data)
        threat_rate = 0.0
        if threat_data:
             threat_rate = sum(item.get('percentage', 0) for item in threat_data)

        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_threats': total_threats,
                'threat_domains': len(threat_data),
                'threat_rate': f"{threat_rate:.2f}%"
            },
            'top_domains': threat_data
        })
    except Exception as e:
        print(f"Error in traffic_threats: {e}")
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'summary': {'total_threats': 0, 'threat_domains': 0, 'threat_rate': "0.00%"},
            'top_domains': []
        })

def get_service_status(service_name):
    try:
        # Use full path to systemctl to avoid PATH issues
        cmd = ['/usr/bin/systemctl', 'is-active', service_name]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.strip() == 'active'
    except Exception as e:
        print(f"Error checking service {service_name}: {e}")
        return False

def run_command(command, timeout=30):
    return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)

def safe_service_restart(background=False):
    """
    ISP-Scale Safety: Test configurations before restarting services.
    If a config is invalid, do NOT restart and return the error.
    Optionally restart in background to avoid HTTP timeouts.
    """
    # 1. Test Dnsmasq
    test_dnsmasq = run_command("sudo dnsmasq --test")
    if test_dnsmasq.returncode != 0:
        return False, f"Dnsmasq config error: {test_dnsmasq.stderr.strip()}"
    
    # 2. Test Unbound
    test_unbound = run_command("sudo unbound-checkconf")
    if test_unbound.returncode != 0:
        return False, f"Unbound config error: {test_unbound.stderr.strip()}"
    
    # 3. Restart if all good
    if background:
        def restart_task():
            # Add small delay to allow response to be sent
            time.sleep(0.5)
            # RESTART dnsmasq (Required for config changes to take effect)
            run_command("sudo systemctl restart dnsmasq")
            # Unbound needs restart for some config changes
            run_command("sudo systemctl restart unbound")
        threading.Thread(target=restart_task).start()
        return True, "Services restarting in background"
    else:
        # RESTART dnsmasq
        run_command("sudo systemctl restart dnsmasq")
        run_command("sudo systemctl restart unbound")
        return True, "Services restarted successfully"

@app.route('/health')
def health():
    """Simple health check for monitoring (no auth required)"""
    return jsonify({'status': 'ok', 'service': 'dnsmars-gui'}), 200

@app.route('/')
def index():
    resp = make_response(render_template('index.html'))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/api/manual/pdf')
def download_manual_pdf():
    # Public access for manual
    path = "/home/dns/web_gui/static/manual.pdf"
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name="Buku_Panduan_DNS_MarsData.pdf")
    return jsonify({'status': 'error', 'message': 'File not found'}), 404

@app.route('/api/manual/html')
def view_manual_html():
    # Public access for manual
    # Generate HTML from Markdown on the fly for latest content
    try:
        import markdown
        with open("/home/dns/PANDUAN_SISTEM.md", "r") as f:
            content = f.read()
        html_content = markdown.markdown(content, extensions=['extra', 'codehilite'])
        
        # Add basic styling to make it look good
        styled_html = f"""
        <html>
        <head>
            <title>Manual - PT MARS DATA TELEKOMUNIKASI</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
            <style>
                body {{ font-family: 'Inter', sans-serif; line-height: 1.6; max-width: 800px; margin: 40px auto; padding: 0 20px; color: #333; }}
                h1, h2 {{ color: #003399; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
                h3 {{ color: #0044cc; margin-top: 30px; }}
                code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; font-family: monospace; }}
                pre {{ background: #f4f4f4; padding: 15px; border-radius: 8px; overflow-x: auto; border: 1px solid #ddd; }}
                hr {{ border: 0; border-top: 1px solid #eee; margin: 40px 0; }}
                .footer {{ margin-top: 50px; font-size: 0.8em; color: #777; text-align: center; border-top: 1px solid #eee; padding-top: 20px; }}
            </style>
        </head>
        <body>
            {html_content}
            <div class="footer">
                &copy; 2026 PT MARS DATA TELEKOMUNIKASI
            </div>
        </body>
        </html>
        """
        return styled_html
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error generating HTML: {e}'}), 500

def get_iptables_status():
    try:
        # Check for NAT redirection in both IPv4 and IPv6
        nat_v4 = subprocess.run(['sudo', 'iptables', '-t', 'nat', '-L', 'PREROUTING', '-n'], capture_output=True, text=True)
        nat_v6 = subprocess.run(['sudo', 'ip6tables', '-t', 'nat', '-L', 'PREROUTING', '-n'], capture_output=True, text=True)
        
        # Use iptables-save for more reliable module detection (hashlimit, connlimit)
        save_res = subprocess.run(['sudo', 'iptables-save'], capture_output=True, text=True)
        
        # NAT is considered active if REDIRECT exists in either IPv4 or IPv6
        is_nat_active = 'REDIRECT' in nat_v4.stdout or 'REDIRECT' in nat_v6.stdout
        
        return {
            'nat': is_nat_active,
            'flood_prot': 'hashlimit' in save_res.stdout,
            'conn_limit': 'connlimit' in save_res.stdout
        }
    except:
        return {'nat': False, 'flood_prot': False, 'conn_limit': False}

def get_dns_performance():
    try:
        # Measure response time for local query
        start = time.time()
        subprocess.run(['dig', '@127.0.0.1', 'google.com', '+short'], capture_output=True, timeout=2)
        end = time.time()
        latency = (end - start) * 1000
        # Performance percentage: 100% if < 10ms, drops as latency increases
        perf = max(0, min(100, 100 - (latency - 10) / 2)) if latency > 10 else 100
        return round(perf, 1)
    except:
        return 0

def get_network_info():
    try:
        import yaml
        with open('/etc/netplan/00-installer-config.yaml', 'r') as f:
            config = yaml.safe_load(f)
            
        ip4 = ""
        ip4_gw = ""
        ip6 = ""
        ip6_gw = ""
        
        if 'network' in config and 'ethernets' in config['network']:
            ifname = list(config['network']['ethernets'].keys())[0]
            iface = config['network']['ethernets'][ifname]
            
            # Extract addresses
            for addr in iface.get('addresses', []):
                if ':' in addr:
                    ip6 = addr
                else:
                    ip4 = addr
            
            # Extract gateways (from routes)
            for route in iface.get('routes', []):
                if route.get('to') == 'default':
                    via = route.get('via', '')
                    if ':' in via:
                        ip6_gw = via
                    else:
                        ip4_gw = via
        
        return {
            'ip4': ip4,
            'ip4_gw': ip4_gw,
            'ip6': ip6,
            'ip6_gw': ip6_gw,
            'ipv6_enabled': bool(ip6)
        }
    except Exception as e:
        print(f"Error reading netplan: {e}")
        # Try reading via sudo cat if direct read fails
        try:
            res = subprocess.run(['sudo', 'cat', '/etc/netplan/00-installer-config.yaml'], capture_output=True, text=True)
            if res.returncode == 0:
                config = yaml.safe_load(res.stdout)
                ip4 = ""
                ip4_gw = ""
                ip6 = ""
                ip6_gw = ""
                
                if 'network' in config and 'ethernets' in config['network']:
                    ifname = list(config['network']['ethernets'].keys())[0]
                    iface = config['network']['ethernets'][ifname]
                    for addr in iface.get('addresses', []):
                        if ':' in addr: ip6 = addr
                        else: ip4 = addr
                    for route in iface.get('routes', []):
                        if route.get('to') == 'default':
                            via = route.get('via', '')
                            if ':' in via: ip6_gw = via
                            else: ip4_gw = via
                return {'ip4': ip4, 'ip4_gw': ip4_gw, 'ip6': ip6, 'ip6_gw': ip6_gw, 'ipv6_enabled': bool(ip6)}
        except: pass
        return {'ip4': '', 'ip4_gw': '', 'ip6': '', 'ip6_gw': '', 'ipv6_enabled': False}

def get_trust_info():
    try:
        # Source of Truth: Database (User Intent)
        # We must reflect what the user WANTS, not necessarily what the file system has (which might be syncing)
        is_enabled = False
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT enabled FROM trust_schedule WHERE id=1")
            row = c.fetchone()
            if row:
                is_enabled = bool(row[0])
        except Exception as e:
            print(f"Error reading trust schedule in get_trust_info: {e}")
        finally:
            if 'conn' in locals() and conn:
                conn.close()

        return {'enabled': is_enabled, 'ip': 'Local DB'}
    except:
        return {'enabled': False, 'ip': ''}

@app.route('/api/status')
def status():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    fw_status = get_iptables_status()
    cpu_usage = psutil.cpu_percent()
    ram_usage = psutil.virtual_memory().percent
    dns_perf = get_dns_performance()
    net_info = get_network_info()
    trust_info = get_trust_info()
    
    # Check DNSSEC status
    dnssec_active = False
    try:
        # Check if proxy-dnssec is in any dnsmasq config
        # ISP Scale: check 00-base.conf
        base_conf = "/etc/dnsmasq.d/00-base.conf"
        if os.path.exists(base_conf):
            with open(base_conf, 'r') as f:
                if 'proxy-dnssec' in f.read():
                    dnssec_active = True
    except:
        pass

    # Guardian Logs
    guardian_logs = []
    if os.path.exists('/home/dns/guardian.log'):
        try:
            with open('/home/dns/guardian.log', 'r') as f:
                guardian_logs = f.readlines()[-5:] # Last 5 events
        except:
            pass
            
    # Whitelist info (Combined IP and Domain)
    whitelist = []
    whitelist_ips = []
    whitelist_domains = []

    # 1. Load IPs from Firewall Whitelist
    if os.path.exists('/home/dns/whitelist.conf'):
        try:
            with open('/home/dns/whitelist.conf', 'r') as f:
                lines = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
                whitelist.extend(lines)
                whitelist_ips.extend(lines)
        except:
            pass

    # 2. Load Domains from Custom Trust
    if os.path.exists('/home/dns/blocklists/custom_trust.txt'):
        try:
            with open('/home/dns/blocklists/custom_trust.txt', 'r') as f:
                lines = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
                whitelist.extend(lines)
                whitelist_domains.extend(lines)
        except:
            pass
    
    # Deduplicate
    whitelist = list(set(whitelist))
    whitelist_ips = list(set(whitelist_ips))
    whitelist_domains = list(set(whitelist_domains))

    # HDD Usage
    hdd_usage = 0
    try:
        hdd = psutil.disk_usage('/')
        hdd_usage = hdd.percent
    except:
        pass

    # Debug: Check if it's already authenticated
    auth_status = is_authenticated()

    return jsonify({
        'authenticated': auth_status,
        'dnsmasq': get_service_status('dnsmasq'),
        'unbound': get_service_status('unbound'),
        'dnssec': dnssec_active,
        'resolved': get_service_status('systemd-resolved'),
        'guardian': get_service_status('guardian'),
        'iptables': fw_status.get('nat', False) if isinstance(fw_status, dict) else False,
        'security': {
            'flood_protection': fw_status.get('flood_prot', False) if isinstance(fw_status, dict) else False,
            'connection_limit': fw_status.get('conn_limit', False) if isinstance(fw_status, dict) else False,
            'guardian_logs': guardian_logs,
            'whitelist': whitelist,
            'whitelist_ips': whitelist_ips,
            'whitelist_domains': whitelist_domains
        },
        'metrics': {
            'cpu': cpu_usage,
            'ram': ram_usage,
            'hdd': hdd_usage,
            'dns_perf': dns_perf
        },
        'network': net_info or {},
        'trust': trust_info or {}
    })

def get_system_ips():
    ips = {'ipv4': [], 'ipv6': []}
    try:
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            if iface == 'lo': continue
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ips['ipv4'].append(addr.address)
                elif addr.family == socket.AF_INET6:
                    # Ignore link-local addresses
                    if not addr.address.startswith('fe80'):
                        ips['ipv6'].append(addr.address)
    except Exception as e:
        print(f"Error getting system IPs: {e}")
    return ips

@app.route('/api/dig', methods=['POST'])
def dig():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    data = request.json
    domain = data.get('domain', 'google.com')
    qtype = data.get('qtype', 'A')
    
    domain = re.sub(r'[^a-zA-Z0-9.-]', '', domain)
    if qtype not in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
        qtype = 'A'
        
    system_ips = get_system_ips()
    # Unique targets starting with loopbacks
    targets = []
    for t in ['127.0.0.1', '::1']:
        if t not in targets: targets.append(t)
    for t in system_ips['ipv4'] + system_ips['ipv6']:
        if t not in targets: targets.append(t)
    
    results = []
    for target in targets:
        dig_target = f"@{target}"
        cmd = f"dig {dig_target} {domain} {qtype} +short +time=1 +tries=1"
        try:
            proc = run_command(cmd)
            output = (proc.stdout or '').strip()
            full_output = (proc.stderr or '') + (proc.stdout or '')
        except subprocess.TimeoutExpired:
            output = "TIMEOUT"
            full_output = "timeout"
        except Exception as e:
            output = ""
            full_output = str(e)
        
        # If +short is empty, try without +short to see if there's an error
        if not output:
            full_cmd = f"dig {dig_target} {domain} {qtype} +time=1 +tries=1"
            try:
                proc2 = run_command(full_cmd)
                full_output = (proc2.stdout or '') + (proc2.stderr or '')
            except Exception:
                full_output = ""
            if "connection timed out" in full_output.lower():
                output = "TIMEOUT"
            elif "communications error" in full_output.lower() or "connection refused" in full_output.lower():
                output = "CONNECTION REFUSED"
            elif "network is unreachable" in full_output.lower():
                output = "NETWORK UNREACHABLE"
            else:
                output = "NO RECORD" if not output else output
                
        results.append(f"[{target}] -> {output}")
        
    return jsonify({'result': "\n".join(results)})

@app.route('/api/list/<list_type>', methods=['GET'])
def list_domains(list_type):
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    file_path = ""
    if list_type == 'blacklist':
        file_path = "/etc/dnsmasq.d/blacklist.conf"
    elif list_type == 'whitelist':
        file_path = "/etc/dnsmasq.d/whitelist.conf"
    else:
        return jsonify({'status': 'error', 'message': 'Invalid list type'}), 400
        
    domains = []
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    # Format for blacklist: address=/domain/0.0.0.0
                    # Format for whitelist: server=/domain/8.8.8.8
                    match = re.search(r'/(.*?)/', line)
                    if match:
                        domains.append(match.group(1))
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
            
    return jsonify({'status': 'success', 'domains': domains, 'count': len(domains)})

@app.route('/api/action', methods=['POST'])
def action():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    data = request.json
    cmd_type = data.get('type')
    domain = data.get('domain', '').strip()
    dns_ip = data.get('dns_ip', '').strip()
    ipv6_ip = data.get('ipv6_ip', '').strip()
    
    # Network fields
    ip4_addr = data.get('ip4_addr', '').strip()
    ip4_gw = data.get('ip4_gw', '').strip()
    ip6_addr = data.get('ip6_addr', '').strip()
    ip6_gw = data.get('ip6_gw', '').strip()
    ipv6_enabled = data.get('ipv6_enabled', False)
    
    # Trust fields
    trust_ip = data.get('trust_ip', '').strip()
    trust_enabled = data.get('trust_enabled', False)
    
    # Whitelist fields
    whitelist_data = data.get('whitelist', '').strip()
    
    # Sanitize domain
    if domain:
        # Allow pipe | for complex botnet domains
        domain = re.sub(r'[^a-zA-Z0-9.\-\|]', '', domain)
    
    # Sanitize IPs
    if dns_ip:
        # Allow dots, numbers, spaces and commas for multiple IPs
        dns_ip = re.sub(r'[^0-9., ]', '', dns_ip)
    if ipv6_ip:
        ipv6_ip = re.sub(r'[^a-fA-F0-9:/, ]', '', ipv6_ip)
    if ip4_addr:
        ip4_addr = re.sub(r'[^0-9./]', '', ip4_addr)
    if ip4_gw:
        ip4_gw = re.sub(r'[^0-9.]', '', ip4_gw)
    if ip6_addr:
        ip6_addr = re.sub(r'[^a-fA-F0-9:/]', '', ip6_addr)
    if ip6_gw:
        ip6_gw = re.sub(r'[^a-fA-F0-9:]', '', ip6_gw)
    if trust_ip:
        trust_ip = re.sub(r'[^0-9.]', '', trust_ip)
        
    if cmd_type == 'update_whitelist':
        try:
            # Smart Whitelist: Separate IPs and Domains
            raw_lines = [l.strip() for l in whitelist_data.split('\n') if l.strip()]
            ips = []
            domains = []
            
            # Regex for IP (IPv4/IPv6) and CIDR
            ip_pattern = re.compile(r'^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?$|'  # IPv4
                                  r'^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(/[0-9]+)?$') # IPv6 (Simple)

            for line in raw_lines:
                # Remove comments
                if line.startswith('#'): continue
                
                # Check if IP
                if ip_pattern.match(line) or ':' in line: # Fallback for complex IPv6
                    ips.append(line)
                else:
                    # Assume Domain
                    # Sanitize domain
                    d = re.sub(r'[^a-zA-Z0-9._\-]', '', line)
                    if d: domains.append(d)

            # 1. Handle IPs (Firewall)
            content = "# Dynamic Whitelist Configuration\n# Format: IP or Subnet (one per line)\n"
            content += "\n".join(ips)
            
            with open('/home/dns/whitelist.conf', 'w') as f:
                f.write(content)
            
            # 2. Handle Domains (DNS - Custom Trust)
            with open('/home/dns/blocklists/custom_trust.txt', 'w') as f:
                f.write("\n".join(domains))

            # Apply Changes
            errors = []
            
            # A. Firewall
            try:
                run_command("sudo /home/dns/setup_firewall.sh")
                # Use correct service name
                run_command("sudo systemctl restart dnsmdnet-guardian")
            except Exception as e:
                errors.append(f"Firewall Error: {e}")

            # B. DNS Whitelist (Update Internet Positif / DNSMasq)
            try:
                # Update trust list logic
                if os.path.exists('/home/dns/scripts/update_trust_list.py'):
                    subprocess.run(['/usr/bin/python3', '/home/dns/scripts/update_trust_list.py'])
                
                # Also ensure they are in whitelist.conf as server entries (Bypass Blocklists)
                current_wl_content = ""
                if os.path.exists('/etc/dnsmasq.d/whitelist.conf'):
                     with open('/etc/dnsmasq.d/whitelist.conf', 'r') as f:
                         current_wl_content = f.read()
                
                new_wl_entries = ""
                for d in domains:
                    # Point to local Unbound to ensure proper resolution while bypassing blocklists
                    entry = f"server=/{d}/127.0.0.1#5353"
                    if entry not in current_wl_content:
                        new_wl_entries += f"{entry}\n"
                
                if new_wl_entries:
                    # Use sudo tee to append to protected file
                    run_command(f"echo '{new_wl_entries}' | sudo tee -a /etc/dnsmasq.d/whitelist.conf")
                
                # Trigger Sync to Secondary
                sync_whitelist_to_secondary()
                
                safe_service_restart(background=True)
            except Exception as e:
                errors.append(f"DNS Error: {e}")

            if errors:
                return jsonify({'status': 'warning', 'message': 'Whitelist updated with errors: ' + "; ".join(errors)})
                
            return jsonify({'status': 'success', 'message': 'Global Whitelist updated (Firewall & DNS)'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})

    elif cmd_type == 'restart_dnsmasq':
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
    elif cmd_type == 'restart_unbound':
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
    elif cmd_type == 'clear_cache':
        run_command("sudo unbound-control flush_zone .")
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
    elif cmd_type == 'blacklist':
        domains = data.get('domains', [])
        if domain:
            domains.append(domain)
            
        if not domains:
             return jsonify({'status': 'error', 'message': 'No domain provided'})

        action_val = data.get('action', 'add')
        
        if action_val == 'add':
            count, msg = block_domains_internal(domains)
            if count == 0 and "already" not in msg:
                return jsonify({'status': 'error', 'message': msg})
        elif action_val == 'remove':
            # Bulk remove
            for d in domains:
                d = re.sub(r'[^a-zA-Z0-9.\-\|]', '', d) # Sanitize
                if d:
                    run_command(f"sudo sed -i '/address=\/{d}\//d' /etc/dnsmasq.d/blacklist.conf")
        
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
        return jsonify({'status': 'success', 'message': f'Processed {len(domains)} domains for blacklist'})

    elif cmd_type == 'whitelist':
        domains = data.get('domains', [])
        if domain:
            domains.append(domain)

        if not domains:
             return jsonify({'status': 'error', 'message': 'No domain provided'})

        action_val = data.get('action', 'add')
        
        for d in domains:
            d = re.sub(r'[^a-zA-Z0-9._\-\|]', '', d) # Sanitize (Allow underscore for SRV/PTR)
            if not d: continue
            
            if action_val == 'add':
                # 1. Remove from blacklist if exists
                blacklist_path = "/etc/dnsmasq.d/blacklist.conf"
                if os.path.exists(blacklist_path):
                    run_command(f"sudo sed -i '/address=\/{d}\//d' {blacklist_path}")
                
                # 2. Add to whitelist.conf with Local Unbound (127.0.0.1#5353) to prevent leaks
                # This ensures the client sees YOUR IP as the resolver, not Google
                run_command(f"echo 'server=/{d}/127.0.0.1#5353' | sudo tee -a /etc/dnsmasq.d/whitelist.conf")
                
                # 3. Add to Custom Trust (Internet Positif Whitelist)
                custom_trust_file = '/home/dns/blocklists/custom_trust.txt'
                try:
                    # Check if already exists
                    exists = False
                    if os.path.exists(custom_trust_file):
                        with open(custom_trust_file, 'r') as f:
                            if d in [line.strip() for line in f]:
                                exists = True
                    if not exists:
                        with open(custom_trust_file, 'a') as f:
                            f.write(f"{d}\n")
                except: pass

            elif action_val == 'remove':
                run_command(f"sudo sed -i '/server=\/{d}\//d' /etc/dnsmasq.d/whitelist.conf")
                # Remove from custom trust
                custom_trust_file = '/home/dns/blocklists/custom_trust.txt'
                try:
                    if os.path.exists(custom_trust_file):
                        run_command(f"sudo sed -i '/^{d}$/d' {custom_trust_file}")
                except: pass
            
        # Update Internet Positif Blocklist if active (Apply Whitelist)
        if os.path.exists('/etc/dnsmasq.d/internet_positif.conf'):
             subprocess.run(['/usr/bin/python3', '/home/dns/scripts/update_trust_list.py'])
            
        # 3. Restart services safely
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
        return jsonify({'status': 'success', 'message': f'Processed {len(domains)} domains for whitelist'})

    elif cmd_type == 'update_whitelist':
        whitelist_data = data.get('whitelist', '')
        
        # Validate and filter IPs/CIDRs
        valid_entries = []
        for line in whitelist_data.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Simple regex for IPv4/IPv6/CIDR
            if re.match(r'^[0-9a-fA-F:./]+$', line):
                valid_entries.append(line)
        
        try:
            # Write to /home/dns/whitelist.conf for Firewall
            with open('/home/dns/whitelist.conf', 'w') as f:
                f.write('\n'.join(valid_entries))
            
            # Apply Firewall Rules
            run_command("sudo bash /home/dns/setup_firewall.sh")
            
            # Restart services to ensure consistency
            success, msg = safe_service_restart()
            if not success:
                 return jsonify({'status': 'error', 'message': msg})
                 
            return jsonify({'status': 'success', 'message': 'Global Whitelist updated and Firewall applied'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})

    elif cmd_type == 'update_ssh':
        run_command("sudo apt-get update && sudo apt-get install --only-upgrade openssh-server -y")
    elif cmd_type == 'update_firewall':
        run_command("sudo chmod +x /home/dns/setup_firewall.sh && sudo /home/dns/setup_firewall.sh")
    elif cmd_type == 'malware_shield':
        # Redirect malware domains to 0.0.0.0
        cmd = f"curl -s https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | grep '^0.0.0.0' | awk '{{print \"address=/\"$2\"/0.0.0.0\"}}' | sudo tee /etc/dnsmasq.d/malware.conf > /dev/null"
        run_command(cmd)
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
    elif cmd_type == 'change_dns' and dns_ip:
        # Support multiple IPs separated by comma or space
        ips = re.split(r'[,\s]+', dns_ip)
        forward_lines = "\n".join([f"    forward-addr: {ip.strip()}" for ip in ips if ip.strip()])
        forward_conf = f"forward-zone:\n    name: \".\"\n{forward_lines}\n"
        run_command(f"echo '{forward_conf}' | sudo tee /etc/unbound/unbound.conf.d/forward.conf")
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
    elif cmd_type == 'update_network':
        try:
            import yaml
            # Load existing config
            config = None
            try:
                with open('/etc/netplan/00-installer-config.yaml', 'r') as f:
                    config = yaml.safe_load(f)
            except:
                res = subprocess.run(['sudo', 'cat', '/etc/netplan/00-installer-config.yaml'], capture_output=True, text=True)
                if res.returncode == 0:
                    config = yaml.safe_load(res.stdout)
            
            if not config:
                return jsonify({'status': 'error', 'message': 'Could not read netplan config'})
            
            # Find the first ethernet interface
            if 'network' in config and 'ethernets' in config['network']:
                ifname = list(config['network']['ethernets'].keys())[0]
                iface = config['network']['ethernets'][ifname]
                
                # Update addresses with validation
                def validate_cidr(addr, max_prefix):
                    if '/' in addr:
                        parts = addr.split('/')
                        if len(parts) == 2:
                            try:
                                prefix = int(parts[1])
                                if 0 <= prefix <= max_prefix:
                                    return addr
                            except ValueError:
                                pass
                    return None

                ip4_with_cidr = validate_cidr(ip4_addr, 32) or (f"{ip4_addr}/24" if '/' not in ip4_addr else None)
                if not ip4_with_cidr:
                    return jsonify({'status': 'error', 'message': f'Invalid IPv4 prefix length in {ip4_addr}'})
                
                new_addrs = [ip4_with_cidr]
                
                if ipv6_enabled and ip6_addr:
                    ip6_with_cidr = validate_cidr(ip6_addr, 128) or (f"{ip6_addr}/64" if '/' not in ip6_addr else None)
                    if not ip6_with_cidr:
                        return jsonify({'status': 'error', 'message': f'Invalid IPv6 prefix length in {ip6_addr}'})
                    new_addrs.append(ip6_with_cidr)
                
                iface['addresses'] = new_addrs
                
                # Update routes
                new_routes = [{'to': 'default', 'via': ip4_gw}]
                if ipv6_enabled and ip6_gw:
                    new_routes.append({'to': 'default', 'via': ip6_gw})
                iface['routes'] = new_routes
                
                # Write to temp file
                temp_yaml = '/home/dns/new_netplan.yaml'
                with open(temp_yaml, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False)
                
                # Apply changes
                # Netplan apply can be slow and might disconnect, so we use a longer timeout or no timeout
                cmd = f"sudo mv {temp_yaml} /etc/netplan/00-installer-config.yaml && sudo chmod 600 /etc/netplan/00-installer-config.yaml && sudo netplan apply"
                apply_res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if apply_res.returncode != 0:
                    return jsonify({'status': 'error', 'message': f'Netplan apply failed: {apply_res.stderr}'})
                
                # Update system via central script
                run_command(f"sudo bash /home/dns/update_system_ip.sh")
                
                return jsonify({'status': 'success', 'message': 'Network settings updated. System is restarting with new IP.'})
            else:
                return jsonify({'status': 'error', 'message': 'Invalid netplan structure'})
                
        except Exception as e:
            print(f"Network update error: {e}")
            return jsonify({'status': 'error', 'message': str(e)})
        
    elif cmd_type == 'toggle_ipv6':
        enabled = data.get('enabled', False)
        if enabled:
            run_command("sudo sed -i '/listen-address=127.0.0.1/s/$/,::1/' /home/dns/dnsmasq_smartdns.conf")
            run_command("sudo sed -i 's/do-ip6: no/do-ip6: yes/' /home/dns/unbound_smartdns.conf")
            run_command("sudo sed -i '/interface: 127.0.0.1/a \    interface: ::1' /home/dns/unbound_smartdns.conf")
        else:
            run_command("sudo sed -i 's/,::1//' /home/dns/dnsmasq_smartdns.conf")
            run_command("sudo sed -i 's/do-ip6: yes/do-ip6: no/' /home/dns/unbound_smartdns.conf")
            run_command("sudo sed -i '/interface: ::1/d' /home/dns/unbound_smartdns.conf")
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': msg})
        return jsonify({'status': 'success', 'message': 'IPv6 settings updated'})
    elif cmd_type == 'toggle_trust':
        # ISP Scale: Toggle local content filtering (Internet Positif)
        trust_enabled = data.get('trust_enabled', False)
        
        # SYNC WITH SCHEDULE DB
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            if trust_enabled:
                # Force Manual Mode (Always Active) to prevent scheduler from disabling it
                # if the current time is outside the previous schedule range.
                c.execute("UPDATE trust_schedule SET enabled=1, start_time='00:00', end_time='00:00' WHERE id=1")
            else:
                c.execute("UPDATE trust_schedule SET enabled=0 WHERE id=1")
            conn.commit()
        except Exception as e:
            print(f"Error syncing schedule DB: {e}")
        finally:
            if 'conn' in locals() and conn:
                conn.close()

        # Use shared function
        if perform_trust_toggle(trust_enabled):
            status_msg = "ENABLED" if trust_enabled else "DISABLED"
            return jsonify({'status': 'success', 'message': f'Internet Positif (Local Filtering) {status_msg}'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to toggle trust settings'})
        
    return jsonify({'status': 'success'})

@app.route('/api/blocking/status', methods=['GET'])
def get_blocking_status():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    config = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        except: pass
    
    return jsonify({'enabled': config.get('blocking_enabled', True)})

@app.route('/api/blocking/toggle', methods=['POST'])
def toggle_blocking():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    data = request.json
    enabled = data.get('enabled', True)
    
    # 1. Update Config
    config = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        except: pass
    
    config['blocking_enabled'] = enabled
    
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
            
        # 2. Rename Strategy for Fast Toggling
        # List of blocklists to manage
        blocklists = [
            "malware.conf",
            "internet_positif.conf",
            "external_threats.conf",
            "blacklist.conf"
        ]
        
        base_dir = "/etc/dnsmasq.d/"
        
        for fname in blocklists:
            active_path = os.path.join(base_dir, fname)
            disabled_path = os.path.join(base_dir, fname + ".disabled")
            
            if enabled:
                # Enable: Rename .disabled -> .conf
                if os.path.exists(disabled_path):
                    run_command(f"sudo mv {disabled_path} {active_path}")
            else:
                # Disable: Rename .conf -> .disabled
                if os.path.exists(active_path):
                    run_command(f"sudo mv {active_path} {disabled_path}")
        
        # 3. Restart DNS Service SAFELY
        success, msg = safe_service_restart()
        if not success:
            return jsonify({'status': 'error', 'message': f'Service restart failed: {msg}'})
        
        return jsonify({'status': 'success', 'enabled': enabled})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/logs')
def logs():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    # Get last 20 lines of dnsmasq logs
    # Use full path for tail and sudo
    cmd = "sudo /usr/bin/tail -n 20 /var/log/dnsmasq.log"
    proc = run_command(cmd)
    
    logs = ''
    if proc and proc.returncode == 0:
        logs = (proc.stdout or '').strip()
    else:
        # Debug logging
        try:
            with open('/home/dns/web_gui/debug_logs.txt', 'a') as f:
                f.write(f"[{datetime.now()}] Log fetch failed. Cmd: {cmd}\n")
                if proc:
                    f.write(f"Stderr: {proc.stderr}\n")
                else:
                    f.write("Proc is None\n")
        except:
            pass
            
    return jsonify({'logs': logs})

@app.route('/api/banned_ips', methods=['GET'])
def get_banned_ips():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    banned_ips = []
    if os.path.exists('/home/dns/banned_ips.txt'):
        try:
            with open('/home/dns/banned_ips.txt', 'r') as f:
                banned_ips = list(set([line.strip() for line in f if line.strip()]))
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})
    
    return jsonify({'status': 'success', 'ips': banned_ips})

@app.route('/api/trust/schedule', methods=['GET', 'POST'])
def trust_schedule():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        if request.method == 'POST':
            data = request.json
            enabled = 1 if data.get('enabled') else 0
            start_time = data.get('start_time', '00:00')
            end_time = data.get('end_time', '00:00')
            trust_ips = data.get('trust_ips', '')
            
            c.execute("UPDATE trust_schedule SET enabled=?, start_time=?, end_time=?, trust_ips=? WHERE id=1",
                      (enabled, start_time, end_time, trust_ips))
            conn.commit()
            
            # APPLY CHANGES IMMEDIATELY
            # If Manual Mode (00:00 - 00:00), we should enforce the 'enabled' state immediately
            # Otherwise, the scheduler will pick it up, but immediate feedback is better.
            
            if start_time == '00:00' and end_time == '00:00':
                perform_trust_toggle(bool(enabled))

            return jsonify({'status': 'success', 'message': 'Schedule updated'})
        
        c.execute("SELECT enabled, start_time, end_time, trust_ips FROM trust_schedule WHERE id=1")
        row = c.fetchone()
        
        if row:
            return jsonify({
                'enabled': bool(row[0]),
                'start_time': row[1],
                'end_time': row[2],
                'trust_ips': row[3]
            })
        return jsonify({'status': 'error', 'message': 'No schedule found'}), 404

    except Exception as e:
        print(f"Error in trust_schedule: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/api/sync/info')
def sync_info():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT key, value FROM cluster_status")
    status = dict(c.fetchall())
    conn.close()
    
    return jsonify({
        'status': 'success',
        'sync_token': get_sync_token(),
        'primary_ip': get_server_ip(),
        'role': status.get('role', 'PRIMARY'),
        'last_sync': status.get('last_sync_received', 'Never'),
        'secondary_ip': status.get('secondary_ip', 'None'),
        'connection_mode': status.get('connection_mode', 'API')
    })

@app.route('/api/system/role', methods=['POST'])
def set_system_role():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    data = request.json
    role = data.get('role')
    if role not in ['PRIMARY', 'SECONDARY']:
        return jsonify({'status': 'error', 'message': 'Invalid role'}), 400
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE cluster_status SET value = ? WHERE key = 'role'", (role,))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success', 'role': role})

@app.route('/api/unblock_ip', methods=['POST'])
def unblock_ip():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    data = request.json
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'status': 'error', 'message': 'IP address is required'}), 400
    
    # Sanitize IP
    ip = re.sub(r'[^0-9.]', '', ip)
    
    try:
        # Remove from iptables
        run_command(f"sudo iptables -D INPUT -s {ip} -j DROP")
        
        # Remove from banned_ips.txt
        if os.path.exists('/home/dns/banned_ips.txt'):
            run_command(f"sudo sed -i '/^{ip}$/d' /home/dns/banned_ips.txt")
            
        return jsonify({'status': 'success', 'message': f'IP {ip} has been unblocked'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# --- GUARDIAN CONFIGURATION ---
GUARDIAN_CONFIG_FILE = "/home/dns/guardian_config.json"
DNSMASQ_CONFIG_FILE = "/etc/dnsmasq.d/00-base.conf"

def read_dnsmasq_config():
    config = {}
    if os.path.exists(DNSMASQ_CONFIG_FILE):
        try:
            with open(DNSMASQ_CONFIG_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        parts = line.split('=', 1)
                        config[parts[0].strip()] = parts[1].strip()
        except:
             # Try sudo cat
             proc = subprocess.run(f"sudo cat {DNSMASQ_CONFIG_FILE}", shell=True, capture_output=True, text=True)
             for line in proc.stdout.splitlines():
                 line = line.strip()
                 if line and not line.startswith('#') and '=' in line:
                     parts = line.split('=', 1)
                     config[parts[0].strip()] = parts[1].strip()
    return config

def update_dnsmasq_config(new_settings):
    lines = []
    try:
        with open(DNSMASQ_CONFIG_FILE, 'r') as f:
            lines = f.readlines()
    except:
        proc = subprocess.run(f"sudo cat {DNSMASQ_CONFIG_FILE}", shell=True, capture_output=True, text=True)
        lines = proc.stdout.splitlines(keepends=True)
    
    new_content = []
    for line in lines:
        stripped = line.strip()
        # Check if line is a setting key=value
        if stripped and not stripped.startswith('#') and '=' in stripped:
            key = stripped.split('=', 1)[0].strip()
            if key in new_settings:
                new_content.append(f"{key}={new_settings[key]}\n")
            else:
                new_content.append(line)
        else:
            new_content.append(line)
    
    # Write to temp
    temp_path = '/tmp/dnsmasq_temp.conf'
    with open(temp_path, 'w') as f:
        f.writelines(new_content)
        
    # Move with sudo
    subprocess.run(f"sudo mv {temp_path} {DNSMASQ_CONFIG_FILE}", shell=True, check=True)
    subprocess.run(f"sudo chown root:root {DNSMASQ_CONFIG_FILE}", shell=True, check=True)
    
    # Reload dnsmasq without downtime
    subprocess.run("sudo systemctl restart dnsmasq", shell=True)

@app.route('/api/export/threats/pdf')
def export_threats_pdf():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    try:
        # Get Threat Data
        limit = request.args.get('limit', 100, type=int)
        threat_data = get_threat_stats(limit=limit)
        
        # Initialize PDF
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "CYBER THREAT DETECTION REPORT", 0, 1, "C")
        pdf.set_font("Arial", "I", 10)
        pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Server: {get_server_ip()}", 0, 1, "C")
        pdf.ln(5)
        
        # Summary
        total_threats = sum(item['threat'] for item in threat_data)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "SUMMARY", 0, 1)
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 6, f"Total Detected Threats: {total_threats}", 0, 1)
        pdf.cell(0, 6, f"Unique Domains: {len(threat_data)}", 0, 1)
        pdf.ln(5)
        
        # Table Header
        pdf.set_fill_color(200, 220, 255)
        pdf.set_font("Arial", "B", 10)
        pdf.cell(100, 8, "DOMAIN / HOST", 1, 0, "L", True)
        pdf.cell(50, 8, "THREAT TYPE", 1, 0, "C", True)
        pdf.cell(30, 8, "HITS", 1, 1, "R", True)
        
        # Table Content
        pdf.set_font("Arial", "", 9)
        for item in threat_data:
            # Handle long domains
            domain = item['domain']
            if len(domain) > 50:
                domain = domain[:47] + "..."
                
            pdf.cell(100, 7, domain, 1, 0, "L")
            pdf.cell(50, 7, item['type'], 1, 0, "C")
            pdf.cell(30, 7, str(item['threat']), 1, 1, "R")
            
        # Footer Note
        pdf.ln(10)
        pdf.set_font("Arial", "I", 8)
        pdf.multi_cell(0, 5, "This report is generated automatically by DNS ENGINE CYBER SECURITY. The domains listed above have been detected and blocked due to suspicious activity (Botnet/Malware/Crypto Mining patterns).")
        
        # Output
        pdf_content = pdf.output(dest='S').encode('latin1')
        return send_file(
            io.BytesIO(pdf_content),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"Threat_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        )
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/guardian/config', methods=['GET'])
def get_guardian_config():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    # Read Guardian Config
    guardian_config = {
        "ban_threshold": 10000,
        "malicious_threshold": 200,
        "limit_query_per_min": 1000,
        "limit_hit_threshold": 0,
        "abnormal_query_per_min": 500
    }
    if os.path.exists(GUARDIAN_CONFIG_FILE):
        try:
            with open(GUARDIAN_CONFIG_FILE, 'r') as f:
                guardian_config.update(json.load(f))
        except:
            pass
            
    # Read DNSMasq Config
    dnsmasq_config = read_dnsmasq_config()
    
    return jsonify({
        'status': 'success',
        'guardian': guardian_config,
        'dnsmasq': {
            'dns_forward_max': dnsmasq_config.get('dns-forward-max', '1500'),
            'cache_size': dnsmasq_config.get('cache-size', '1000')
        }
    })

@app.route('/api/guardian/config', methods=['POST'])
def save_guardian_config():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
    
    data = request.json
    
    # Save Guardian Config
    guardian_settings = {
        "ban_threshold": int(data.get('ban_threshold', 10000)),
        "malicious_threshold": int(data.get('malicious_threshold', 200)),
        "limit_query_per_min": int(data.get('limit_query_per_min', 1000)),
        "limit_hit_threshold": int(data.get('limit_hit_threshold', 0)),
        "abnormal_query_per_min": int(data.get('abnormal_query_per_min', 500)),
        "bandwidth_gbps": int(data.get('bandwidth_gbps', 10)),
        "auto_tune_enabled": data.get('auto_tune_enabled', False)
    }
    
    try:
        with open(GUARDIAN_CONFIG_FILE, 'w') as f:
            json.dump(guardian_settings, f, indent=4)
        # Ensure correct ownership
        subprocess.run(['sudo', 'chown', 'dns:dns', GUARDIAN_CONFIG_FILE])
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error saving guardian config: {e}'}), 500
        
    # Save DNSMasq Config
    dnsmasq_settings = {}
    if 'dns_forward_max' in data:
        dnsmasq_settings['dns-forward-max'] = str(data['dns_forward_max'])
    if 'cache_size' in data:
        dnsmasq_settings['cache-size'] = str(data['cache_size'])
        
    if dnsmasq_settings:
        try:
            update_dnsmasq_config(dnsmasq_settings)
            # Also restart Guardian to apply new limits (e.g. limit_query_per_min)
            subprocess.run("sudo systemctl restart dnsmdnet-guardian", shell=True)
        except Exception as e:
             return jsonify({'status': 'error', 'message': f'Error saving dnsmasq config: {e}'}), 500
            
    return jsonify({'status': 'success', 'message': 'Configuration saved and applied'})

# --- ADVANCED CONFIGURATION (GUARDIAN SETTINGS) ---
SMARTDNS_CONF = '/etc/unbound/unbound.conf.d/security-hardening.conf'

def read_smartdns_config():
    config = {
        'num-threads': '1',
        'msg-cache-size': '4m',
        'rrset-cache-size': '4m',
        'num-queries-per-thread': '1024',
        'outgoing-range': '4096',
        'so-rcvbuf': '4m',
        'so-sndbuf': '4m',
        'so-reuseport': 'no',
        'edns-buffer-size': '1232',
        'ratelimit': '1000',
        'ip-ratelimit': '500'
    }
    
    if os.path.exists(SMARTDNS_CONF):
        try:
            with open(SMARTDNS_CONF, 'r') as f:
                content = f.read()
                
            for key in config.keys():
                # Regex to find "key: value"
                match = re.search(fr'^\s*{key}:\s*(.+)$', content, re.MULTILINE)
                if match:
                    config[key] = match.group(1).strip()
        except Exception as e:
            print(f"Error reading smartdns config: {e}")
            
    return config

def save_smartdns_config_file(new_config):
    # Read existing file to preserve comments and structure
    if os.path.exists(SMARTDNS_CONF):
        with open(SMARTDNS_CONF, 'r') as f:
            content = f.read()
    else:
        return False, "Config file not found"

    # Update values using regex
    for key, value in new_config.items():
        # Check if key exists
        if re.search(fr'^\s*{key}:', content, re.MULTILINE):
            content = re.sub(fr'^(\s*{key}:)\s*.+$', fr'\1 {value}', content, flags=re.MULTILINE)
        else:
            # If key doesn't exist, append it to the end of the file (assuming inside server: block)
            if not content.endswith('\n'):
                content += '\n'
            content += f"    {key}: {value}\n"

    # Write back to temp
    temp_path = '/tmp/smartdns_temp.conf'
    with open(temp_path, 'w') as f:
        f.write(content)
        
    # BACKUP existing config
    backup_path = SMARTDNS_CONF + ".bak"
    subprocess.run(f"sudo cp {SMARTDNS_CONF} {backup_path}", shell=True)

    # Move new config to place
    try:
        subprocess.run(f"sudo mv {temp_path} {SMARTDNS_CONF}", shell=True, check=True)
        subprocess.run(f"sudo chown root:root {SMARTDNS_CONF}", shell=True, check=True)
        
        # VALIDATE Config
        check = subprocess.run(['unbound-checkconf'], capture_output=True, text=True)
        if check.returncode != 0:
            # Restore backup if invalid
            subprocess.run(f"sudo mv {backup_path} {SMARTDNS_CONF}", shell=True)
            return False, f"Invalid Configuration: {check.stderr}"
            
        # Remove backup if success
        subprocess.run(f"sudo rm {backup_path}", shell=True)
        return True, "Saved"
    except Exception as e:
        # Restore backup on error
        if os.path.exists(backup_path):
            subprocess.run(f"sudo mv {backup_path} {SMARTDNS_CONF}", shell=True)
        return False, str(e)

@app.route('/api/guardian/advanced-config', methods=['GET', 'POST'])
def advanced_config_api():
    if not is_authenticated():
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
        
    if request.method == 'GET':
        return jsonify({
            'status': 'success',
            'unbound': read_smartdns_config()
        })
        
    if request.method == 'POST':
        data = request.json
        unbound_settings = data.get('unbound', {})
        
        # Validate/Sanitize inputs (basic)
        allowed_keys = [
            'num-threads', 'msg-cache-size', 'rrset-cache-size', 
            'num-queries-per-thread', 'outgoing-range', 'so-rcvbuf', 
            'so-sndbuf', 'so-reuseport', 'edns-buffer-size', 
            'ratelimit', 'ip-ratelimit'
        ]
        
        clean_settings = {}
        for k in allowed_keys:
            if k in unbound_settings:
                clean_settings[k] = str(unbound_settings[k])
                
        success, msg = save_smartdns_config_file(clean_settings)
        
        if success:
            # Restart Unbound and Dnsmasq safely
            restart_success, restart_msg = safe_service_restart(background=True)
            if restart_success:
                return jsonify({'status': 'success', 'message': 'Settings saved. ' + restart_msg})
            else:
                return jsonify({'status': 'warning', 'message': 'Settings saved but restart failed: ' + restart_msg})
        else:
            return jsonify({'status': 'error', 'message': msg})

@app.route('/api/scan_domains', methods=['POST'])
def scan_domains():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Run the sanitizer script
        result = subprocess.run(['sudo', 'python3', '/home/dns/sanitize_blocklists.py'], 
                              capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            return jsonify({'status': 'success', 'message': 'Scan completed successfully', 'output': result.stdout})
        else:
            return jsonify({'status': 'error', 'message': 'Scan failed', 'output': result.stderr}), 500
            
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'Scan timed out'}), 504
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    # Use port 5001 for compatibility with Nginx proxy and dnsmdnet-gui service
    app.run(host='0.0.0.0', port=5001)
