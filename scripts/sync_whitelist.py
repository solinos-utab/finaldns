#!/usr/bin/env python3
import os
import json
import re
import subprocess

# Shared Configuration
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

CATEGORY_STATUS_FILE = '/home/dns/category_status.json'
WHITELIST_PATH = '/etc/dnsmasq.d/whitelist.conf'
CUSTOM_TRUST_PATH = '/home/dns/blocklists/custom_trust.txt'
WL_DOMAINS_PATH = '/home/dns/whitelist_domains.txt'

def load_category_status():
    if os.path.exists(CATEGORY_STATUS_FILE):
        try:
            with open(CATEGORY_STATUS_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}

def update_whitelist_domains_txt():
    print("Syncing whitelist domains...")
    domains = set()
    
    # 1. Read existing whitelist.conf (server=/domain/ip)
    if os.path.exists(WHITELIST_PATH):
        try:
            with open(WHITELIST_PATH, 'r') as f:
                for line in f:
                    match = re.search(r'server=/(.*?)/', line)
                    if match:
                        domains.add(match.group(1).lower())
        except Exception as e:
            print(f"Error reading whitelist.conf: {e}")
        
    # 2. Read custom_trust.txt (raw domains)
    if os.path.exists(CUSTOM_TRUST_PATH):
        try:
            with open(CUSTOM_TRUST_PATH, 'r') as f:
                for line in f:
                    dom = line.strip().lower()
                    if dom:
                        domains.add(dom)
        except Exception as e:
            print(f"Error reading custom_trust.txt: {e}")

    # 3. Read Enabled Categories (Smart Whitelist)
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
        with open(WL_DOMAINS_PATH, 'w') as f:
            for domain in sorted(list(domains)):
                f.write(f"{domain}\n")
        # Ensure correct ownership
        subprocess.run(['sudo', 'chown', 'dns:dns', WL_DOMAINS_PATH])
        print(f"Successfully synced {len(domains)} domains to {WL_DOMAINS_PATH}")
    except Exception as e:
        print(f"Error writing whitelist_domains.txt: {e}")

if __name__ == "__main__":
    update_whitelist_domains_txt()
