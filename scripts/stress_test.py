#!/usr/bin/env python3
import threading
import time
import subprocess
import random
import sys

# Target
TARGET_IP = "127.0.0.1"
TARGET_PORT = 53
DURATION = 5 # seconds
THREADS = 50

# Domains to query
DOMAINS = [
    "google.com", "facebook.com", "youtube.com", "twitter.com", "instagram.com",
    "linkedin.com", "netflix.com", "microsoft.com", "apple.com", "amazon.com",
    "wikipedia.org", "yahoo.com", "reddit.com", "tiktok.com", "bing.com",
    "example.com", "test.com", "localhost", "router.local"
]

stats = {
    "sent": 0,
    "received": 0,
    "errors": 0
}

def worker():
    start_time = time.time()
    while time.time() - start_time < DURATION:
        domain = random.choice(DOMAINS)
        try:
            # Use dig
            cmd = f"dig @{TARGET_IP} -p {TARGET_PORT} {domain} +short +tries=1 +time=1"
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stats["sent"] += 1
            if result.returncode == 0 and result.stdout:
                stats["received"] += 1
            else:
                stats["errors"] += 1
        except Exception:
            stats["errors"] += 1

print(f"Starting DNS Stress Test on {TARGET_IP}:{TARGET_PORT} for {DURATION} seconds with {THREADS} threads...")
threads = []
for i in range(THREADS):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("\n--- Results ---")
print(f"Total Sent: {stats['sent']}")
print(f"Total Received: {stats['received']}")
print(f"Total Errors: {stats['errors']}")
qps = stats['received'] / DURATION
print(f"Estimated QPS: {qps:.2f}")
print("Note: This is a client-side test. Server-side logs (Dnsmasq/Unbound) should show the spike.")
