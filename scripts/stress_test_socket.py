#!/usr/bin/env python3
import socket
import threading
import time
import random
import struct

# Target
TARGET_IP = "127.0.0.1"
TARGET_PORT = 53
DURATION = 10 # seconds
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

def build_query(domain):
    # Header: ID, Flags (Recursion Desired), Questions=1, others=0
    header = struct.pack('!HHHHHH', random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    qname = b''
    for part in domain.split('.'):
        qname += struct.pack('B', len(part)) + part.encode()
    qname += b'\x00'
    qtype = struct.pack('!HH', 1, 1) # A record, IN class
    return header + qname + qtype

def worker():
    start_time = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    
    while time.time() - start_time < DURATION:
        domain = random.choice(DOMAINS)
        query = build_query(domain)
        try:
            sock.sendto(query, (TARGET_IP, TARGET_PORT))
            stats["sent"] += 1
            # We don't wait for response to simulate flood/load, 
            # but if we want to measure successful QPS we should recv.
            # For "worst case" (DoS), we just send.
            # For "capacity", we wait.
            # Let's try to recv to be fair.
            data, _ = sock.recvfrom(512)
            if data:
                stats["received"] += 1
        except Exception:
            stats["errors"] += 1
    sock.close()

print(f"Starting High-Performance DNS Stress Test on {TARGET_IP}:{TARGET_PORT} for {DURATION} seconds...")
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
print(f"Estimated QPS (Processed): {qps:.2f}")
