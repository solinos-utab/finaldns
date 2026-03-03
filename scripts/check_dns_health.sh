#!/bin/bash
# Check if Unbound is running
if ! pidof unbound > /dev/null; then
    exit 1
fi

# Check if Dnsmasq is running
if ! pidof dnsmasq > /dev/null; then
    exit 1
fi

# Check if port 53 is listening (DNS)
if ! ss -luan | grep -q ":53 "; then
    exit 1
fi

# Check if Guardian is active
if systemctl is-active --quiet guardian; then
    : # OK
else
    # If guardian is not a service but a python script, check pid
    if ! pgrep -f "guardian.py" > /dev/null; then
        exit 1
    fi
fi

# Check API Sync (Localhost)
# We use curl to check if the API is responsive. 
# Using -k because we might be using self-signed certs soon.
# We check the /api/ha/status endpoint which is lightweight.
if ! curl -s -k --max-time 2 https://127.0.0.1:5000/api/ha/status > /dev/null; then
    # Fallback to HTTP if HTTPS not yet configured
    if ! curl -s --max-time 2 http://127.0.0.1:5000/api/ha/status > /dev/null; then
        exit 1
    fi
fi

exit 0
