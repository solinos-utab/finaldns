import os
import json
import uuid
import datetime
import hashlib
import base64
import subprocess

# Paths
LICENSE_DB_FILE = "/home/dns/web_gui/licenses_db.json"
PRIVATE_KEY_FILE = "/home/dns/web_gui/private_key.pem"
PUBLIC_KEY_FILE = "/home/dns/web_gui/public_key.pem"
LICENSE_FILE = "/home/dns/web_gui/license.key"

PLAN_FEATURES = {
    "BASIC": [
        "Core DNS Filtering (Ads & Malware)",
        "Standard DNS Caching",
        "Basic Web GUI Access",
        "Local Logs Only"
    ],
    "PRO": [
        "All BASIC Features",
        "Advanced Threat Detection (Botnets, Crypto, C2)",
        "Full Traffic Analysis & Charts",
        "API Access",
        "Priority Support",
        "Unlimited Custom Whitelists"
    ],
    "ENTERPRISE": [
        "All PRO Features",
        "High Availability Clustering (Primary/Secondary Sync)",
        "Unlimited RPS Optimization (ISP Scale)",
        "Custom Branding / White-label",
        "Dedicated Support Channel",
        "Multi-Node Central Management"
    ]
}

def get_plan_features(plan):
    return PLAN_FEATURES.get(plan, [])

def load_db():
    if os.path.exists(LICENSE_DB_FILE):
        try:
            with open(LICENSE_DB_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}

def save_db(db):
    try:
        with open(LICENSE_DB_FILE, 'w') as f:
            json.dump(db, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving license DB: {e}")
        return False

# --- RSA CRYPTO UTILS ---
def sign_data(data_str):
    """Sign data using Private Key (Generator Only)"""
    if not os.path.exists(PRIVATE_KEY_FILE):
        return None
    try:
        # Use openssl to sign
        proc = subprocess.Popen(
            ['openssl', 'dgst', '-sha256', '-sign', PRIVATE_KEY_FILE],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        signature, err = proc.communicate(input=data_str.encode())
        if proc.returncode != 0:
            print(f"Sign Error: {err}")
            return None
        return base64.b64encode(signature).decode()
    except Exception as e:
        print(f"Sign Exception: {e}")
        return None

def verify_signature(data_str, signature_b64):
    """Verify data using Public Key (Client)"""
    if not os.path.exists(PUBLIC_KEY_FILE):
        return False
    try:
        signature = base64.b64decode(signature_b64)
        # Create temp sig file
        sig_path = "/tmp/license.sig"
        with open(sig_path, 'wb') as f:
            f.write(signature)
            
        proc = subprocess.Popen(
            ['openssl', 'dgst', '-sha256', '-verify', PUBLIC_KEY_FILE, '-signature', sig_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate(input=data_str.encode())
        os.remove(sig_path)
        
        return proc.returncode == 0 and b"OK" in out
    except Exception as e:
        print(f"Verify Exception: {e}")
        return False

# --- GENERATOR LOGIC ---
def generate_license(client_name, plan="PRO", duration_days=365):
    """Generate a Signed License Key"""
    if not os.path.exists(PRIVATE_KEY_FILE):
        return {"error": "Private Key not found. Cannot generate licenses."}

    # Data to sign
    expiry_str = "LIFETIME"
    if str(duration_days) != "9999":
        expiry_str = (datetime.datetime.now() + datetime.timedelta(days=int(duration_days))).strftime("%Y-%m-%d")
    
    # Payload format: CLIENT|PLAN|EXPIRY|RANDOM
    random_part = uuid.uuid4().hex[:8].upper()
    payload = f"{client_name}|{plan}|{expiry_str}|{random_part}"
    
    # Sign it
    signature = sign_data(payload)
    if not signature:
        return {"error": "Signing failed"}
    
    # Final Key Format: Base64(Payload)::Base64(Signature)
    # We encode payload to base64 too to make it URL safe-ish
    payload_b64 = base64.b64encode(payload.encode()).decode()
    final_key = f"{payload_b64}::{signature}"
    
    # Save to local DB (for records)
    license_data = {
        "client_name": client_name,
        "plan": plan,
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "expiry_date": expiry_str,
        "status": "ACTIVE",
        "key": final_key
    }
    
    db = load_db()
    db[final_key] = license_data
    save_db(db)
    
    return license_data

def list_licenses():
    db = load_db()
    licenses = [{"key": k, **v} for k, v in db.items()]
    try:
        licenses.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    except:
        pass
    return licenses

def revoke_license(key):
    db = load_db()
    if key in db:
        del db[key]
        save_db(db)
        return True
    return False

# --- CLIENT/VALIDATOR LOGIC ---
def validate_license_key(key):
    """
    Validate a license key using Public Key.
    Returns: (is_valid, message, plan_info)
    """
    if not key or "::" not in key:
        return False, "Invalid Key Format", None
        
    try:
        payload_b64, signature_b64 = key.split("::", 1)
        payload = base64.b64decode(payload_b64).decode()
        
        # 1. Verify Signature
        if not verify_signature(payload, signature_b64):
            return False, "Invalid Signature (Tampered Key)", None
            
        # 2. Parse Payload
        # CLIENT|PLAN|EXPIRY|RANDOM
        parts = payload.split("|")
        if len(parts) < 4:
            return False, "Corrupt License Data", None
            
        client_name = parts[0]
        plan = parts[1]
        expiry_str = parts[2]
        
        # 3. Check Expiry
        if expiry_str != "LIFETIME":
            expiry_date = datetime.datetime.strptime(expiry_str, "%Y-%m-%d")
            if datetime.datetime.now() > expiry_date + datetime.timedelta(days=1): # 1 day grace
                return False, f"License Expired on {expiry_str}", None
        
        return True, "License Valid", {"client": client_name, "plan": plan, "expiry": expiry_str}
        
    except Exception as e:
        return False, f"Validation Error: {str(e)}", None

def activate_client_license(key):
    """Activate license on Client Machine"""
    is_valid, msg, info = validate_license_key(key)
    if is_valid:
        try:
            with open(LICENSE_FILE, 'w') as f:
                f.write(key.strip())
            return True, msg, info
        except Exception as e:
            return False, f"Write Error: {e}", None
    return False, msg, None

def get_current_license_status():
    """Get status from local license file"""
    if not os.path.exists(LICENSE_FILE):
        return {"valid": False, "plan": "FREE", "message": "No License Found"}
        
    try:
        with open(LICENSE_FILE, 'r') as f:
            key = f.read().strip()
            
        is_valid, msg, info = validate_license_key(key)
        if is_valid:
            return {"valid": True, "plan": info['plan'], "client": info['client'], "expiry": info['expiry'], "message": msg}
        else:
            return {"valid": False, "plan": "FREE", "message": msg}
            
    except:
        return {"valid": False, "plan": "FREE", "message": "Read Error"}
