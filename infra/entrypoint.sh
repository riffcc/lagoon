#!/bin/bash
set -e

SITE_NAME="${SITE_NAME:-lagoon}"

mkdir -p /var/run/yggdrasil

echo "[${SITE_NAME}] Starting Yggdrasil..."
yggdrasil -useconffile /etc/yggdrasil/yggdrasil.conf &
YGG_PID=$!

# Wait for Yggdrasil TUN interface to come up (using /proc/net/if_inet6, no iproute2 needed).
echo "[${SITE_NAME}] Waiting for Yggdrasil interface..."
for i in $(seq 1 30); do
    if grep -q "^02" /proc/net/if_inet6 2>/dev/null; then
        break
    fi
    if ! kill -0 $YGG_PID 2>/dev/null; then
        echo "[${SITE_NAME}] Yggdrasil died!"
        exit 1
    fi
    sleep 0.1
done

# Parse Yggdrasil address from /proc/net/if_inet6 (hex format, 200::/7 prefix = starts with 02).
YGG_HEX=$(grep "^02" /proc/net/if_inet6 2>/dev/null | head -1 | awk '{print $1}')
if [ -n "$YGG_HEX" ]; then
    YGG_ADDR=$(echo "$YGG_HEX" | sed 's/.\{4\}/&:/g; s/:$//')
    echo "[${SITE_NAME}] Yggdrasil address: ${YGG_ADDR}"
else
    echo "[${SITE_NAME}] WARNING: no Yggdrasil address detected"
fi

echo "[${SITE_NAME}] Starting Lagoon IRC server..."
exec /usr/local/bin/lagoon
