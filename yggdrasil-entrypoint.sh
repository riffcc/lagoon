#!/bin/sh
set -e

CONFIG="${YGGDRASIL_CONFIG:-/etc/yggdrasil/yggdrasil.conf}"

# Generate config if it doesn't exist.
if [ ! -f "$CONFIG" ]; then
    echo "Generating Yggdrasil config at $CONFIG"
    mkdir -p "$(dirname "$CONFIG")"
    yggdrasil -genconf > "$CONFIG"
fi

# Inject peers from environment if set.
if [ -n "$YGGDRASIL_PEERS" ]; then
    # Build JSON peer list from space-separated URIs.
    PEER_JSON=$(echo "$YGGDRASIL_PEERS" | tr ' ' '\n' | sed 's/.*/"&"/' | paste -sd, -)
    # Use sed to replace the Peers line in the config.
    sed -i "s|Peers: \[.*\]|Peers: [$PEER_JSON]|" "$CONFIG"
fi

# Override listen address if set.
if [ -n "$YGGDRASIL_LISTEN" ]; then
    sed -i "s|Listen: \[.*\]|Listen: [\"$YGGDRASIL_LISTEN\"]|" "$CONFIG"
fi

# Override admin listen if set.
if [ -n "$YGGDRASIL_ADMIN" ]; then
    sed -i "s|AdminListen:.*|AdminListen: \"$YGGDRASIL_ADMIN\"|" "$CONFIG"
fi

echo "Starting Yggdrasil..."
exec yggdrasil -useconffile "$CONFIG" -logto stdout
