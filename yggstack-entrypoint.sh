#!/bin/sh
set -e

CONFIG="${YGG_CONFIG:-/etc/yggdrasil/yggdrasil.conf}"

# Generate config if it doesn't exist.
if [ ! -f "$CONFIG" ]; then
    echo "Generating yggstack config at $CONFIG"
    mkdir -p "$(dirname "$CONFIG")"
    yggstack -genconf > "$CONFIG"
fi

# Inject peers from environment if set.
if [ -n "$YGG_PEERS" ]; then
    # Build JSON peer list from space-separated URIs.
    # Auto-prepend tcp:// if no scheme is present.
    PEER_JSON=$(echo "$YGG_PEERS" | tr ' ' '\n' | while read -r uri; do
        case "$uri" in
            *://*) echo "$uri" ;;
            *)     echo "tcp://$uri" ;;
        esac
    done | sed 's/.*/"&"/' | paste -sd, -)
    # Replace the Peers line in the HJSON config.
    sed -i "s|Peers: \[.*\]|Peers: [$PEER_JSON]|" "$CONFIG"
fi

# Override admin listen if set.
if [ -n "$YGG_ADMIN_LISTEN" ]; then
    sed -i "s|AdminListen:.*|AdminListen: \"$YGG_ADMIN_LISTEN\"|" "$CONFIG"
fi

SOCKS="${YGG_SOCKS_LISTEN:-127.0.0.1:1080}"
FORWARD_TARGET="${YGG_FORWARD_TARGET:-127.0.0.1:6667}"
FORWARD_PORT="${YGG_FORWARD_PORT:-6667}"

echo "Starting yggstack (SOCKS5=${SOCKS}, forward=${FORWARD_PORT}:${FORWARD_TARGET})..."
exec yggstack -useconffile "$CONFIG" \
    -socks "$SOCKS" \
    -remote-tcp "${FORWARD_PORT}:${FORWARD_TARGET}"
