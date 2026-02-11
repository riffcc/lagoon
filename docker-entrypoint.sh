#!/bin/sh
set -e

# Derive a unique node name if not explicitly set.
# On container platforms like Bunny.net, hostname may be the domain (shared),
# so we fall back to a stable random ID persisted to the data dir.
if [ -z "$LAGOON_NODE_NAME" ]; then
    data_dir="${LAGOON_DATA_DIR:-/data}"
    node_id_file="$data_dir/.node_id"
    if [ -f "$node_id_file" ]; then
        LAGOON_NODE_NAME=$(cat "$node_id_file")
    else
        mkdir -p "$data_dir"
        LAGOON_NODE_NAME="pod-$(head -c4 /dev/urandom | od -A n -t x1 | tr -d ' \n')"
        printf '%s' "$LAGOON_NODE_NAME" > "$node_id_file"
    fi
    export LAGOON_NODE_NAME
fi

# In embedded mode (default), lagoon-web starts the IRC server internally.
# No separate IRC process needed — single binary, single process.
exec lagoon-web
