#!/bin/sh
set -e

# In embedded mode (default), lagoon-web starts the IRC server internally.
# No separate IRC process needed — single binary, single process.
exec lagoon-web
