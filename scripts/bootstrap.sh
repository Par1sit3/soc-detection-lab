#!/usr/bin/env bash
# One-time setup: fetch the pinned upstream Wazuh single-node deployment,
# generate TLS certificates and add the lab's manager config additions.
set -euo pipefail

WAZUH_TAG="v4.14.10"
LAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
UPSTREAM="$LAB_DIR/vendor/wazuh-docker"
NODE="$UPSTREAM/single-node"

step() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

if [ ! -d "$NODE" ]; then
  step "Fetching wazuh-docker $WAZUH_TAG"
  mkdir -p "$LAB_DIR/vendor"
  git clone -q --depth 1 --branch "$WAZUH_TAG" https://github.com/wazuh/wazuh-docker.git "$UPSTREAM"
fi

# The generator makes this directory root-owned, so test the directory, not a file in it.
if [ ! -d "$NODE/config/wazuh_indexer_ssl_certs" ]; then
  step "Generating TLS certificates for indexer, manager and dashboard"
  (cd "$NODE" && docker compose -f generate-indexer-certs.yml run --rm generator)
fi

# Append the lab's manager additions (active response + ticket integration).
# Anything from a previous run is removed first so edits to the file take effect.
CONF="$NODE/config/wazuh_cluster/wazuh_manager.conf"
sed -i '/<!-- SOC-LAB/,$d' "$CONF"
cat "$LAB_DIR/wazuh/manager-extra.xml" >> "$CONF"

step "Setup complete. Next: make up"
