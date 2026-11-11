#!/bin/bash
# Shared settings for the attack scenarios. The target is fixed to the lab
# victim so these scripts cannot be pointed at anything else by accident.
TARGET="172.30.0.10"

banner() { printf '\n\033[1;31m[ATTACK]\033[0m %s\n' "$*"; }
info()   { printf '         %s\n' "$*"; }

# Active response may have blocked us; wait until the port answers again.
wait_for_port() {
  local port="$1" tries="${2:-20}"
  for _ in $(seq 1 "$tries"); do
    nc -z -w 2 "$TARGET" "$port" 2>/dev/null && return 0
    sleep 10
  done
  return 1
}
