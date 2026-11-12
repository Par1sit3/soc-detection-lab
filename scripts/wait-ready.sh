#!/usr/bin/env bash
# Waits for the stack to become usable and draws a progress bar while it does.
# Usage: wait-ready.sh "<docker compose command prefix>"
set -uo pipefail
COMPOSE="$1"

bar() { # bar <done> <total> <label>
  local w=30 fill=$(( $1 * 30 / $2 ))
  printf '\r[%s%s] %d/%d %-34s' \
    "$(printf '%*s' "$fill" '' | tr ' ' '#')" "$(printf '%*s' $((w - fill)) '' | tr ' ' '-')" "$1" "$2" "$3"
}

checks=(
  "indexer answering|curl -sk -u admin:SecretPassword https://127.0.0.1:9200 | grep -q cluster_name"
  "manager API up|curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:55000 | grep -q 401"
  "dashboard up|curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/app/login | grep -qE '200|302'"
  "agent web01 connected|$COMPOSE exec -T wazuh.manager /var/ossec/bin/agent_control -l | grep -q 'web01.*Active'"
  "ticket queue up|curl -s http://127.0.0.1:8080/healthz | grep -q true"
  "suricata capturing|$COMPOSE exec -T victim test -s /var/log/suricata/eve.json"
)

total=${#checks[@]}
i=0
for c in "${checks[@]}"; do
  label="${c%%|*}"; cmd="${c#*|}"
  bar "$i" "$total" "waiting: $label"
  tries=0
  until eval "$cmd" >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -gt 120 ]; then printf '\nTimed out waiting for: %s\n' "$label"; exit 1; fi
    sleep 5
  done
  i=$((i + 1))
done
bar "$total" "$total" "ready"
printf '\n'
