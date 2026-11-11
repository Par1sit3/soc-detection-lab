#!/usr/bin/env bash
# Prints alerts from the Wazuh manager as a table: what a SOC analyst would triage.
# Hardening-checklist (SCA) results are hidden here; see them in the dashboard.
# Usage: show-alerts.sh "<docker compose command prefix>" [min_level]
set -euo pipefail
COMPOSE="$1"
MIN_LEVEL="${2:-7}"

$COMPOSE exec -T wazuh.manager cat /var/ossec/logs/alerts/alerts.json \
| jq -r --argjson min "$MIN_LEVEL" '
    select(.rule.level >= $min and ((.rule.groups // []) | index("sca") | not))
    | [ (.timestamp | .[11:19]),
        (.rule.level | tostring),
        .rule.id,
        ((.rule.mitre.id // ["-"]) | join(",")),
        (.rule.description | .[0:90]) ]
    | @tsv' \
| awk -F'\t' 'BEGIN { printf "%-9s %-4s %-7s %-20s %s\n", "TIME", "LVL", "RULE", "MITRE", "DESCRIPTION" }
              { printf "%-9s %-4s %-7s %-20s %s\n", $1, $2, $3, $4, $5 }'
