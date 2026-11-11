#!/usr/bin/env bash
# Detection-as-code check: replay known-bad log lines through wazuh-logtest
# and confirm the expected rule ID fires. Run after editing wazuh/local_rules.xml.
# Usage: test-rules.sh "<docker compose command prefix>"
set -uo pipefail
COMPOSE="$1"
LAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
pass=0; fail=0

# tests/rule-tests.tsv columns: expected rule id <TAB> name <TAB> raw log line
while IFS=$'\t' read -r expected name log; do
  [[ -z "$expected" || "$expected" == \#* ]] && continue
  got="$(printf '%s\n' "$log" | $COMPOSE exec -T wazuh.manager /var/ossec/bin/wazuh-logtest 2>&1 \
          | awk -F"'" '/^\tid: /{id=$2} END{print id}')"
  if [ "$got" = "$expected" ]; then
    printf '  PASS  %-7s %s\n' "$expected" "$name"; pass=$((pass + 1))
  else
    printf '  FAIL  %-7s %s (got: %s)\n' "$expected" "$name" "${got:-no rule}"; fail=$((fail + 1))
  fi
done < "$LAB_DIR/tests/rule-tests.tsv"

printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
