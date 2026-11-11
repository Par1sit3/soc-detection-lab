#!/bin/sh
# Start Suricata on the victim's lab-facing interface with only the lab ruleset.
set -e

LAB_NET_PREFIX="172.30.0."
IFACE=""
for i in $(seq 1 30); do
  IFACE="$(ip -o -4 addr show 2>/dev/null | awk -v p="$LAB_NET_PREFIX" 'index($4, p) == 1 {print $2; exit}')"
  [ -n "$IFACE" ] && break
  sleep 1
done
[ -n "$IFACE" ] || { echo "could not find the labnet interface" >&2; exit 1; }
echo "suricata: capturing on $IFACE"

rm -f /var/run/suricata.pid
exec suricata -i "$IFACE" \
  -S /lab/local.rules \
  -l /var/log/suricata \
  -k none \
  --set "vars.address-groups.HOME_NET=[172.30.0.10]" \
  --set "vars.address-groups.EXTERNAL_NET=!\$HOME_NET"
