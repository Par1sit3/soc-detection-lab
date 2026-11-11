#!/bin/bash
# Scenario 1 - Reconnaissance            MITRE ATT&CK: T1046 Network Service Discovery
# Expect: Suricata sid 1000001 -> Wazuh rule 100101
source /attacks/common.sh

banner "01 Recon: SYN scan of the top 1000 ports, then service/version detection"
nmap -sS -T4 --top-ports 1000 "$TARGET"
nmap -sV -p 22,80 "$TARGET"
