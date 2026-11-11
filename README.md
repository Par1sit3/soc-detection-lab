# SOC Detection Lab

A small security operations centre that runs on one machine with Docker. It attacks a deliberately weak Linux server, detects each stage of the attack with a SIEM and a network IDS, and automatically blocks the attacker.

I built it to practise the blue-team side of security: reading logs, writing detection rules, mapping them to MITRE ATT&CK and checking that they actually fire. It was built with help from an AI coding assistant (Claude Code); I run it, test it and extend the rules myself.

## What is in it

| Component | Tool | Purpose |
|---|---|---|
| SIEM | [Wazuh](https://wazuh.com) 4.14 (manager, indexer, dashboard) | Collects logs, applies detection rules, stores and displays alerts |
| Network IDS | [Suricata](https://suricata.io) 7 | Watches traffic to the victim using five signatures written for this lab |
| Endpoint | Debian 12 server `web01` with SSH, nginx and a Wazuh agent | The monitored host. Ships auth, web and IDS logs; file integrity monitoring; CIS benchmark scan |
| Attacker | Debian with nmap, hydra, curl | Runs four scripted attack scenarios |
| Response | Wazuh active response (`firewall-drop`) | Drops the attacker's IP for 120 seconds when a brute force is detected |

```mermaid
flowchart LR
  subgraph labnet["labnet 172.30.0.0/24 (hostile)"]
    A[attacker<br/>nmap, hydra, curl]
    V[web01 victim<br/>sshd + nginx<br/>Wazuh agent]
    S[Suricata sensor<br/>shares web01's NIC]
  end
  subgraph mgmt["management network"]
    M[Wazuh manager<br/>rules + active response]
    I[Wazuh indexer]
    D[Wazuh dashboard<br/>localhost:8443]
  end
  A -- attacks --> V
  S -. eve.json .-> V
  V -- logs, FIM, SCA --> M
  M -- firewall-drop --> V
  M --> I --> D
```

The attacker is only attached to `labnet`, so it cannot reach the SIEM. Every published port is bound to `127.0.0.1`, so nothing in the lab is reachable from the rest of the network.

## Quick start

Requirements: Docker with the Compose plugin, `make`, `git`, `jq`, `curl`, about 6 GB of free RAM. Works on x86-64 and ARM64.

```bash
git clone https://github.com/Par1sit3/soc-detection-lab.git
cd soc-detection-lab
make up        # first run downloads ~3 GB and takes a few minutes
make attack    # run all four attack scenarios
make alerts    # see what was detected
```

Dashboard: <https://localhost:8443> (user `admin`, password `SecretPassword`, accept the self-signed certificate). `make help` lists every command; `make clean` removes everything.

## Attack scenarios and detections

| # | Scenario | `make` target | ATT&CK | Detected by |
|---|---|---|---|---|
| 1 | Port scan and service discovery | `recon` | T1046 | Suricata sid 1000001 → Wazuh rule **100101** |
| 2 | SQL injection, path traversal, scanner fingerprint | `web` | T1190, T1595.002 | Suricata sids 1000003-5 → rules **100103**, **100104**; stock rules 31103, 31104 from the nginx log |
| 3 | SSH brute force with hydra | `brute` | T1110.001 | Stock rule 5763 from `auth.log` and rule **100102** from the network; **active response blocks the attacker** |
| 4 | Login with a weak service account, then add a user, plant an SSH key, drop a web shell placeholder | `persist` | T1078.003, T1136.001, T1098.004, T1505.003 | Rules **100110**, **100111**, **100112**, **100113**; stock correlation rules 40112, 40501 |

Rule IDs in bold are the custom rules in [`wazuh/local_rules.xml`](wazuh/local_rules.xml). The Suricata signatures are in [`suricata/local.rules`](suricata/local.rules).

### Real output

`make alerts` after `make attack` on a fresh lab (repeats trimmed, full capture in [`docs/sample-alerts.txt`](docs/sample-alerts.txt)):

```
TIME      LVL  RULE    MITRE                DESCRIPTION
05:53:04  8    100101  T1046                Recon: port scan against 172.30.0.10 from 172.30.0.66
05:53:10  7    31103   T1190                SQL injection attempt.
05:53:10  7    100104  T1595.002            Recon: vulnerability scanner user-agent from 172.30.0.66
05:53:10  10   100103  T1190                Initial access attempt: LAB Web attack - SQL injection attempt from 172.30.0.66
05:53:10  10   100103  T1190                Initial access attempt: LAB Web attack - path traversal attempt from 172.30.0.66
05:53:10  10   100102  T1110.001            Credential access: SSH brute force seen on the wire from 172.30.0.66
05:53:14  10   5763    T1110                sshd: brute force trying to get access to the system. Authentication failed.
05:55:24  12   40112   T1078,T1110          Multiple authentication failures followed by a success.
05:55:24  15   40501   T1068,T1136,T1203    Attacks followed by the addition of an user.
05:55:24  12   100112  T1098.004            Persistence: SSH authorized_keys changed - /root/.ssh/authorized_keys
05:55:25  12   100113  T1505.003            Persistence: possible web shell dropped in web root - /var/www/html/upload.php
```

The brute force started at 05:53:10 and rule 5763 fired at 05:53:14. The attacker script then reported:

```
port 22 no longer reachable - active response blocked the attacker
```

and `make blocked` showed the rule Wazuh added on the victim: `-A INPUT -s 172.30.0.66/32 -j DROP`.

Rules 100110 (service-account login) and 100111 (new account) fire when scenario 4 is run on its own. When it follows a brute force, Wazuh's stock correlation rules 40112 and 40501 match the same events at a higher severity and take precedence, which is the better alert.

## Testing the rules

Detection rules are treated like code. [`tests/rule-tests.tsv`](tests/rule-tests.tsv) holds sample log lines with the rule ID each one should trigger, and `make test-rules` replays them through `wazuh-logtest`:

```
  PASS  100101  Suricata port scan
  PASS  100102  Suricata SSH brute force
  PASS  100103  Suricata SQL injection
  PASS  100104  Suricata scanner user-agent
  PASS  100110  Service account SSH login
  PASS  5715    Normal user SSH login stays stock
  PASS  100111  New local account
7 passed, 0 failed
```

The `5715` case is a negative test: a normal user logging in must not trigger the service-account rule.

## Problems I hit and how I fixed them

- **The first minute of IDS alerts never reached the SIEM.** The agent started before Suricata had created `eve.json`. Wazuh only re-checks for missing files about once a minute and then reads from the end of the file. Fix: the victim creates the file before the agent starts.
- **Brute force showed 4 failed logins instead of 20, so nothing was blocked.** About 45 seconds after enrolling, the agent restarted itself to load shared configuration from the manager and dropped the logs that arrived during the restart. I found it from the `agent reload` line in `active-responses.log`. Fix: `<auto_restart>no</auto_restart>` in the agent config, since this lab keeps the agent config in one file.
- **The attacker kept getting re-blocked.** I first triggered active response from the network rule as well, but the attacker's own "is the port open yet" probes counted as new connections. I limited the response to the host-based rule, which needs real failed logins.

## Layout

```
docker-compose.lab.yml   lab services, layered over the upstream Wazuh compose file
Makefile                 every command
victim/                  monitored server image and Wazuh agent config
attacker/attacks/        the four attack scripts
suricata/local.rules     network signatures
wazuh/local_rules.xml    custom Wazuh rules with ATT&CK mappings
wazuh/active-response.xml  automated containment config
tests/rule-tests.tsv     rule test cases
scripts/                 bootstrap, readiness check, alert table, rule tests
```

`make setup` fetches the official [wazuh-docker](https://github.com/wazuh/wazuh-docker) single-node deployment (pinned to v4.14.10) into `vendor/` and generates TLS certificates. Neither is committed.

## Safety

The victim is intentionally vulnerable: a guessable password, passwordless sudo, SSH password login. The dashboard and API use Wazuh's published default passwords. Keep the lab on the isolated Docker networks it creates and do not expose it to a real network. The attack scripts have the lab victim's address hard-coded and are meant only for this lab.

## Ideas for later

- Add a Windows endpoint with Sysmon
- Load the Emerging Threats Open ruleset next to the custom signatures
- Send high-severity alerts to a chat webhook
- Deploy the same stack on my Proxmox host as separate VMs

## License

MIT. Wazuh and Suricata are the property of their respective projects.
