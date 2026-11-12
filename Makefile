SHELL := /bin/bash
export LAB_DIR := $(CURDIR)
UPSTREAM := vendor/wazuh-docker/single-node
COMPOSE  := docker compose -p soclab -f $(UPSTREAM)/docker-compose.yml -f docker-compose.lab.yml
LEVEL    ?= 7

.DEFAULT_GOAL := help
.PHONY: help setup up down status attack recon web brute persist alerts summary blocked tickets ticket-ack ticket-close test test-rules reload-rules reset clean

help: ## Show this help
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-14s %s\n", $$1, $$2}'

setup: ## One-time: fetch Wazuh config, generate certificates
	@scripts/bootstrap.sh

up: setup ## Build and start the whole lab, wait until it is ready
	@$(COMPOSE) up -d --build
	@scripts/wait-ready.sh "$(COMPOSE)"
	@echo "Dashboard: https://localhost:8443  (admin / SecretPassword)"
	@echo "Tickets:   http://localhost:8080"

down: ## Stop the lab (keeps data)
	@$(COMPOSE) down

status: ## Container state and connected agents
	@$(COMPOSE) ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}'
	@$(COMPOSE) exec -T wazuh.manager /var/ossec/bin/agent_control -l

attack: recon web brute persist ## Run all four attack scenarios in order

recon: ## Scenario 1: port scan (T1046)
	@$(COMPOSE) exec -T attacker bash /attacks/01-recon.sh
web: ## Scenario 2: web attacks (T1190)
	@$(COMPOSE) exec -T attacker bash /attacks/02-web-attacks.sh
brute: ## Scenario 3: SSH brute force (T1110) - triggers active response
	@$(COMPOSE) exec -T attacker bash /attacks/03-ssh-bruteforce.sh
persist: ## Scenario 4: valid account + persistence (T1078, T1136, T1098)
	@$(COMPOSE) exec -T attacker bash /attacks/04-compromise-persist.sh

alerts: ## Show alerts at or above LEVEL (default 7), e.g. make alerts LEVEL=3
	@scripts/show-alerts.sh "$(COMPOSE)" $(LEVEL)

summary: ## Alert counts per rule
	@$(COMPOSE) exec -T wazuh.manager cat /var/ossec/logs/alerts/alerts.json \
	  | jq -r 'select((.rule.groups // []) | index("sca") | not) | "\(.rule.level)\t\(.rule.id)\t\(.rule.description | .[0:80])"' | sort | uniq -c | sort -k2,2nr -k1,1nr

blocked: ## Show active-response activity and current firewall drops on the victim
	@$(COMPOSE) exec -T victim sh -c 'tail -n 4 /var/ossec/logs/active-responses.log 2>/dev/null | cut -c1-150; echo "--- iptables INPUT ---"; iptables -S INPUT'

tickets: ## Show the ticket queue (also at http://localhost:8080)
	@curl -s http://127.0.0.1:8080/api/tickets | jq -r '["ID","SEV","STATUS","ALERTS","RULE","MITRE","SOURCE","TITLE"], (.[] | [.id, .severity, .status, .alert_count, .rule_id, .mitre, .source, .title[0:60]]) | @tsv' | column -t -s $$'\t'

ticket-ack: ## Acknowledge a ticket: make ticket-ack ID=3
	@curl -s -X POST -H 'Content-Type: application/json' -d '{"status":"acknowledged"}' http://127.0.0.1:8080/api/tickets/$(ID)/status; echo
ticket-close: ## Close a ticket: make ticket-close ID=3
	@curl -s -X POST -H 'Content-Type: application/json' -d '{"status":"closed"}' http://127.0.0.1:8080/api/tickets/$(ID)/status; echo

test: ## Unit tests for the ticket queue (no containers needed)
	@python3 -m unittest discover -s tests -v

test-rules: ## Replay sample logs through wazuh-logtest and check which rule fires
	@scripts/test-rules.sh "$(COMPOSE)"

reload-rules: ## Apply edits to wazuh/local_rules.xml
	@$(COMPOSE) restart wazuh.manager

reset: ## Rebuild the victim to a clean state (removes attacker persistence)
	@$(COMPOSE) up -d --build --force-recreate victim suricata

clean: ## Stop the lab and delete all data volumes
	@$(COMPOSE) down -v
