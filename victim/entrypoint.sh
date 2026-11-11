#!/bin/sh
# Starts the services a real server would run under systemd.
set -e

# The agent config lives in the image; /var/ossec/etc is a volume so the
# enrollment key (client.keys) survives container restarts.
cp /opt/lab/ossec.conf /var/ossec/etc/ossec.conf
chown root:wazuh /var/ossec/etc/ossec.conf
chmod 660 /var/ossec/etc/ossec.conf

rm -f /run/rsyslogd.pid
rsyslogd                      # sshd -> /var/log/auth.log
/usr/sbin/sshd
nginx

# Create the IDS log before the agent starts, otherwise the agent only notices
# the file a minute later and skips whatever Suricata wrote in between.
touch /var/log/suricata/eve.json

/var/ossec/bin/wazuh-control start || true
exec tail -F /var/ossec/logs/ossec.log
