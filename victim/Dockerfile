# Intentionally weak Linux server used as the monitored endpoint.
# DO NOT expose this container to a real network.
FROM debian:12-slim

ARG WAZUH_VERSION=4.14.10
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server nginx rsyslog iptables sudo curl ca-certificates procps lsb-release \
 && ARCH="$(dpkg --print-architecture)" \
 && curl -fsSLo /tmp/agent.deb \
      "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}-1_${ARCH}.deb" \
 && dpkg -i /tmp/agent.deb \
 && rm -rf /tmp/agent.deb /var/lib/apt/lists/*

# Deliberate weaknesses the attack scenarios rely on (see docs/attack-scenarios.md):
#   1. service account with a guessable password
#   2. that account has passwordless sudo
#   3. SSH password authentication is enabled
RUN useradd -m -s /bin/bash svc-backup \
 && echo 'svc-backup:backup123' | chpasswd \
 && echo 'svc-backup ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/svc-backup \
 && chmod 440 /etc/sudoers.d/svc-backup \
 && mkdir -p /run/sshd /root/.ssh \
 && sed -i '/imklog/d' /etc/rsyslog.conf

COPY www/ /var/www/html/
COPY ossec.conf /opt/lab/ossec.conf
COPY entrypoint.sh /opt/lab/entrypoint.sh

EXPOSE 22 80
ENTRYPOINT ["/bin/sh", "/opt/lab/entrypoint.sh"]
