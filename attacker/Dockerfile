# Small attack box. Only attached to the isolated lab network.
FROM debian:12-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap hydra curl sshpass openssh-client iputils-ping netcat-openbsd ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /attacks
CMD ["sleep", "infinity"]
