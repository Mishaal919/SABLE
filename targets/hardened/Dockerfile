# hardened: same base, tight permissions. No extra SUID in the escalation
# catalogue, no sudo for auditor, no writable cron scripts, shadow not readable.
# SABLE must find zero paths to root and no High-confidence paths.
FROM ubuntu:22.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd

RUN useradd -m -s /bin/bash auditor && echo 'auditor:auditorpass' | chpasswd

# Harden: ensure shadow is not world-readable and disable root login over SSH.
RUN chmod 640 /etc/shadow \
 && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
