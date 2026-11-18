# NF-03 compatibility target: same collector against a different base image.
# BASE is set per compose service (ubuntu:24.04, debian:12). A single detectable
# weakness (world-readable /etc/shadow) confirms cross-distro collection + analysis.
ARG BASE=ubuntu:24.04
FROM ${BASE}

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd

RUN useradd -m -s /bin/bash auditor && echo 'auditor:auditorpass' | chpasswd \
 && chmod 644 /etc/shadow

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
