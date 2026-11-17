# weak2: a root cron job runs /opt/backup.sh, which is group-writable by www-data.
# Deliberately vulnerable LAB image.
FROM ubuntu:22.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo cron ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd

RUN useradd -m -s /bin/bash auditor && echo 'auditor:auditorpass' | chpasswd

# Planted weakness: www-data can write the root-run backup script.
RUN (useradd -r -s /usr/sbin/nologin www-data 2>/dev/null || true) \
 && printf '#!/bin/sh\n# nightly backup placeholder\n' > /opt/backup.sh \
 && chown root:www-data /opt/backup.sh \
 && chmod 775 /opt/backup.sh \
 && echo '*/5 * * * * root /opt/backup.sh' > /etc/cron.d/backup \
 && chmod 644 /etc/cron.d/backup

EXPOSE 22
CMD ["/bin/sh", "-c", "service cron start >/dev/null 2>&1; exec /usr/sbin/sshd -D -e"]
