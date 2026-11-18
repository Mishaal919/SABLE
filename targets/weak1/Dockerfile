# weak1: readable config.php holds a DB password reused by local user dbadmin,
# who has NOPASSWD sudo for /usr/bin/find. Deliberately vulnerable LAB image.
# The password below is a synthetic lab-only value, not a real secret.
FROM ubuntu:22.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo apache2 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd

# Scan account used by SABLE (unprivileged).
RUN useradd -m -s /bin/bash auditor && echo 'auditor:auditorpass' | chpasswd

# Planted weakness: dbadmin reuses the DB password and has a NOPASSWD sudo rule.
RUN useradd -m -s /bin/bash dbadmin && echo 'dbadmin:dbadminpass' | chpasswd \
 && echo 'dbadmin ALL=(root) NOPASSWD: /usr/bin/find' > /etc/sudoers.d/dbadmin \
 && chmod 440 /etc/sudoers.d/dbadmin \
 && mkdir -p /var/www \
 && printf '<?php\n// database configuration\n$db_host = "localhost";\n$db_password = "S3cr3t-LAB-ONLY";\n' > /var/www/config.php \
 && chown root:root /var/www/config.php \
 && chmod 644 /var/www/config.php

EXPOSE 22 80
CMD ["/bin/sh", "-c", "service apache2 start >/dev/null 2>&1; exec /usr/sbin/sshd -D -e"]
