# weak3: a copy of python carries cap_setuid+ep (root via os.setuid(0)), and
# /etc/shadow is world-readable. Deliberately vulnerable LAB image.
FROM ubuntu:22.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo python3 libcap2-bin ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd

RUN useradd -m -s /bin/bash auditor && echo 'auditor:auditorpass' | chpasswd

# Planted weaknesses: setuid-capable python copy, and a world-readable shadow file.
RUN cp /usr/bin/python3 /opt/python \
 && setcap cap_setuid+ep /opt/python \
 && chmod 644 /etc/shadow

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
