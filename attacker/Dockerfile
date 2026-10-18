# DeceptionNet Attacker Container
#
# A throwaway host for launching attacks against the lab target(s). Lives on
# honeypot_net so it can reach the attack-target web app (attack-target:9090),
# the Cowrie SSH honeypot (honeypot:2222), Dionaea and the custom-decoy — just
# like a real attacker on the outside of the DMZ. It must NOT reach core-api /
# ai-service / dashboard (those are on the isolated deceptionnet network).
FROM python:3.10-slim

# Debian (unlike Kali) has no 'wordlists' package; the bundled
# scripts/mini-users.txt + mini-pass.txt wordlists are copied in below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        hydra \
        curl \
        netcat-openbsd \
        iputils-ping \
        dnsutils \
        jq \
    && rm -rf /var/lib/apt/lists/*

# sqlmap is pure-Python and pip-installable.
RUN pip install --no-cache-dir sqlmap

WORKDIR /opt/attack
COPY scripts/ ./scripts/
RUN chmod +x scripts/*.sh

CMD ["sleep", "infinity"]
