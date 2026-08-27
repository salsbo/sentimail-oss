# Image du service `relay` (docker-compose.yml) : le Postfix interne qui
# relaie le courrier accepté vers la boîte réelle. Ne pas confondre avec le
# MX public autonome (infra/postfix/Dockerfile).
FROM debian:12.13-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends postfix ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY config/main.cf /etc/postfix/main.cf
COPY config/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod 0755 /usr/local/bin/entrypoint.sh

EXPOSE 25

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["postfix", "start-fg"]
