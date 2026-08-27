# MX public autonome de SentiMail V3.
# Contexte de build attendu : racine du dépôt (infra/postfix/Dockerfile).
FROM debian:12.13-slim

ENV DEBIAN_FRONTEND=noninteractive

# postfix-pgsql fournit le greffon de table pgsql: sans lequel relay_domains
# et transport_maps ne peuvent pas être lus en base.
RUN apt-get update && apt-get install -y --no-install-recommends \
        postfix \
        postfix-pgsql \
        ca-certificates \
        gettext-base \
        openssl \
    && rm -rf /var/lib/apt/lists/*

COPY infra/postfix/main.cf.tmpl /etc/postfix/main.cf.tmpl
COPY infra/postfix/master.cf /etc/postfix/master.cf
COPY infra/postfix/header_checks /etc/postfix/header_checks
COPY infra/postfix/relay_domains.cf.tmpl /etc/postfix/relay_domains.cf.tmpl
COPY infra/postfix/transport.cf.tmpl /etc/postfix/transport.cf.tmpl
COPY infra/postfix/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod 0755 /usr/local/bin/entrypoint.sh
# Postfix refuse de faire confiance à une configuration modifiable par
# d'autres que root, et le signale à chaque démarrage.
RUN chmod 644 /etc/postfix/main.cf.tmpl /etc/postfix/master.cf \
    /etc/postfix/header_checks /etc/postfix/relay_domains.cf.tmpl \
    /etc/postfix/transport.cf.tmpl

EXPOSE 25

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["postfix", "start-fg"]
