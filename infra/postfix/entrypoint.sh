#!/usr/bin/env bash
# Rend les gabarits Postfix puis démarre le MX.
#
# Le mot de passe Postgres n'existe jamais comme variable d'environnement du
# service : il est lu depuis le fichier de secret monté, injecté le temps du
# rendu, et n'atterrit que dans des fichiers .cf en 0640 root:postfix — que
# Postfix seul relit.
set -euo pipefail

: "${POSTFIX_MYHOSTNAME:?POSTFIX_MYHOSTNAME requis}"
: "${POSTFIX_MYORIGIN:=${POSTFIX_MYHOSTNAME}}"
: "${POSTFIX_MYDOMAIN:=${POSTFIX_MYORIGIN}}"
: "${POSTGRES_HOST:=db}"
: "${POSTGRES_USER:=sentimail_v3}"
: "${POSTGRES_DB:=sentimail_v3}"
: "${SENTINEL_COLLECTOR_HOST:=collector}"
: "${SENTINEL_COLLECTOR_PORT:=2525}"
: "${RSPAMD_MILTER_HOST:=rspamd}"
: "${RSPAMD_MILTER_PORT:=11332}"
: "${DATABASE_PASSWORD_FILE:=/run/secrets/db_password}"

case "${SENTINEL_COLLECTOR_PORT}${RSPAMD_MILTER_PORT}" in
    *[!0-9]*|'')
        echo "entrypoint: les ports doivent être numériques" >&2
        exit 1
        ;;
esac

if [[ ! -r "${DATABASE_PASSWORD_FILE}" ]]; then
    echo "entrypoint: secret introuvable : ${DATABASE_PASSWORD_FILE}" >&2
    exit 1
fi
POSTGRES_PASSWORD="$(tr -d '\r\n' < "${DATABASE_PASSWORD_FILE}")"
export POSTGRES_PASSWORD

# Un MX public sans certificat démarrerait sans STARTTLS et annoncerait en
# clair qu'il ne sait pas chiffrer. Un certificat éphémère auto-signé vaut
# mieux : le chiffrement opportuniste fonctionne, et l'absence de certificat
# valide reste visible dans les journaux.
if [[ ! -r "${POSTFIX_TLS_CERT_FILE:-}" || ! -r "${POSTFIX_TLS_KEY_FILE:-}" ]]; then
    fallback_dir=/var/lib/postfix/sentinel-tls
    mkdir -p "${fallback_dir}"
    fallback_cert="${fallback_dir}/fullchain.pem"
    fallback_key="${fallback_dir}/privkey.pem"
    if [[ ! -r "${fallback_cert}" || ! -r "${fallback_key}" ]]; then
        openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
            -subj "/CN=${POSTFIX_MYHOSTNAME}" \
            -keyout "${fallback_key}" -out "${fallback_cert}" >/dev/null 2>&1
        chmod 600 "${fallback_key}"
    fi
    chown -R postfix:postfix "${fallback_dir}"
    export POSTFIX_TLS_CERT_FILE="${fallback_cert}"
    export POSTFIX_TLS_KEY_FILE="${fallback_key}"
    echo "postfix: certificat configuré absent, TLS auto-signé temporaire" >&2
fi

# Liste de variables explicite : sans elle, envsubst effacerait aussi les
# références internes de Postfix ($data_directory, $myhostname).
main_vars='${POSTFIX_MYHOSTNAME} ${POSTFIX_MYORIGIN} ${POSTFIX_MYDOMAIN} ${POSTFIX_TLS_CERT_FILE} ${POSTFIX_TLS_KEY_FILE} ${RSPAMD_MILTER_HOST} ${RSPAMD_MILTER_PORT}'
map_vars='${POSTGRES_HOST} ${POSTGRES_USER} ${POSTGRES_PASSWORD} ${POSTGRES_DB} ${SENTINEL_COLLECTOR_HOST} ${SENTINEL_COLLECTOR_PORT}'

envsubst "${main_vars}" < /etc/postfix/main.cf.tmpl > /etc/postfix/main.cf
envsubst "${map_vars}" < /etc/postfix/relay_domains.cf.tmpl > /etc/postfix/relay_domains.cf
envsubst "${map_vars}" < /etc/postfix/transport.cf.tmpl > /etc/postfix/transport.cf

chmod 640 /etc/postfix/relay_domains.cf /etc/postfix/transport.cf
chown root:postfix /etc/postfix/relay_domains.cf /etc/postfix/transport.cf

# Le mot de passe est désormais dans les seuls fichiers .cf protégés.
unset POSTGRES_PASSWORD

# La table des sources hostiles vit sur un volume partagé : au premier
# démarrage, le superviseur ne l'a pas encore écrite - un fichier vide vaut
# une table vide, jamais une erreur de lookup.
mkdir -p /etc/postfix/hostile
[ -f /etc/postfix/hostile/hostile.cidr ] || : > /etc/postfix/hostile/hostile.cidr

postfix check

exec "$@"
