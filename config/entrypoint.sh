#!/bin/sh
set -eu

: "${RELAY_HOST:=collector}"
: "${RELAY_PORT:=2525}"

case "$RELAY_PORT" in
    *[!0-9]*|'')
        echo "RELAY_PORT doit etre un port numerique" >&2
        exit 1
        ;;
esac

postconf -e "relayhost = [$RELAY_HOST]:$RELAY_PORT"
# Le client SMTP doit voir le DNS Docker pour resoudre le service collector.
postconf -M "smtp/unix=smtp unix - - n - - smtp"
postfix check

exec "$@"
