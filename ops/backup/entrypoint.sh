#!/bin/sh
set -eu

install -o postgres -g postgres -m 0400 \
    "${BACKUP_PASSWORD_FILE}" /tmp/sentimail-backup-password
export BACKUP_PASSWORD_FILE=/tmp/sentimail-backup-password

install -o postgres -g postgres -m 0400 \
    "${DATABASE_PASSWORD_FILE}" /tmp/sentimail-db-password
export DATABASE_PASSWORD_FILE=/tmp/sentimail-db-password

exec gosu postgres "$@"
