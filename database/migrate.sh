#!/bin/sh
set -eu

psql_args="-v ON_ERROR_STOP=1 -h ${PGHOST} -p ${PGPORT:-5432} -U ${PGUSER} -d ${PGDATABASE}"

psql ${psql_args} <<'SQL'
CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY,
    checksum char(64) NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);
SQL

for file in /migrations/init/*.sql; do
    version=$(basename "${file}" .sql)
    checksum=$(sha256sum "${file}" | awk '{print $1}')
    applied=$(psql ${psql_args} -Atc "SELECT rtrim(checksum) FROM schema_migrations WHERE version='${version}'")
    if [ -n "${applied}" ]; then
        if [ "${applied}" != "${checksum}" ] && [ "${applied}" != "baseline" ]; then
            echo "Migration ${version} modifiée après application" >&2
            exit 1
        fi
        continue
    fi
    case "${version}" in
        001_*|002_*|003_*|004_*|005_*|006_*|007_*|008_*|009_*)
            psql ${psql_args} -c \
                "INSERT INTO schema_migrations(version,checksum) VALUES ('${version}','baseline')"
            ;;
        *)
            psql ${psql_args} -f "${file}"
            psql ${psql_args} -c \
                "INSERT INTO schema_migrations(version,checksum) VALUES ('${version}','${checksum}')"
            ;;
    esac
done
