#!/bin/sh
set -eu

LOCK_KEY=839274615
script=$(mktemp /tmp/migrate.XXXXXX)
trap 'rm -f "${script}"' EXIT

cat > "${script}" <<SQL
SELECT pg_advisory_lock(${LOCK_KEY});
CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY,
    checksum char(64) NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);
SQL

for file in /migrations/init/*.sql; do
    [ -f "${file}" ] || continue
    version=$(basename "${file}" .sql)
    checksum=$(sha256sum "${file}" | awk '{print $1}')
    case "${version}" in
        *[!A-Za-z0-9_.-]*|'')
            echo "Nom de migration invalide : ${version}" >&2
            exit 1
            ;;
    esac
    cat >> "${script}" <<SQL
\set version ${version}
\set checksum ${checksum}
SELECT
    EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = :'version'
          AND rtrim(checksum) NOT IN (:'checksum', 'baseline')
    ) AS is_mismatch,
    NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = :'version'
    ) AS should_apply
\gset
\if :is_mismatch
\warn Migration :version modifiee apres application
DO \$\$ BEGIN RAISE EXCEPTION 'Migration modifiee apres application'; END \$\$;
\endif
SQL
    case "${version}" in
        001_*|002_*|003_*|004_*|005_*|006_*|007_*|008_*|009_*)
            cat >> "${script}" <<'SQL'
\if :should_apply
BEGIN;
INSERT INTO schema_migrations(version, checksum) VALUES (:'version', 'baseline');
COMMIT;
\endif
SQL
            ;;
        *)
            if grep -Eiq '^[[:space:]]*(BEGIN[[:space:]]*;|CREATE[[:space:]]+INDEX[[:space:]]+CONCURRENTLY)' "${file}"; then
                cat >> "${script}" <<SQL
\if :should_apply
\i ${file}
INSERT INTO schema_migrations(version, checksum) VALUES (:'version', :'checksum');
\endif
SQL
            else
                cat >> "${script}" <<SQL
\if :should_apply
BEGIN;
\i ${file}
INSERT INTO schema_migrations(version, checksum) VALUES (:'version', :'checksum');
COMMIT;
\endif
SQL
            fi
            ;;
    esac
done

cat >> "${script}" <<SQL
SELECT pg_advisory_unlock(${LOCK_KEY});
SQL

psql -v ON_ERROR_STOP=1 \
    -h "${PGHOST}" \
    -p "${PGPORT:-5432}" \
    -U "${PGUSER}" \
    -d "${PGDATABASE}" \
    -f "${script}"
