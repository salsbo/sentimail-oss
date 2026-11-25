-- Les compteurs récents et les curseurs d'activation utilisent les mêmes clés.
-- Les comptes d'intégrité sans borne d'âge conservent leur portée historique.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

CREATE INDEX ix_audit_log_action_created ON audit_log (action, created_at);
CREATE INDEX ix_hook_runs_name_created ON hook_runs (hook_name, created_at);
CREATE INDEX ix_hook_runs_error_created ON hook_runs (created_at) WHERE status='error';

COMMIT;
