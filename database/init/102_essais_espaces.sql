-- Essais espacés du juge après une panne passagère du modèle (15 octobre 2026).
--
-- Un échec passager planifie le nouvel essai 15 min, 1 h puis 4 h plus tard.
-- L'échéance vit en base pour survivre à un redémarrage. NULL garde le
-- comportement historique : les runs existants ne changent pas de sens, et
-- un code antérieur ignore simplement la colonne.
ALTER TABLE verdict_runs ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz;

COMMENT ON COLUMN verdict_runs.next_attempt_at IS
    'Échéance de l''essai planifié après un échec passager du modèle ; NULL : cadence historique ou rien à reprendre.';

INSERT INTO audit_log (actor, action, payload)
VALUES (
    'migration', 'verdict.spaced_retries_enabled',
    '{"transient_retry_delays_seconds":[900,3600,14400],"max_transient_attempts":4,"max_other_attempts":3,"retry_grace_seconds":900}'
);
