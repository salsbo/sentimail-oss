-- Les anciennes comparaisons sans contexte restent historiques et ne peuvent
-- qualifier une nouvelle paire, marge, version du prompt ou édition du Code.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

ALTER TABLE verdict_model_routing_evaluations
    ADD COLUMN prompt_version text,
    ADD COLUMN corpus_sha256 text,
    ADD COLUMN rules_version text,
    ADD COLUMN confidence_margin double precision
        CHECK (confidence_margin BETWEEN 0 AND 0.20);

COMMIT;
