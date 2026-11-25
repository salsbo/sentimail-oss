-- Résultats de travail temporaires, jamais un verdict ni une preuve réécrite.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

CREATE TABLE observation_cache (
    message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    stage text NOT NULL CHECK (length(stage) BETWEEN 1 AND 160),
    fingerprint char(64) NOT NULL,
    result jsonb NOT NULL CHECK (jsonb_typeof(result)='object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (message_id, stage, fingerprint)
);
CREATE INDEX ix_observation_cache_expiry ON observation_cache(expires_at);
COMMIT;
