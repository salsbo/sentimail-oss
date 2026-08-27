CREATE TABLE IF NOT EXISTS verdict_llm_call_events (
    id bigserial PRIMARY KEY,
    verdict_run_id uuid NOT NULL REFERENCES verdict_runs(id) ON DELETE CASCADE,
    message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    attempt integer NOT NULL CHECK (attempt > 0),
    status text NOT NULL DEFAULT 'reserved'
        CHECK (status IN ('reserved','complete','error')),
    provider text,
    model_name text,
    error_type text,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (verdict_run_id, attempt)
);

CREATE INDEX IF NOT EXISTS ix_verdict_llm_call_events_quota
    ON verdict_llm_call_events (created_at DESC);

ALTER TABLE assistant_outbox
    ADD COLUMN IF NOT EXISTS smtp_queue_id text;

CREATE TABLE IF NOT EXISTS operational_status (
    component text PRIMARY KEY,
    status text NOT NULL CHECK (status IN ('ok','degraded','down')),
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO audit_log (actor, action, payload)
SELECT 'migration', 'verdict.global_quotas_enabled',
       '{"hourly_default":100,"daily_default":500}'::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM audit_log WHERE action='verdict.global_quotas_enabled'
);
