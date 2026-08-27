CREATE TABLE verdict_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id uuid NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    engine text NOT NULL,
    model_name text NOT NULL,
    prompt_version text NOT NULL,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'complete', 'error')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 10),
    input_fingerprint char(64),
    input_snapshot jsonb,
    response jsonb,
    duration_ms double precision CHECK (duration_ms IS NULL OR duration_ms >= 0),
    error_type text,
    error_detail text,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    UNIQUE (investigation_id, engine, prompt_version)
);

CREATE INDEX ix_verdict_runs_work
    ON verdict_runs (status, created_at) WHERE status IN ('pending', 'error');

INSERT INTO audit_log (actor, action, payload)
VALUES (
    'migration', 'deepseek.verdict_engine_enabled',
    '{"version":"0.1.0","binding":false,"delivery_policy":"deliver_all"}'
);
