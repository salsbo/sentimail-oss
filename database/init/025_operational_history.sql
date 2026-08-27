-- L'état d'exploitation n'était qu'un instantané : impossible de dire, un jour
-- plus tard, si le système avait été stable. Les transitions sont désormais
-- conservées, avec la même fenêtre de rétention que le reste.

CREATE TABLE IF NOT EXISTS operational_events (
    id bigserial PRIMARY KEY,
    component text NOT NULL,
    status text NOT NULL CHECK (status IN ('ok','degraded','down')),
    previous_status text CHECK (previous_status IN ('ok','degraded','down')),
    reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_operational_events_timeline
    ON operational_events (component, observed_at DESC);

INSERT INTO operational_events (component, status, previous_status, reasons, details)
SELECT component, status, NULL, coalesce(details->'reasons','[]'::jsonb), details
FROM operational_status
WHERE NOT EXISTS (SELECT 1 FROM operational_events);

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'operational.history_enabled',
    '{"table":"operational_events","retention":"delete_after_days"}'
);
