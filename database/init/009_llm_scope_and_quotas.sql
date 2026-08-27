CREATE TABLE llm_call_events (
    id bigserial PRIMARY KEY,
    participant_email text NOT NULL,
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN ('assistant_scope_and_intent')),
    status text NOT NULL DEFAULT 'reserved'
        CHECK (status IN ('reserved','complete','error')),
    provider text,
    model_name text,
    error_type text,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE INDEX ix_llm_call_events_quota
    ON llm_call_events (participant_email, created_at DESC);
CREATE INDEX ix_llm_call_events_conversation
    ON llm_call_events (conversation_id, created_at DESC);

INSERT INTO audit_log (actor, action, payload)
VALUES (
    'migration', 'assistant.scope_and_quotas_enabled',
    '{"local_out_of_scope_gate":true,"ambiguous_max_calls":1,"hourly_user":20,"daily_user":100,"hourly_conversation":10}'
);
