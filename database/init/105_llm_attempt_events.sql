-- Une ligne par tentative réseau, sans requête, réponse, URL ni secret.
CREATE TABLE llm_attempt_events (
    id bigserial PRIMARY KEY,
    message_id uuid,
    verdict_run_id uuid,
    conversation_id uuid,
    purpose text,
    role text,
    provider text,
    model_name text,
    is_fallback boolean NOT NULL DEFAULT false,
    quota_event_id bigint REFERENCES llm_call_events(id) ON DELETE SET NULL,
    status text NOT NULL DEFAULT 'started'
        CHECK (status IN ('started','complete','error','cancelled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    duration_ms double precision CHECK (duration_ms >= 0),
    http_status integer CHECK (http_status BETWEEN 100 AND 599),
    error_type text,
    input_tokens bigint CHECK (input_tokens >= 0),
    output_tokens bigint CHECK (output_tokens >= 0),
    cache_read_tokens bigint CHECK (cache_read_tokens >= 0),
    cache_creation_tokens bigint CHECK (cache_creation_tokens >= 0)
);
CREATE INDEX ix_llm_attempt_events_created ON llm_attempt_events(created_at);
CREATE INDEX ix_llm_attempt_events_message ON llm_attempt_events(message_id,created_at)
    WHERE message_id IS NOT NULL;
CREATE INDEX ix_llm_attempt_events_run ON llm_attempt_events(verdict_run_id,created_at)
    WHERE verdict_run_id IS NOT NULL;
