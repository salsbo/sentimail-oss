BEGIN;

-- Évaluation parallèle (shadow) via l'API Google Gemini Decisions, sans impact
-- sur les verdicts exécutoires ni sur la livraison.
CREATE TABLE IF NOT EXISTS decisions_api_shadow (
    id bigserial PRIMARY KEY,
    message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    verdict_run_id uuid REFERENCES verdict_runs(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    model_name text NOT NULL,
    status text NOT NULL CHECK (status IN ('ok', 'error')),
    error_type text,
    latency_ms double precision NOT NULL,
    input_tokens integer,
    binding_classification text NOT NULL,
    binding_decision text NOT NULL,
    binding_confidence double precision,
    predicted_classification text,
    predicted_decision text,
    classification_confidence double precision,
    decision_confidence double precision,
    scam_probability double precision,
    impersonation_probability double precision,
    sensitive_action_probability double precision,
    risk_score double precision,
    answers jsonb NOT NULL DEFAULT '{}'::jsonb,
    agrees_classification boolean,
    agrees_decision boolean,
    unsafe_divergence boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS ix_decisions_api_shadow_created
    ON decisions_api_shadow (created_at DESC);

CREATE INDEX IF NOT EXISTS ix_decisions_api_shadow_message
    ON decisions_api_shadow (message_id);

COMMIT;
