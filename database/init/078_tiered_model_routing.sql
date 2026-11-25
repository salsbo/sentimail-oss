-- 078 : moduler le modèle selon la complexité, sans confier une livraison à
-- un modèle moins cher avant de l'avoir comparé au juge de référence.

ALTER TABLE llm_local_routing
    DROP CONSTRAINT IF EXISTS llm_local_routing_role_check;
ALTER TABLE llm_local_routing
    ADD CONSTRAINT llm_local_routing_role_check
    CHECK (role IN ('conversation', 'analysis', 'verdict'));

CREATE TABLE verdict_model_routing (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    mode text NOT NULL DEFAULT 'off'
        CHECK (mode IN ('off', 'shadow', 'enforced')),
    economy_model_name text NOT NULL CHECK (economy_model_name <> ''),
    premium_model_name text NOT NULL CHECK (premium_model_name <> ''),
    confidence_margin double precision NOT NULL DEFAULT 0.05
        CHECK (confidence_margin BETWEEN 0 AND 0.20),
    configured_by text NOT NULL DEFAULT 'operator',
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO verdict_model_routing
    (singleton, mode, economy_model_name, premium_model_name,
     confidence_margin, configured_by)
VALUES (
    true, 'off', 'deepseek-v4-flash', 'deepseek-v4-pro', 0.05, 'migration'
);

ALTER TABLE verdict_runs
    ADD COLUMN model_tier text
        CHECK (model_tier IN ('single', 'economy', 'premium')),
    ADD COLUMN routing_reason text,
    ADD COLUMN routing_trace jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE verdict_llm_call_events
    ADD COLUMN stage text NOT NULL DEFAULT 'single'
        CHECK (stage IN ('single', 'economy', 'premium'));
ALTER TABLE verdict_llm_call_events
    DROP CONSTRAINT IF EXISTS verdict_llm_call_events_verdict_run_id_attempt_key;
ALTER TABLE verdict_llm_call_events
    ADD CONSTRAINT verdict_llm_call_events_run_attempt_stage_key
    UNIQUE (verdict_run_id, attempt, stage);

CREATE TABLE verdict_model_routing_evaluations (
    id bigserial PRIMARY KEY,
    verdict_run_id uuid NOT NULL REFERENCES verdict_runs(id) ON DELETE CASCADE,
    attempt integer NOT NULL CHECK (attempt > 0),
    economy_model_name text NOT NULL,
    premium_model_name text NOT NULL,
    economy_valid boolean NOT NULL,
    economy_classification text,
    economy_decision text,
    economy_confidence double precision,
    premium_classification text NOT NULL,
    premium_decision text NOT NULL,
    premium_confidence double precision NOT NULL,
    agreement boolean NOT NULL,
    unsafe_delivery_divergence boolean NOT NULL,
    escalation_reasons text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (verdict_run_id, attempt)
);

CREATE INDEX ix_verdict_model_routing_evaluations_created
    ON verdict_model_routing_evaluations (created_at DESC);

COMMENT ON TABLE verdict_model_routing IS
    'Cascade de verdict : off=modèle historique, shadow=Flash comparé mais Pro '
    'reste contraignant, enforced=Flash peut conclure un dossier simple.';
COMMENT ON TABLE verdict_model_routing_evaluations IS
    'Comparaisons Flash/Pro sans contenu du courrier, avant activation contraignante.';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'llm.tiered_routing_created',
    '{"version":"1.0.0","default":"off","economy":"deepseek-v4-flash","premium":"deepseek-v4-pro","local_role":"analysis"}'::jsonb
);
