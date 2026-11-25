-- Le modèle vit dans la sauvegarde PostgreSQL, sans pickle ni service GPU.
CREATE TABLE classifier_models (
    model_id text PRIMARY KEY CHECK (model_id ~ '^[0-9a-f]{64}$'),
    artifact jsonb NOT NULL CHECK (jsonb_typeof(artifact) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE classifier_config (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    mode text NOT NULL DEFAULT 'off' CHECK (mode IN ('off','shadow','enforced')),
    model_id text REFERENCES classifier_models(model_id),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (mode = 'off' OR model_id IS NOT NULL)
);
INSERT INTO classifier_config(singleton) VALUES (true);

CREATE TABLE classifier_observations (
    model_id text NOT NULL REFERENCES classifier_models(model_id),
    verdict_run_id uuid NOT NULL REFERENCES verdict_runs(id) ON DELETE CASCADE,
    split_group_hash text NOT NULL,
    probability double precision NOT NULL CHECK (probability BETWEEN 0 AND 1),
    eligible boolean NOT NULL,
    reason text NOT NULL,
    reference_classification text NOT NULL,
    reference_decision text NOT NULL,
    reference_model text NOT NULL,
    reference_prompt text NOT NULL,
    unsafe boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (model_id, verdict_run_id)
);
CREATE INDEX classifier_observations_created ON classifier_observations(created_at);
COMMENT ON TABLE classifier_observations IS
    'Comparaison avant décision : le score local ne modifie jamais le verdict LLM accepté.';
