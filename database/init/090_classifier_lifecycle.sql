-- Le cycle propose des versions ; une expertise reste une action humaine tracée.
CREATE TABLE classifier_automation (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    enabled boolean NOT NULL DEFAULT false,
    auto_activate boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_started_at timestamptz,
    last_completed_at timestamptz,
    dataset_id text,
    candidate_model_id text REFERENCES classifier_models(model_id),
    status text NOT NULL DEFAULT 'idle' CHECK (status IN ('idle','running','ok','error')),
    report jsonb NOT NULL DEFAULT '{}'::jsonb
);
INSERT INTO classifier_automation(singleton) VALUES (true);

CREATE TABLE classifier_review_queue (
    id bigserial PRIMARY KEY,
    sample_id bigint NOT NULL REFERENCES training_samples(id) ON DELETE CASCADE,
    group_hash text NOT NULL UNIQUE,
    partition text NOT NULL CHECK (partition IN ('train','valid','test')),
    eligible boolean NOT NULL,
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','submitted','done','error')),
    label text CHECK (label IN ('legitimate','spam','suspect','dangerous')),
    reason_code text,
    operator text,
    submitted_at timestamptz,
    completed_at timestamptz,
    label_id bigint REFERENCES labels(id) ON DELETE SET NULL,
    error text,
    CHECK (status='queued' OR (label IS NOT NULL AND operator IS NOT NULL))
);
CREATE INDEX classifier_review_pending ON classifier_review_queue(status,partition);
