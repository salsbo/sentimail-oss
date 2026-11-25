-- La génération est choisie une seule fois pour les nouvelles captures.
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='60s';
ALTER TABLE messages ADD COLUMN engine_generation text NOT NULL DEFAULT 'legacy'
    CHECK (engine_generation IN ('legacy','core-v1'));
ALTER TABLE messages ADD COLUMN engine_generation_assigned_at timestamptz;
-- Les captures antérieures appartiennent définitivement au moteur historique.
UPDATE messages SET engine_generation_assigned_at=now();
ALTER TABLE verdict_runs ADD COLUMN engine_generation text NOT NULL DEFAULT 'legacy'
    CHECK (engine_generation IN ('legacy','core-v1'));
ALTER TABLE verdict_runs ADD COLUMN analysis_plan jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(analysis_plan)='object');

CREATE FUNCTION sentimail_generation_fixed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME='verdict_runs' THEN
        IF NEW.engine_generation IS DISTINCT FROM OLD.engine_generation THEN
            RAISE EXCEPTION 'génération du jugement immuable';
        END IF;
    ELSIF OLD.engine_generation_assigned_at IS NOT NULL THEN
        IF NEW.engine_generation IS DISTINCT FROM OLD.engine_generation
           OR NEW.engine_generation_assigned_at IS DISTINCT FROM OLD.engine_generation_assigned_at THEN
            RAISE EXCEPTION 'génération de capture immuable';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER messages_generation_fixed
    BEFORE UPDATE OF engine_generation,engine_generation_assigned_at ON messages
    FOR EACH ROW EXECUTE FUNCTION sentimail_generation_fixed();
CREATE TRIGGER verdict_runs_generation_fixed
    BEFORE UPDATE OF engine_generation ON verdict_runs
    FOR EACH ROW EXECUTE FUNCTION sentimail_generation_fixed();

CREATE TABLE core_rollout_comparisons (
    id bigserial PRIMARY KEY,
    message_id uuid REFERENCES messages(id) ON DELETE SET NULL,
    source text NOT NULL CHECK (source IN ('offline','shadow')),
    core_version text NOT NULL,
    oracle_revision text NOT NULL,
    suite_version text NOT NULL,
    package_sha256 char(64) NOT NULL,
    corpus_sha256 char(64) NOT NULL,
    dossier_sha256 char(64) NOT NULL,
    response_sha256 char(64) NOT NULL,
    legacy_sha256 char(64) NOT NULL,
    candidate_sha256 char(64) NOT NULL,
    agreement boolean NOT NULL,
    status text NOT NULL CHECK (status IN ('complete','error','excluded')),
    error_type text,
    coverage text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_core_rollout_comparison_context ON core_rollout_comparisons
    (package_sha256,corpus_sha256,suite_version,source);
CREATE INDEX ix_core_rollout_comparison_message ON core_rollout_comparisons(message_id)
    WHERE message_id IS NOT NULL;
CREATE INDEX ix_core_rollout_failed_shadow ON core_rollout_comparisons
    (package_sha256,corpus_sha256,suite_version)
    WHERE source='shadow' AND (status='error' OR (status='complete' AND NOT agreement));
CREATE INDEX ix_core_rollout_failed_audit ON audit_log
    ((payload#>>'{context,package_sha256}')) WHERE action='core.comparison_failed';

CREATE TABLE core_rollout_qualifications (
    id bigserial PRIMARY KEY,
    core_version text NOT NULL,
    oracle_revision text NOT NULL,
    suite_version text NOT NULL,
    package_sha256 char(64) NOT NULL,
    corpus_sha256 char(64) NOT NULL,
    case_set_sha256 char(64) NOT NULL,
    comparison_set_sha256 char(64) NOT NULL,
    comparison_rows bigint NOT NULL CHECK (comparison_rows>=0),
    comparison_last_id bigint NOT NULL CHECK (comparison_last_id>=0),
    cases integer NOT NULL CHECK (cases>=0),
    mismatches integer NOT NULL CHECK (mismatches>=0),
    errors integer NOT NULL CHECK (errors>=0),
    excluded integer NOT NULL CHECK (excluded>=0),
    coverage text[] NOT NULL DEFAULT '{}',
    status text NOT NULL CHECK (status IN ('complete','incomplete')),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE core_rollout_config (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    mode text NOT NULL DEFAULT 'legacy' CHECK (mode IN ('legacy','shadow','canary','active')),
    target_generation text NOT NULL DEFAULT 'core-v1' CHECK (target_generation='core-v1'),
    canary_percent integer NOT NULL DEFAULT 0 CHECK (canary_percent BETWEEN 0 AND 100),
    qualification_id bigint REFERENCES core_rollout_qualifications(id),
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO core_rollout_config(singleton) VALUES(true);

-- Une preuve publiée est append-only. Sa frontière suffit alors à vérifier
-- sa fraîcheur pendant le SMTP, sans relire tous les dossiers historiques.
CREATE FUNCTION sentimail_core_proof_fixed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='UPDATE' AND TG_TABLE_NAME='core_rollout_comparisons'
       AND NEW.message_id IS NULL
       AND (to_jsonb(NEW)-'message_id') = (to_jsonb(OLD)-'message_id') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'preuve de qualification immuable';
END;
$$;
CREATE TRIGGER core_comparisons_fixed BEFORE UPDATE OR DELETE ON core_rollout_comparisons
    FOR EACH ROW EXECUTE FUNCTION sentimail_core_proof_fixed();
CREATE TRIGGER core_qualifications_fixed BEFORE UPDATE OR DELETE ON core_rollout_qualifications
    FOR EACH ROW EXECUTE FUNCTION sentimail_core_proof_fixed();
COMMIT;
