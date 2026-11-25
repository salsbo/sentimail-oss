-- 079 : rendre le corpus exploitable sans confondre une préférence humaine,
-- un jugement du modèle et une vérité expertisée.
--
-- Un dossier reste unique par empreinte, mais plusieurs annotations peuvent le
-- qualifier. Cette normalisation évite de perdre un second avis lorsque deux
-- messages ont exactement la même forme probatoire.

ALTER TABLE training_samples
    ADD COLUMN IF NOT EXISTS teacher_model_name text,
    ADD COLUMN IF NOT EXISTS teacher_model_version text,
    ADD COLUMN IF NOT EXISTS teacher_provider text,
    ADD COLUMN IF NOT EXISTS teacher_target jsonb,
    ADD COLUMN IF NOT EXISTS split_group_hash char(64);

ALTER TABLE training_samples
    ADD CONSTRAINT training_samples_teacher_target_object
    CHECK (teacher_target IS NULL OR jsonb_typeof(teacher_target) = 'object'),
    ADD CONSTRAINT training_samples_split_group_hash_format
    CHECK (
        split_group_hash IS NULL
        OR split_group_hash ~ '^[0-9a-f]{64}$'
    );

CREATE TABLE training_sample_annotations (
    id bigserial PRIMARY KEY,
    sample_id bigint NOT NULL REFERENCES training_samples(id) ON DELETE CASCADE,
    label_id bigint REFERENCES labels(id) ON DELETE SET NULL,
    label text NOT NULL,
    source text NOT NULL,
    authority text NOT NULL CHECK (authority IN ('user', 'expert', 'outcome')),
    scope text NOT NULL CHECK (scope IN ('mailbox_preference', 'security')),
    confidence double precision CHECK (confidence BETWEEN 0 AND 1),
    labelled_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (sample_id, label_id)
);

CREATE UNIQUE INDEX ux_training_sample_annotations_label
    ON training_sample_annotations (label_id)
    WHERE label_id IS NOT NULL;
CREATE INDEX ix_training_sample_annotations_sample
    ON training_sample_annotations (sample_id, authority, labelled_at DESC);

-- Les lignes déjà liées à un label deviennent des annotations explicites.
INSERT INTO training_sample_annotations (
    sample_id, label_id, label, source, authority, scope, confidence, labelled_at
)
SELECT ts.id, l.id, l.label, l.source,
       CASE WHEN l.source = 'smtp_feedback_user' THEN 'user' ELSE 'expert' END,
       CASE
           WHEN l.source = 'smtp_feedback_user' THEN 'mailbox_preference'
           ELSE 'security'
       END,
       l.confidence, l.created_at
FROM training_samples ts
JOIN labels l ON l.id = ts.label_id
WHERE ts.kind = 'ground_truth'
ON CONFLICT DO NOTHING;

-- Récupère les qualifications qui possèdent encore un dossier de verdict mais
-- qui n'avaient pas obtenu d'échantillon. Un conflit d'empreinte est normal :
-- l'annotation sera alors rattachée au dossier identique déjà présent.
WITH candidates AS (
    SELECT DISTINCT ON (l.id)
           l.id AS label_id,
           l.message_id,
           l.label,
           vr.input_snapshot AS dossier,
           encode(
               sha256(convert_to(vr.input_snapshot::text, 'UTF8')),
               'hex'
           ) AS dossier_sha256,
           coalesce(
               nullif(vr.input_snapshot->>'schema', ''),
               'sentimail-v3-training-view-1'
           ) AS schema_version
    FROM labels l
    JOIN investigations i ON i.message_id = l.message_id
    JOIN verdict_runs vr ON vr.investigation_id = i.id
    WHERE l.is_ground_truth = true
      AND l.active = true
      AND vr.input_snapshot IS NOT NULL
      AND NOT EXISTS (
          SELECT 1
          FROM training_sample_annotations a
          WHERE a.label_id = l.id
      )
    ORDER BY l.id, vr.completed_at DESC NULLS LAST, vr.created_at DESC
)
INSERT INTO training_samples (
    label_id, message_id, kind, dossier, dossier_sha256, human_label,
    schema_version
)
SELECT c.label_id, c.message_id, 'ground_truth', c.dossier, c.dossier_sha256,
       c.label, c.schema_version
FROM candidates c
WHERE NOT EXISTS (
    SELECT 1
    FROM training_samples ts
    WHERE ts.kind = 'ground_truth' AND ts.dossier = c.dossier
)
ON CONFLICT (kind, dossier_sha256) DO NOTHING;

-- Toutes les qualifications récupérables sont maintenant reliées, y compris
-- celles qui partagent une empreinte et ne justifient pas une ligne dupliquée.
WITH candidates AS (
    SELECT DISTINCT ON (l.id)
           l.id AS label_id,
           l.label,
           l.source,
           l.confidence,
           l.created_at,
           vr.input_snapshot AS dossier,
           encode(
               sha256(convert_to(vr.input_snapshot::text, 'UTF8')),
               'hex'
           ) AS dossier_sha256
    FROM labels l
    JOIN investigations i ON i.message_id = l.message_id
    JOIN verdict_runs vr ON vr.investigation_id = i.id
    WHERE l.is_ground_truth = true
      AND vr.input_snapshot IS NOT NULL
      AND NOT EXISTS (
          SELECT 1
          FROM training_sample_annotations a
          WHERE a.label_id = l.id
      )
    ORDER BY l.id, vr.completed_at DESC NULLS LAST, vr.created_at DESC
)
INSERT INTO training_sample_annotations (
    sample_id, label_id, label, source, authority, scope, confidence, labelled_at
)
SELECT ts.id, c.label_id, c.label, c.source,
       CASE WHEN c.source = 'smtp_feedback_user' THEN 'user' ELSE 'expert' END,
       CASE
           WHEN c.source = 'smtp_feedback_user' THEN 'mailbox_preference'
           ELSE 'security'
       END,
       c.confidence, c.created_at
FROM candidates c
JOIN LATERAL (
    SELECT candidate.id
    FROM training_samples candidate
    WHERE candidate.kind = 'ground_truth'
      AND (
          candidate.dossier_sha256 = c.dossier_sha256
          OR candidate.dossier = c.dossier
      )
    ORDER BY (candidate.dossier_sha256 = c.dossier_sha256) DESC, candidate.id
    LIMIT 1
) ts ON true
ON CONFLICT DO NOTHING;

-- Le groupe de découpage est figé avec l'échantillon. Il ne contient aucune
-- identité : seulement les familles et les codes d'indices triés.
UPDATE training_samples ts
SET split_group_hash = encode(
    sha256(
        convert_to(
            coalesce((
                SELECT string_agg(value, '|' ORDER BY value)
                FROM jsonb_array_elements_text(
                    coalesce(ts.dossier->'evidence_families', '[]'::jsonb)
                ) AS family(value)
            ), '')
            || '#'
            || coalesce((
                SELECT string_agg(clue->>'clue_code', '|' ORDER BY clue->>'clue_code')
                FROM jsonb_array_elements(
                    coalesce(ts.dossier->'clues', '[]'::jsonb)
                ) AS clues(clue)
                WHERE clue->>'clue_code' IS NOT NULL
            ), ''),
            'UTF8'
        )
    ),
    'hex'
)
WHERE split_group_hash IS NULL;

-- Chaque échantillon garde la cible structurée du modèle de référence, sans
-- motivation libre, nom, domaine ou contenu du courrier. Sur un label humain,
-- elle permet de mesurer séparément l'accord au professeur et l'accord au réel.
WITH candidates AS (
    SELECT DISTINCT ON (ts.id)
           ts.id AS sample_id,
           vr.model_name,
           vr.response->'api'->>'system_fingerprint' AS model_version,
           vr.response->'api'->>'provider' AS provider,
           jsonb_strip_nulls(jsonb_build_object(
               'classification', vr.response->'verdict'->>'classification',
               'confidence', vr.response->'verdict'->'confidence',
               'delivery_decision', vr.response->'verdict'->>'delivery_decision',
               'doubt', vr.response->'verdict'->'verdict_doubt',
               'supporting_clue_codes', coalesce(
                   vr.response->'verdict'->'supporting_clue_codes', '[]'::jsonb
               ),
               'contradicting_clue_codes', coalesce(
                   vr.response->'verdict'->'contradicting_clue_codes', '[]'::jsonb
               ),
               'attack_techniques', coalesce(
                   vr.response->'verdict'->'attack'->'techniques', '[]'::jsonb
               )
           )) AS teacher_target
    FROM training_samples ts
    JOIN investigations i ON i.message_id = ts.message_id
    JOIN verdict_runs vr ON vr.investigation_id = i.id AND vr.status = 'complete'
    ORDER BY ts.id,
             (encode(
                 sha256(convert_to(vr.input_snapshot::text, 'UTF8')),
                 'hex'
              ) =
              ts.dossier_sha256) DESC,
             vr.completed_at DESC NULLS LAST
)
UPDATE training_samples ts
SET teacher_model_name = candidates.model_name,
    teacher_model_version = candidates.model_version,
    teacher_provider = candidates.provider,
    teacher_target = candidates.teacher_target
FROM candidates
WHERE ts.id = candidates.sample_id;

-- Les qualifications encore privées de dossier restent visibles comme dette
-- de corpus, sans exposer leurs adresses ni leur objet.
CREATE VIEW training_label_gaps AS
SELECT l.id AS label_id, l.label, l.source, l.created_at
FROM labels l
WHERE l.is_ground_truth = true
  AND l.active = true
  AND NOT EXISTS (
      SELECT 1 FROM training_sample_annotations a WHERE a.label_id = l.id
  );

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'training.corpus_ready',
    jsonb_build_object(
        'samples', (SELECT count(*) FROM training_samples),
        'annotations', (SELECT count(*) FROM training_sample_annotations),
        'unmaterialized_labels', (SELECT count(*) FROM training_label_gaps),
        'teacher_target', 'code_only',
        'split_group', 'evidence_signature'
    )
);
