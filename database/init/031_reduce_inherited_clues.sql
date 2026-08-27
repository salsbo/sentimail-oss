-- La réduction précédente avait gardé les indices tels quels, avec leurs faits
-- de travail : ceux-ci contiennent des extraits du message, des URL et des noms
-- de fichiers. Un indice conservable ne garde que ce qui a fondé la décision —
-- son code, son article, sa direction, sa force et son énoncé — jamais la
-- matière qui a permis de l'établir.

UPDATE verdict_runs
SET input_snapshot = jsonb_set(
        input_snapshot,
        '{clues}',
        (
            SELECT coalesce(jsonb_agg(
                jsonb_build_object(
                    'clue_code', clue->>'clue_code',
                    'article_code', clue->>'article_code',
                    'direction', clue->>'direction',
                    'strength', clue->'strength',
                    'confidence', clue->'confidence',
                    'statement', left(coalesce(clue->>'statement', ''), 300),
                    'occurrence_count', coalesce(clue->'occurrence_count', '1'::jsonb)
                )
            ), '[]'::jsonb)
            FROM jsonb_array_elements(input_snapshot->'clues') AS clue
        )
    )
WHERE input_snapshot ? 'clues'
  AND EXISTS (
      SELECT 1 FROM jsonb_array_elements(input_snapshot->'clues') AS clue
      WHERE clue ? 'facts' OR clue ? 'provenance'
  );

-- Les qualifications déjà données méritent leur échantillon : ce sont les
-- seules vérités terrain existantes, et la rétention effacera bientôt les
-- dossiers qui les ont motivées.
INSERT INTO training_samples (
    label_id, message_id, kind, dossier, dossier_sha256, human_label,
    schema_version
)
SELECT DISTINCT ON (l.id)
       l.id,
       l.message_id,
       'ground_truth',
       vr.input_snapshot,
       encode(sha256(vr.input_snapshot::text::bytea), 'hex'),
       l.label,
       'sentimail-v3-training-view-1'
FROM labels l
JOIN investigations i ON i.message_id = l.message_id
JOIN verdict_runs vr ON vr.investigation_id = i.id
WHERE l.source = 'smtp_feedback_user'
  AND l.active = true
  AND vr.input_snapshot IS NOT NULL
ORDER BY l.id, vr.completed_at DESC NULLS LAST
ON CONFLICT (kind, dossier_sha256) DO NOTHING;

-- Les jugements déjà rendus enseignent la forme du procès, jamais la vérité.
INSERT INTO training_samples (
    message_id, kind, dossier, dossier_sha256, model_classification,
    model_decision, prompt_version, schema_version
)
SELECT DISTINCT ON (encode(sha256(vr.input_snapshot::text::bytea), 'hex'))
       i.message_id,
       'form_example',
       vr.input_snapshot,
       encode(sha256(vr.input_snapshot::text::bytea), 'hex'),
       vr.response->'verdict'->>'classification',
       vr.response->'verdict'->>'delivery_decision',
       vr.prompt_version,
       'sentimail-v3-training-view-1'
FROM verdict_runs vr
JOIN investigations i ON i.id = vr.investigation_id
WHERE vr.status = 'complete'
  AND vr.input_snapshot IS NOT NULL
  AND vr.response->'verdict'->>'classification' IS NOT NULL
ORDER BY encode(sha256(vr.input_snapshot::text::bytea), 'hex'), vr.completed_at DESC
ON CONFLICT (kind, dossier_sha256) DO NOTHING;

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'training.inherited_corpus_recovered',
    jsonb_build_object(
        'ground_truth', (SELECT count(*) FROM training_samples WHERE kind='ground_truth'),
        'form_examples', (SELECT count(*) FROM training_samples WHERE kind='form_example')
    )
);
