-- Une qualification humaine ne vaut, pour entraîner un modèle, que si la forme
-- du dossier qui l'a motivée lui survit. La rétention efface le message à
-- trente jours et le supprime à cent quatre-vingts : sans cette table, le
-- corpus serait vide avant d'être constitué.
--
-- L'échantillon ne contient ni sujet, ni corps, ni adresse, ni URL : seulement
-- les indices, les règles appliquées et la décision humaine. Il n'est donc pas
-- soumis à la fenêtre de rétention, puisqu'il ne conserve aucune donnée
-- personnelle.

CREATE TABLE IF NOT EXISTS training_samples (
    id bigserial PRIMARY KEY,
    label_id bigint REFERENCES labels(id) ON DELETE SET NULL,
    message_id uuid REFERENCES messages(id) ON DELETE SET NULL,
    kind text NOT NULL CHECK (kind IN ('ground_truth', 'form_example')),
    dossier jsonb NOT NULL,
    dossier_sha256 char(64) NOT NULL,
    human_label text,
    model_classification text,
    model_decision text,
    prompt_version text,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (kind, dossier_sha256)
);

CREATE INDEX IF NOT EXISTS ix_training_samples_kind
    ON training_samples (kind, created_at DESC);

COMMENT ON TABLE training_samples IS
    'Corpus d''entraînement figé : indices et règles, jamais de contenu de message.';
COMMENT ON COLUMN training_samples.kind IS
    'ground_truth : qualification humaine. form_example : jugement du modèle, utile pour la forme, jamais pour la vérité.';

-- Le dossier soumis au juge était persisté intégralement, corps compris, et
-- echappait à la rétention. Il est désormais réduit à sa vue conservable.
UPDATE verdict_runs
SET input_snapshot = jsonb_build_object(
        'schema', 'sentimail-v3-training-view-1',
        'redacted_by_migration', true,
        'clues', coalesce(input_snapshot->'clues', '[]'::jsonb),
        'judgment_rules', coalesce(input_snapshot->'judgment_rules', '{}'::jsonb)
    )
WHERE input_snapshot IS NOT NULL
  AND input_snapshot->>'schema' IS DISTINCT FROM 'sentimail-v3-training-view-1';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'training.samples_enabled',
    '{"input_snapshot":"reduced_to_training_view","personal_data":"removed"}'
);
