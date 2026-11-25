-- 080 : retirer du corpus permanent les anciens énoncés libres des indices.
--
-- Un énoncé peut contenir un domaine, un nom de fichier ou un extrait visible.
-- Les codes, articles, directions et forces suffisent à conserver la preuve.
-- dossier_sha256 reste l'empreinte de provenance de la vue reçue : l'export
-- canonique a déjà son propre dataset_id calculé sur la forme assainie.

WITH stripped AS (
    UPDATE training_samples
    SET dossier = jsonb_set(
        dossier,
        '{clues}',
        coalesce(
            (
                SELECT jsonb_agg(item.value - 'statement' ORDER BY item.ordinality)
                FROM jsonb_array_elements(
                    coalesce(dossier->'clues', '[]'::jsonb)
                ) WITH ORDINALITY AS item(value, ordinality)
            ),
            '[]'::jsonb
        ),
        true
    )
    WHERE jsonb_path_exists(dossier, '$.clues[*].statement')
    RETURNING id
)
INSERT INTO audit_log(actor, action, payload)
SELECT 'migration', 'training.free_text_stripped',
       jsonb_build_object(
           'samples', count(*),
           'removed_field', 'clues.statement'
       )
FROM stripped;

ALTER TABLE training_samples
    ADD CONSTRAINT training_samples_no_free_clue_text
    CHECK (NOT jsonb_path_exists(dossier, '$.clues[*].statement'));
