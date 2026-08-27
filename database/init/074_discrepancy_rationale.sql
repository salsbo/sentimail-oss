-- Instruire un écart demande de revoir le jugement lui-même : ce que le
-- moteur a conclu et pourquoi. La classification seule ne le dit pas, et le
-- raisonnement du verdict vit dans verdict_runs, qui suit le message dans sa
-- purge. L'écart garde donc sa propre copie du raisonnement : comme les
-- colonnes du label, elle survit au message d'origine.

ALTER TABLE discrepancies ADD COLUMN IF NOT EXISTS model_rationale text;

-- Les écarts déjà enregistrés reprennent le raisonnement tant qu'il existe
-- encore ; un raisonnement déjà purgé reste simplement absent.
UPDATE discrepancies d
SET model_rationale = sub.rationale
FROM (
    SELECT DISTINCT ON (l.id)
           l.id AS label_id,
           vr.response->'verdict'->>'rationale' AS rationale
    FROM labels l
    JOIN investigations i ON i.message_id = l.message_id
    JOIN verdict_runs vr ON vr.investigation_id = i.id
                        AND vr.status = 'complete'
    ORDER BY l.id, vr.created_at DESC
) sub
WHERE sub.label_id = d.label_id AND d.model_rationale IS NULL;

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'discrepancies.rationale_added',
    jsonb_build_object(
        'reason', 'reviewing_a_discrepancy_requires_the_judgment_itself',
        'migration', '074_discrepancy_rationale'
    )
);
