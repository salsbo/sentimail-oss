-- Les qualifications déjà données valaient pour un genre de message autant que
-- pour un expéditeur, mais seul l'expéditeur en avait été retenu. Les indices
-- de leurs dossiers, encore présents, leur sont rendus : l'apprentissage part
-- ainsi de ce que l'utilisateur a réellement tranché, et non de zéro.

UPDATE labels l
SET context = l.context || jsonb_build_object('signals', signals.codes)
FROM (
    SELECT i.message_id,
           jsonb_agg(DISTINCT c.clue_code) AS codes
    FROM clues c
    JOIN investigations i ON i.id=c.investigation_id
    WHERE c.direction <> 'neutral'
    GROUP BY i.message_id
) AS signals
WHERE l.message_id = signals.message_id
  AND l.source='smtp_feedback_user'
  AND NOT (l.context ? 'signals');

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'learning.label_signals_backfilled',
    jsonb_build_object(
        'labels_with_signals',
        (SELECT count(*) FROM labels WHERE context ? 'signals')
    )
);
