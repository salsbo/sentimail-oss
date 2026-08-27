-- Un dossier resté sans réponse humaine n'est ni livré, ni classé : il est
-- ignoré. L'absence de réponse ne dit rien - ni que le message était bon, ni
-- qu'il était mauvais - et ne doit donc rien décider. « closed » ne suffisait
-- pas à le dire : il servait déjà à conclure un dossier tranché, et rien ne
-- distinguait plus une décision d'un abandon, y compris dans les mesures.

ALTER TABLE delivery_cases DROP CONSTRAINT IF EXISTS delivery_cases_state_check;
ALTER TABLE delivery_cases ADD CONSTRAINT delivery_cases_state_check
    CHECK (state IN (
        'observation_only', 'analysis_pending', 'original_delivered',
        'original_filed_as_junk', 'review_notice_pending', 'awaiting_reply',
        'release_requested', 'original_released',
        'future_suppression_requested', 'closed', 'ignored'
    ));

-- Les dossiers abandonnés lors de la purge du 21/08 portaient déjà la raison
-- dans leurs détails, faute d'état pour l'exprimer. Ils rejoignent le nouvel
-- état, sans quoi ils resteraient comptés comme des décisions.
UPDATE delivery_cases
SET state = 'ignored'
WHERE state = 'closed' AND details->>'closed_by' = 'ignored_no_human_reply';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'delivery_cases.ignored_state_added',
    jsonb_build_object(
        'reason', 'no_human_reply_is_not_a_signal',
        'migration', '069_ignored_cases'
    )
);
