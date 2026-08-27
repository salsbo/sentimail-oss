-- Le moteur peut désormais qualifier un message d'indésirable.
--
-- Jusqu'ici il n'avait que « suspect » pour dire à la fois « c'est du spam »
-- et « je ne sais pas ». Les deux appellent pourtant des suites opposées :
-- l'un se classe sans déranger personne, l'autre demande un avis. Le mot
-- retenu est celui que l'utilisateur emploie déjà quand il qualifie un
-- message lui-même, pour que verdict et correction parlent la même langue.

ALTER TABLE verdicts DROP CONSTRAINT IF EXISTS verdicts_classification_check;
ALTER TABLE verdicts ADD CONSTRAINT verdicts_classification_check
    CHECK (classification IN ('legitimate', 'spam', 'suspect', 'dangerous', 'undetermined'));

ALTER TABLE delivery_cases
    DROP CONSTRAINT IF EXISTS delivery_cases_assessed_classification_check;
ALTER TABLE delivery_cases ADD CONSTRAINT delivery_cases_assessed_classification_check
    CHECK (assessed_classification IN ('legitimate', 'spam', 'suspect', 'dangerous', 'undetermined'));

-- Un message rangé en indésirables est livré : l'état le dit, sans prétendre
-- qu'il est arrivé dans la boîte de réception.
ALTER TABLE delivery_cases DROP CONSTRAINT IF EXISTS delivery_cases_state_check;
ALTER TABLE delivery_cases ADD CONSTRAINT delivery_cases_state_check
    CHECK (state IN (
        'observation_only', 'analysis_pending', 'original_delivered',
        'original_filed_as_junk', 'review_notice_pending', 'awaiting_reply',
        'release_requested', 'original_released',
        'future_suppression_requested', 'closed'
    ));

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'code.spam_classification_added',
    '{"version":"1.0.0","outcomes":["deliver","junk","ask_user"],"junk_requires":["spam","dangerous"]}'
);
