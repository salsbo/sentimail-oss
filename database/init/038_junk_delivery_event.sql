-- Le classement en indésirables n'avait pas droit de cité dans le journal.
--
-- Le premier message rangé en indésirables a été livré, puis son événement
-- a été refusé par la contrainte : l'envoi avait réussi, l'écriture non. Le
-- dossier est resté en attente, la reprise l'a renvoyé, et cette reprise
-- ignorait le classement — d'où une seconde copie, sans marque, arrivée en
-- boîte de réception. Un message classé et livré deux fois vaut moins que
-- pas de classement du tout.

ALTER TABLE delivery_events DROP CONSTRAINT IF EXISTS delivery_events_event_type_check;
ALTER TABLE delivery_events ADD CONSTRAINT delivery_events_event_type_check
    CHECK (event_type IN (
        'original_delivered', 'original_filed_as_junk', 'review_notice_delivered',
        'reply_received', 'original_release_requested', 'original_released',
        'future_suppression_requested', 'future_suppression_cancelled', 'error'
    ));

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'delivery.junk_event_allowed',
    '{"version":"1.0.0","event":"original_filed_as_junk"}'
);
