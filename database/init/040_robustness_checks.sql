-- Deux garde-fous que le schéma avait laissés dériver.
--
-- La revue de code a trouvé la même classe de défaut qui a cassé la prod deux
-- fois cette semaine : une valeur que le code écrit, mais qu'une contrainte
-- ignore. Ici, rien n'a encore explosé - c'est un contrôle de flux fragile qui
-- retient la balle - mais on ferme la faille avant qu'un refactor l'ouvre.

-- 1. answer_question : l'agent conversationnel produit cette action, le CHECK
-- ne la connaissait pas. Aujourd'hui elle ne franchit pas l'INSERT grâce à une
-- interception dans le code ; demain, un déplacement de cette interception
-- suffirait à mettre le service en boucle d'erreur.
ALTER TABLE assistant_interpretations
    DROP CONSTRAINT IF EXISTS assistant_interpretations_requested_action_check;
ALTER TABLE assistant_interpretations
    ADD CONSTRAINT assistant_interpretations_requested_action_check CHECK (
        requested_action IS NULL OR requested_action IN (
            'release_original', 'suppress_future', 'cancel_suppression',
            'record_feedback', 'explain', 'answer_question', 'list_rules',
            'import_rules', 'set_sender_rule', 'update_rule', 'disable_rule',
            'restore_rule', 'none'
        )
    );

-- 2. Un message classé en indésirables EST livré : son événement doit compter
-- comme une livraison dans l'index d'unicité, sinon la garantie « une seule
-- livraison par dossier » ne couvre pas l'issue junk - précisément celle qui a
-- déjà double-livré une fois.
DROP INDEX IF EXISTS ux_delivery_events_original_delivery;
CREATE UNIQUE INDEX ux_delivery_events_original_delivery
    ON delivery_events (case_id)
    WHERE event_type IN (
        'original_delivered', 'original_released', 'original_filed_as_junk'
    );

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'schema.robustness_checks',
    '{"version":"1.0.0","fixed":["answer_question_check","junk_delivery_uniqueness"]}'
);
