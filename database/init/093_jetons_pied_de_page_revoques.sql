-- 29 septembre 2026 : le pied de page des messages livrés a été retiré le 14
-- septembre (a201d28, déployé vers 14:05 UTC). Ses jetons restaient valables
-- 180 jours : une réponse « A » posait encore une politique allow sur
-- l'expéditeur d'un message déjà livré, et trois de ces jetons circulaient
-- déjà chez un tiers dans un fil cité.
--
-- Le critère n'est pas « pied de page inséré » mais « aucun avis
-- d'indésirable » : les 68 jetons créés sans pied de page n'ont jamais quitté
-- la base, personne ne les détient. Mesure du 29 septembre : 2 073 jetons
-- révoqués (2 005 avec pied de page, 68 sans), 601 gardés (427 émis avant la
-- borne, 174 après) : ce sont les boutons A des avis d'indésirable, dont 47
-- marqués « pied de page » avant le 14. La borne de date écarte un avis
-- d'indésirable en cours d'envoi, dont le jeton existe avant son événement.
--
-- Après révocation, une réponse qui porte l'un de ces jetons ouvre un défi
-- d'identité en conversation libre, jamais un rejet muet : conversation.py
-- cherche d'abord le message livré cité (_replied_delivered_case) avant tout
-- jeton de corps, et cette voie ignore le statut de smtp_actions. Une réponse
-- normale, dans le fil de messagerie habituel, n'est donc pas affectée. Seule
-- une réponse qui recopie le jeton d'un ancien pied de page hors du fil change
-- de comportement : avant, elle pouvait poser une politique allow directement ;
-- après, elle tombe sur le défi d'identité comme toute réponse sans jeton
-- reconnu. Sur les 30 derniers jours, 6 jetons delivered_feedback ont été
-- consommés, tous pour signaler du spam ou suspendre un expéditeur, aucun pour
-- poser un allow : aucun usage légitime mesuré n'est perdu.
--
-- Les identifiants révoqués sont gardés au journal : le retour arrière vise
-- exactement ces lignes, sans les redéduire. Sur une base neuve, rien n'est
-- révoqué et la liste reste un tableau vide.
WITH revoques AS (
    UPDATE smtp_actions sa
    SET status = 'revoked'
    WHERE sa.status = 'pending'
      AND sa.context->>'purpose' = 'delivered_feedback'
      AND sa.issued_at < '2026-09-14 14:05:00+00'
      AND NOT EXISTS (
          SELECT 1 FROM delivery_events de
          WHERE de.case_id = sa.case_id
            AND de.event_type = 'original_filed_as_junk'
      )
    RETURNING sa.id
)
INSERT INTO audit_log(actor, action, payload)
SELECT 'migration', 'smtp_actions.footer_tokens_revoked',
       jsonb_build_object('revoked', count(*), 'purpose', 'delivered_feedback',
                          'kept', 'avis_indesirables', 'footer_removed', '2026-09-14',
                          'ids', coalesce(jsonb_agg(id), '[]'::jsonb))
FROM revoques;
