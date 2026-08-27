-- L'acte réclamé par un message est ce qui sépare une gêne d'une perte : un
-- indésirable veut qu'on lise, une fraude veut qu'on vire de l'argent. Le
-- vocabulaire ne suffit pas à les distinguer - une mention n'est pas une
-- demande - d'où un registre fermé d'actes, nommés par un modèle et pesés ici.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
CROSS JOIN (VALUES
    ('ACT-001', 'Virement ou paiement demandé', 'Un message qui réclame un mouvement d''argent engage un acte irréversible.', 'adverse', 80, 'critical', 'Une facture attendue d''un correspondant établi reste ordinaire.'),
    ('ACT-002', 'Changement de coordonnées bancaires', 'La modification d''un RIB détourne durablement les paiements à venir.', 'adverse', 80, 'critical', 'Un changement annoncé dans une relation suivie se vérifie hors courrier.'),
    ('ACT-003', 'Achat de cartes cadeaux', 'Les cartes cadeaux sont le moyen de paiement des fraudes, car intraçables.', 'adverse', 80, 'critical', 'Aucune : ce registre n''a pas d''usage légitime en courrier non sollicité.'),
    ('ACT-004', 'Saisie d''identifiants', 'Un message qui conduit à saisir un mot de passe vise l''accès au compte.', 'adverse', 70, 'high', 'Les services authentifient légitimement leurs utilisateurs.'),
    ('ACT-005', 'Communication d''un code reçu', 'Un code à usage unique se saisit, il ne se communique jamais à un tiers.', 'adverse', 85, 'critical', 'Aucune : aucun service légitime ne demande la restitution d''un code envoyé.'),
    ('ACT-006', 'Envoi d''une pièce d''identité', 'Une pièce d''identité transmise par courrier alimente l''usurpation.', 'adverse', 70, 'high', 'Certaines démarches l''exigent réellement, par des canaux dédiés.'),
    ('ACT-007', 'Ouverture ou exécution d''un fichier', 'Exécuter un fichier reçu remet le poste à la main de l''expéditeur.', 'adverse', 75, 'high', 'L''échange de documents est ordinaire entre correspondants établis.'),
    ('ACT-008', 'Installation d''un logiciel', 'Un logiciel ou un accès distant installé sur demande ouvre la porte.', 'adverse', 75, 'high', 'Un service informatique interne peut le demander légitimement.'),
    ('ACT-009', 'Scan d''un code QR', 'Le code QR déplace l''action vers un appareil non protégé et masque sa destination.', 'adverse', 55, 'high', 'Billetterie, paiement en boutique et authentification en font un usage courant.'),
    ('ACT-010', 'Rappel téléphonique', 'Le rappel sort de l''écrit, où rien n''est vérifiable ni conservé.', 'adverse', 55, 'medium', 'Un service client indique légitimement son numéro.'),
    ('ACT-011', 'Communication de données personnelles', 'La collecte de données personnelles prépare l''usurpation ou la revente.', 'adverse', 50, 'medium', 'Une relation contractuelle en exige parfois.'),
    ('ACT-012', 'Contournement d''une procédure', 'Demander d''écarter la procédure habituelle vise le contrôle qui protège.', 'adverse', 75, 'high', 'L''urgence réelle existe, et se vérifie par un autre canal.'),
    ('ACT-013', 'Demande de confidentialité', 'Isoler le destinataire l''empêche de demander confirmation autour de lui.', 'adverse', 60, 'high', 'La confidentialité est légitime dans bien des échanges professionnels.'),
    ('ACT-014', 'Invitation à cliquer', 'Le clic est l''acte le plus banal du courrier : il n''engage rien seul.', 'neutral', 25, 'low', 'Présent dans la quasi-totalité du courrier légitime.'),
    ('ACT-015', 'Réponse attendue', 'Attendre une réponse est le fonctionnement ordinaire du courrier.', 'neutral', 15, 'low', 'Aucune portée en soi.'),
    ('CORR-008', 'Convergence : acte financier sans identité établie',
     'Un acte financier irréversible réclamé par un expéditeur dont l''identité n''est pas établie décrit une tentative de fraude, ce qu''aucun des deux faits ne dit seul.',
     'adverse', 85, 'critical',
     'Une facture authentifiée d''un correspondant connu ne relève pas de cette convergence.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a WHERE a.article_code = v.article_code
);

UPDATE attack_techniques
SET indicator_clues = '["ACTION_GIFT_CARD_PURCHASE", "ACTION_PAYMENT_TRANSFER", "CORRELATION_FINANCIAL_FRAUD", "HEADERS_RECIPIENT_NOT_ADDRESSED"]'::jsonb
WHERE technique_code = 'GIFT_CARD_SCAM';
UPDATE attack_techniques
SET indicator_clues = '["ACTION_CREDENTIAL_ENTRY", "URL_SANDBOX_FORM", "URL_AMBIENT_SENSITIVE_FORM", "CORRELATION_CREDENTIAL_HARVESTING"]'::jsonb
WHERE technique_code = 'CREDENTIAL_PHISHING_LINK';
UPDATE attack_techniques
SET indicator_clues = '["ACTION_QR_CODE_SCAN"]'::jsonb
WHERE technique_code = 'QUISHING';
UPDATE attack_techniques
SET indicator_clues = '["ACTION_PHONE_CALLBACK"]'::jsonb
WHERE technique_code = 'CALLBACK_PHISHING';
