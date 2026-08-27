-- Le bac à sable voyait déjà macros, JavaScript, archives chiffrées, membres
-- exécutables et signatures YARA. Le jugement n'en recevait que deux bits :
-- « matériel » au-dessus d'un seuil, « incomplet » sinon. Chaque constat
-- retrouve ici son nom, sa gravité et son article - une macro n'est pas un
-- exécutable, et le destinataire a le droit de savoir lequel il a reçu.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
CROSS JOIN (VALUES
    ('ATT-010', 'Macro lançant des commandes système', 'Une macro qui invoque un interpréteur de commandes donne à l''expéditeur la main sur le poste.', 'adverse', 95, 'critical', 'Aucune : ce comportement n''a pas d''usage bureautique légitime.'),
    ('ATT-011', 'Macro à exécution automatique', 'Une macro déclenchée à l''ouverture s''exécute avant toute décision du destinataire.', 'adverse', 85, 'critical', 'Certains modèles métier en emploient, dans un cadre interne connu.'),
    ('ATT-012', 'Document porteur de macros', 'La présence de macros rend un document capable d''agir sur le poste.', 'adverse', 60, 'high', 'Les documents métier à macros existent et circulent légitimement.'),
    ('ATT-013', 'Document actif', 'Un document qui exécute du code ou lance un programme dépasse le rôle d''un document.', 'adverse', 75, 'critical', 'Les formulaires PDF interactifs emploient parfois du script.'),
    ('ATT-014', 'Archive protégée par mot de passe', 'Le chiffrement d''une archive empêche toute inspection : c''est souvent sa raison d''être.', 'adverse', 70, 'high', 'L''envoi de documents sensibles chiffrés est une pratique légitime.'),
    ('ATT-015', 'Exécutable dans une archive', 'Une archive contenant un fichier exécutable transporte un programme sous couvert d''un document.', 'adverse', 85, 'critical', 'La distribution logicielle légitime emprunte le même chemin.'),
    ('ATT-016', 'Compression anormale', 'Un taux de compression disproportionné signale un contenu conçu pour saturer l''analyse.', 'adverse', 65, 'high', 'Certains formats de données compressent naturellement beaucoup.'),
    ('ATT-017', 'Texte porté par une image', 'Un texte contenu dans une image échappe à la lecture automatique du message.', 'neutral', 0, 'low', 'La signature et le logo en image sont universels.'),
    ('ATT-018', 'Signature de code malveillant', 'Une correspondance avec une signature connue constitue une preuve matérielle.', 'adverse', 95, 'critical', 'Une signature large peut correspondre à un fichier inoffensif : la sévérité du constat compte.'),
    ('ATT-019', 'Inspection de pièce jointe inaboutie', 'Une pièce jointe non inspectée laisse une part du message inconnue.', 'neutral', 0, 'low', 'Une limite d''analyse n''est jamais une charge.'),
    ('ATT-020', 'Liens contenus dans une pièce jointe', 'Un document peut porter des liens que l''analyse du corps ne voit pas.', 'neutral', 0, 'low', 'La quasi-totalité des documents professionnels en contiennent.'),
    ('CORR-009', 'Convergence : contournement de l''analyse',
     'Une archive chiffrée jointe à une invitation pressante à l''ouvrir décrit un contournement délibéré de toute vérification.',
     'adverse', 80, 'critical',
     'L''envoi chiffré convenu entre correspondants établis ne relève pas de cette convergence.'),
    ('CORR-010', 'Convergence : pièce jointe active et invitation à l''ouvrir',
     'Une pièce jointe capable d''exécuter du code, accompagnée d''une invitation à l''ouvrir, réunit le moyen et l''incitation.',
     'adverse', 90, 'critical',
     'Un envoi logiciel attendu d''un correspondant connu reste possible.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a WHERE a.article_code = v.article_code
);

UPDATE attack_techniques
SET indicator_clues = '["ATTACHMENT_MACRO_SHELL", "ATTACHMENT_MACRO_AUTO", "ATTACHMENT_ACTIVE_DOCUMENT", "ATTACHMENT_EXECUTABLE_MEMBER", "ATTACHMENT_YARA_MATCH", "CORRELATION_MALICIOUS_ATTACHMENT"]'::jsonb
WHERE technique_code = 'MALICIOUS_ATTACHMENT';
UPDATE attack_techniques
SET indicator_clues = '["ATTACHMENT_ENCRYPTED_ARCHIVE", "CORRELATION_ANALYSIS_EVASION"]'::jsonb
WHERE technique_code = 'HTML_SMUGGLING';
