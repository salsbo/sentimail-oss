-- Les critères ajoutés au Code : usurpation de marque, domaine sosie, copie
-- cachée, langue du message, et les convergences calculées. Un critère qui
-- n'est pas un article ne se juge pas et ne s'apprend pas ; un article sans
-- technique n'enseigne rien au destinataire. Les deux sont donc posés ici.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
CROSS JOIN (VALUES
    ('IDENTITY-005', 'Marque invoquée par un domaine étranger',
     'Un nom affiché qui nomme une organisation connue engage la confiance du destinataire. Quand le domaine expéditeur n''appartient pas à cette organisation, le nom emprunte une réputation qu''il n''a pas.',
     'adverse', 60, 'high',
     'Une agence peut légitimement écrire au nom d''un client : le fait ne vaut que rapporté à l''authentification.'),
    ('IDENTITY-006', 'Domaine sosie d''une marque',
     'Un domaine qui ne se distingue d''une marque connue que par un caractère exploite la lecture rapide, non la confusion technique.',
     'adverse', 65, 'high',
     'Une proximité orthographique fortuite existe : elle se lit avec l''âge du domaine et le reste du faisceau.'),
    ('HEADERS-003', 'Destinataire non nommé',
     'Un message ordinaire nomme celui à qui il s''adresse. L''adresse absente des en-têtes To et Cc signale une diffusion en copie cachée.',
     'adverse', 40, 'medium',
     'Une lettre d''information déclarée fait de même sans rien dissimuler et n''est pas concernée.'),
    ('NATURE-004', 'Langue du message',
     'La langue de rédaction est un fait de contexte : c''est son écart avec les échanges habituels du destinataire qui informe, jamais la langue elle-même.',
     'neutral', 0, 'low',
     'Un échantillon court ne permet aucune détermination fiable.'),
    ('CORR-001', 'Convergence : marque empruntée sans authentification',
     'Le nom d''une marque connue joint à une identité d''envoi non authentifiée décrit un montage d''usurpation, ce qu''aucun des deux faits n''établit seul.',
     'adverse', 80, 'high',
     'La convergence constate un faisceau réuni ; elle ne conclut pas à la place du jugement.'),
    ('CORR-002', 'Convergence : collecte de justificatifs',
     'Un formulaire de saisie hébergé hors du domaine de l''expéditeur, joint à une identité non authentifiée, décrit une collecte de justificatifs.',
     'adverse', 85, 'critical',
     'Un formulaire ordinaire hébergé chez un prestataire connu doit rester distingué par la destination réelle.'),
    ('CORR-003', 'Convergence : prospection non sollicitée',
     'La copie cachée jointe à un discours promotionnel invérifiable décrit une prospection de masse non sollicitée.',
     'adverse', 55, 'medium',
     'Ni l''un ni l''autre fait ne rend un message dangereux : la convergence qualifie l''indésirable, pas le nuisible.'),
    ('CORR-004', 'Convergence : approche par domaine sosie',
     'Un domaine sosie récemment créé, ou qui détourne les réponses, décrit une approche préparée plutôt qu''une coïncidence.',
     'adverse', 80, 'high',
     'L''âge du domaine dépend de la disponibilité RDAP ; son absence retire la convergence sans rien prouver.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a WHERE a.article_code = v.article_code
);

-- Les techniques nommables gagnent les indices qui les révèlent : sans ce
-- lien, le registre ne pouvait désigner ni l'usurpation de marque, ni le
-- domaine sosie, faute d'indice à citer.
UPDATE attack_techniques SET indicator_clues = '["IDENTITY_BRAND_MISMATCH", "CORRELATION_BRAND_SPOOFING"]'::jsonb
WHERE technique_code = 'BRAND_IMPERSONATION';
UPDATE attack_techniques SET indicator_clues = '["IDENTITY_BRAND_MISMATCH"]'::jsonb
WHERE technique_code = 'DISPLAY_NAME_IMPERSONATION';
UPDATE attack_techniques SET indicator_clues = '["IDENTITY_COUSIN_DOMAIN", "CORRELATION_COUSIN_DOMAIN_APPROACH"]'::jsonb
WHERE technique_code = 'COUSIN_DOMAIN';
UPDATE attack_techniques SET indicator_clues = '["URL_SANDBOX_FORM", "URL_AMBIENT_SENSITIVE_FORM", "CORRELATION_CREDENTIAL_HARVESTING"]'::jsonb
WHERE technique_code = 'CREDENTIAL_PHISHING_LINK';
UPDATE attack_techniques SET indicator_clues = '["AUTH_DMARC_FAIL", "AUTH_SPF_FAIL", "AUTH_DKIM_UNALIGNED"]'::jsonb
WHERE technique_code = 'SENDER_SPOOFING';
UPDATE attack_techniques SET indicator_clues = '["HEADERS_RECIPIENT_NOT_ADDRESSED", "CORRELATION_UNSOLICITED_BULK"]'::jsonb
WHERE technique_code = 'GIFT_CARD_SCAM';
UPDATE attack_techniques SET indicator_clues = '["IDENTITY_UNICODE_HOMOGRAPH", "IDENTITY_ASCII_LOOKALIKE"]'::jsonb
WHERE technique_code = 'HOMOGLYPH_UNICODE';
