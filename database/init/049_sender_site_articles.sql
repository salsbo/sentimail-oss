-- Ce que l'expéditeur publie de lui-même : le seul angle qui reste quand toute
-- la technique est en règle. Un serveur compromis conserve son authentification
-- et son ancienneté ; il ne change pas de métier pour autant.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
CROSS JOIN (VALUES
    ('DEEP-015', 'Destination du même titulaire',
     'Un groupe fait transiter ses liens par ses propres domaines. Le titulaire enregistré distingue ce transit d''une redirection vers un tiers.',
     'favorable', 25, 'low',
     'La plupart des registres masquent le titulaire : son absence ne conclut rien.'),
    ('DEEP-016', 'Activité de l''expéditeur sans rapport avec le message',
     'Un message qui se réclame d''une activité précise - livraison, paiement, accès à un compte - suppose que l''organisation qui l''envoie exerce cette activité. Le site de l''expéditeur en atteste, ou la contredit.',
     'adverse', 55, 'high',
     'Un site illisible ou muet ne prouve rien, et le fait ne vaut que rapporté à l''absence d''historique.'),
    ('DEEP-017', 'Site se réclamant d''une marque étrangère',
     'Ce qu''un domaine dit de lui-même ne vaut rien, car son détenteur l''écrit. S''y réclamer d''une marque à laquelle il n''appartient pas est en revanche un aveu.',
     'adverse', 70, 'high',
     'Un revendeur ou un partenaire cite légitimement une marque : c''est la revendication d''identité qui pèse, pas la mention.'),
    ('CORR-007', 'Convergence : expéditeur détourné',
     'Une identité authentifiée, ancienne et réelle, dont l''activité déclarée est sans rapport avec le propos du message, décrit une infrastructure détournée plutôt qu''une usurpation.',
     'adverse', 75, 'high',
     'Une entreprise peut diversifier son activité sans mettre son site à jour : la convergence signale, elle ne conclut pas.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a WHERE a.article_code = v.article_code
);

UPDATE attack_techniques
SET indicator_clues = '["SENDER_SITE_ACTIVITY_MISMATCH", "CORRELATION_COMPROMISED_SENDER"]'::jsonb
WHERE technique_code = 'THREAD_HIJACKING';
UPDATE attack_techniques
SET indicator_clues = '["IDENTITY_BRAND_MISMATCH", "CORRELATION_BRAND_SPOOFING", "CORRELATION_BRAND_FIRST_CONTACT", "SENDER_SITE_CLAIMS_FOREIGN_BRAND"]'::jsonb
WHERE technique_code = 'BRAND_IMPERSONATION';
