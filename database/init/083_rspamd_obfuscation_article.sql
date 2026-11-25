-- Un objet ou un expéditeur encodés en base64 sans raison, un texte en
-- taille zéro : Rspamd les relève (SUBJ_EXCESS_BASE64, FROM_EXCESS_BASE64,
-- ZERO_FONT) et personne ne les lisait. Sur M-490357 (6 septembre 2026),
-- « C I C » était ainsi déguisé et l'observation n'en gardait rien : sans
-- article, un signal n'entre ni au jugement ni à l'apprentissage.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
CROSS JOIN (VALUES
    ('RSPAMD-009', 'Déguisement relevé par Rspamd',
     'Un objet ou un nom d''expéditeur encodés en base64 alors qu''ils ne contiennent que des caractères ordinaires, ou un texte rendu en taille zéro, sont des procédés pour être lus par un humain sans être lus par un filtre. Un encodage justifié par des caractères non latins n''en est pas un.',
     'adverse', 35, 'medium',
     'Le symbole est une heuristique du filtre : il charge, il ne condamne pas seul. Un logiciel de messagerie maladroit encode parfois plus que nécessaire.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a WHERE a.article_code = v.article_code
);
