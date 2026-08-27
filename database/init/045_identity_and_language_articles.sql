-- Correctif de nommage : IDENTITY-005, IDENTITY-006 et NATURE-004 étaient déjà
-- pris par d'autres articles du Code. Les trois critères ajoutés en 044
-- reçoivent ici leurs propres codes, libres, pour que chaque indice cite
-- l'article qui le décrit réellement et non celui du voisin.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
CROSS JOIN (VALUES
    ('IDENTITY-009', 'Marque invoquée par un domaine étranger',
     'Un nom affiché qui nomme une organisation connue engage la confiance du destinataire. Quand le domaine expéditeur n''appartient pas à cette organisation, le nom emprunte une réputation qu''il n''a pas.',
     'adverse', 60, 'high',
     'Une agence peut légitimement écrire au nom d''un client : le fait ne vaut que rapporté à l''authentification.'),
    ('IDENTITY-010', 'Domaine sosie d''une marque',
     'Un domaine qui ne se distingue d''une marque connue que par un caractère exploite la lecture rapide, non la confusion technique.',
     'adverse', 65, 'high',
     'Une proximité orthographique fortuite existe : elle se lit avec l''âge du domaine et le reste du faisceau.'),
    ('NATURE-005', 'Langue du message',
     'La langue de rédaction est un fait de contexte : c''est son écart avec les échanges habituels du destinataire qui informe, jamais la langue elle-même.',
     'neutral', 0, 'low',
     'Un échantillon court ne permet aucune détermination fiable.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a WHERE a.article_code = v.article_code
);
