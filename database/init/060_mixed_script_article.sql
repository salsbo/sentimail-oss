-- Le mélange d'écritures à l'intérieur d'un même mot n'était couvert par
-- aucun article : « prіority » (і cyrillique) passait pour « priority », et
-- le 20/08 un message ainsi déguisé est parti en boîte de réception avec un
-- verdict légitime. Le numéro 059 est réservé par la branche burst.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
CROSS JOIN (VALUES
    ('CONTENT-012', 'Mélange d''écritures dans un même mot',
     'Un mot qui mélange l''alphabet latin et un alphabet dont les lettres imitent les lettres latines (cyrillique, grec) n''existe dans aucune langue : il est fabriqué pour être lu comme un mot ordinaire tout en échappant aux filtres. Un texte entièrement écrit dans une autre écriture est une langue, jamais un déguisement.',
     'adverse', 65, 'high',
     'Seul le mélange à l''intérieur d''un même mot est constaté : une citation bilingue alterne les écritures entre les mots, pas dedans.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a WHERE a.article_code = v.article_code
);
