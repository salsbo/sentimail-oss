-- CONTENT-013 : texte masqué par CSS inline (« salting »). Recherche 20/08 :
-- dilution des filtres et instructions cachées adressées à un juge IA.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
CROSS JOIN (VALUES
    ('CONTENT-013', 'Texte masqué par CSS',
     'Un volume important de texte rendu invisible par CSS inline (font-size:0, display:none, couleur égale au fond, hors écran) n''existe que pour tromper l''analyse : diluer les termes suspects, ou glisser des instructions à un filtre automatique. Ce que le destinataire voit et ce que le message contient divergent alors volontairement.',
     'adverse', 45, 'high',
     'Le texte d''aperçu (preheader) est légitimement masqué mais court et unique : seul le masquage substantiel, significatif par rapport au texte visible, est retenu.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a WHERE a.article_code = v.article_code
);
