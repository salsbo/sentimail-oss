-- CORR-011 : gabarit de campagne connu. Recherche 20/08. La direction et la
-- force reelles sont portees par le signal (elles dependent du label de la
-- campagne source) ; l'article fixe le cadre et la limite.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
CROSS JOIN (VALUES
    ('CORR-011', 'Gabarit de campagne connu',
     'Le squelette du message (structure du HTML, classes, apex des liens) reprend celui d''un message deja qualifie, meme envoye par un autre compte et personnalise autrement : c''est la recidive d''une campagne reconnue. Le signal propage le label de la campagne source, jamais une simple ressemblance.',
     'adverse', 45, 'high',
     'Un meme squelette peut etre partage par des expediteurs honnetes servis par la meme plateforme : le signal informe le jugement, il ne le remplace pas.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a WHERE a.article_code = v.article_code
);
