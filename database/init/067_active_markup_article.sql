-- ATT-007 : pièce jointe au markup actif (SVG/HTML smuggling). Recherche
-- 20/08 : vecteur en plus forte croissance (+245%% de SVG de phishing en 2025).

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
CROSS JOIN (VALUES
    ('ATT-007', 'Piece jointe au markup actif',
     'Une piece jointe presentee comme image (SVG) ou document (XML, HTML) qui contient du code actif - script, formulaire, champ mot de passe, decodage base64 cote navigateur - est une page web deguisee : le lien de phishing n''apparait pas dans le mail, il est reconstruit a l''ouverture du fichier.',
     'adverse', 65, 'high',
     'Un vrai graphique vectoriel n''a ni script ni formulaire ; un rapport HTML exporte peut contenir du script legitime, le contexte du message reste a apprecier.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a WHERE a.article_code = v.article_code
);
