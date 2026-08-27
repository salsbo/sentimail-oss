-- La cohérence entre le métier d'un expéditeur et le propos de son message ne
-- se mesure pas : elle s'apprécie. Une liste de secteurs était condamnée par
-- construction - chaque métier absent devenait un faux positif ou une faille,
-- et une mutuelle s'est vue accuser d'avoir été détournée parce que son secteur
-- n'y figurait pas. L'appréciation revient donc à un modèle, et son résultat
-- entre au dossier comme n'importe quel indice.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
CROSS JOIN (VALUES
    ('DEEP-018', 'Propos conforme à l''activité de l''expéditeur',
     'Le propos d''un message peut raisonnablement émaner de l''organisation qui l''envoie, telle qu''elle publie son activité.',
     'favorable', 20, 'low',
     'Une organisation communique bien au-delà de son cœur de métier : la conformité rassure faiblement, elle n''innocente pas.'),
    ('DEEP-019', 'Propos étranger à l''activité de l''expéditeur',
     'Un message dont le propos est manifestement étranger à l''activité publiée par son expéditeur décrit une infrastructure détournée : l''authentification et l''ancienneté du domaine restent intactes, seul le sens trahit.',
     'adverse', 55, 'high',
     'L''appréciation porte sur une page d''accueil, qui ne dit pas tout d''une organisation ; le doute profite à l''expéditeur.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a WHERE a.article_code = v.article_code
);

UPDATE attack_techniques
SET indicator_clues = '["SENDER_ACTIVITY_INCOHERENT", "CORRELATION_COMPROMISED_SENDER"]'::jsonb
WHERE technique_code = 'THREAD_HIJACKING';
