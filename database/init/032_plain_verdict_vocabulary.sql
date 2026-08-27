-- Le vocabulaire judiciaire disparaît du Code : ce que lit l'utilisateur, et ce
-- que lit le modèle, parle d'éléments défavorables, d'éléments favorables et de
-- verdict final. Les textes déjà écrits en base sont réécrits ici, sinon le
-- prompt continuerait de transporter l'ancien vocabulaire par les articles.
UPDATE code_articles
SET title = replace(replace(title, 'au juge', 'à l’examen final'), 'du juge', 'de l’examen final'),
    principle = replace(replace(principle, 'au juge', 'à l’examen final'), 'du juge', 'de l’examen final'),
    limitations = replace(replace(limitations, 'au juge', 'à l’examen final'), 'du juge', 'de l’examen final')
WHERE title || principle || limitations LIKE '%juge%';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'code.plain_verdict_vocabulary',
    '{"version":"1.0.0","roles":["unfavorable","favorable","final_verdict"],"replaces":["prosecutor","defence","judge"]}'
);
