-- Un message d'extorsion se faisait créditer de sa propre menace.
--
-- « Your account is hacked… payez en bitcoin » : aucun mot d'urgence français,
-- aucune mention d'IBAN, donc aucun motif connu. Le Code en concluait que le
-- contenu n'exerçait « aucune pression coercitive » et lui accordait dix-huit
-- points favorables. Le modèle, lui, avait bien lu la menace et classait
-- dangereux : l'avis envoyé au destinataire affirmait donc une chose et son
-- contraire.
--
-- Deux corrections de principe. Le chantage devient un fait constatable, avec
-- son article. Et l'absence de pression cesse de créditer : ne pas trouver la
-- trace d'une menace n'établit pas qu'il n'y en a pas, exactement comme une
-- absence de preuve n'a jamais suffi à accuser.

WITH editions AS (
    SELECT id FROM code_editions
    WHERE code_name='Code Sentinel' AND status='active'
)
INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters
)
SELECT editions.id, article_code, title, principle, direction, strength,
       severity, limitations, parameters::jsonb
FROM editions
CROSS JOIN (VALUES
    ('CONTENT-011','Chantage ou demande de rançon',
     'Un message qui menace de divulguer, de publier ou d’exploiter des données prétendument dérobées, ou qui réclame un versement pour s’en abstenir, exerce une contrainte sur son destinataire.',
     'adverse',65,'high',
     'La menace se constate dans le texte, pas dans le ton. Une fiction, une citation ou un article de presse qui rapportent un chantage n’en exercent aucun ; ce fait ne vaut que si le message s’adresse à son destinataire.',
     '{"context_kind":"extortion","delivery_barrier":"material_danger"}')
) AS a(article_code, title, principle, direction, strength, severity, limitations, parameters)
ON CONFLICT (edition_id, article_code) DO NOTHING;

-- L'article qui créditait l'absence de pression ne crédite plus : il décrit.
UPDATE code_articles
SET default_direction='neutral', default_strength=0,
    limitations = limitations || ' Ne rien trouver n’établit rien : ce constat '
        || 'décrit une lecture, il ne crédite pas le message.'
WHERE article_code='CONTENT-007' AND default_direction='favorable';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'code.extortion_article_added',
    '{"version":"1.0.0","added":["CONTENT-011"],"neutralised":["CONTENT-007"],"principle":"une absence de detection ne credite pas"}'
);
