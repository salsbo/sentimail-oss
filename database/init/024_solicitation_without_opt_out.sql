-- Les sollicitations grossières ne se déclarent pas comme diffusion : elles
-- n'ont ni en-tête de liste, ni moyen de se désinscrire. Le cadre d'envoi ne
-- suffisait donc pas à les décrire.

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
    ('NATURE-004','Sollicitation sans moyen de se désinscrire',
     'Une sollicitation qui promet l’invérifiable sans offrir aucun mécanisme normalisé de désinscription ne se comporte pas comme une diffusion consentie.',
     'adverse',20,'low','L’absence d’en-tête de désinscription est banale dans un échange personnel : ce signal ne vaut que conjointement au registre promotionnel, et ne fonde jamais seul une qualification de danger.','{"context_kind":"solicitation_without_opt_out","requires_promotional_register":true}')
) AS article(article_code,title,principle,direction,strength,severity,limitations,parameters)
ON CONFLICT (edition_id, article_code) DO UPDATE SET
    title=EXCLUDED.title, principle=EXCLUDED.principle,
    default_direction=EXCLUDED.default_direction,
    default_strength=EXCLUDED.default_strength, severity=EXCLUDED.severity,
    limitations=EXCLUDED.limitations, parameters=EXCLUDED.parameters,
    enabled=true;

UPDATE code_articles SET
    principle=
        'Un envoi promotionnel qui repose sur des promesses invérifiables de '
        'santé ou d’enrichissement relève d’un registre de sollicitation non '
        'désirée, qu’il se déclare ou non comme une diffusion de masse.'
WHERE article_code='NATURE-003';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'code.undeclared_solicitation_enabled',
    '{"articles":["NATURE-004"],"nature_003_no_longer_requires_bulk_headers":true}'
);
