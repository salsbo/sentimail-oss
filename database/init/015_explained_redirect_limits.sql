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
    ('DEEP-012','Limite de navigation authentifiée et stabilisée',
     'Une limite de redirections dans une chaîne HTTPS authentifiée qui effectue au plus une transition, reste sur l’apex final et répète un point de navigation est une boucle technique expliquée.',
     'neutral',0,'info','Une chaîne non authentifiée, changeant plusieurs fois d’apex, quittant HTTPS ou sans destination finale vérifiable reste incomplète et bloquante.','{}')
) AS article(article_code,title,principle,direction,strength,severity,limitations,parameters)
ON CONFLICT (edition_id, article_code) DO UPDATE SET
    title=EXCLUDED.title, principle=EXCLUDED.principle,
    default_direction=EXCLUDED.default_direction,
    default_strength=EXCLUDED.default_strength, severity=EXCLUDED.severity,
    limitations=EXCLUDED.limitations, parameters=EXCLUDED.parameters,
    enabled=true;

INSERT INTO audit_log(actor, action, payload)
VALUES ('migration','code.explained_redirect_limits_enabled',
        '{"version":"0.4.1","article":"DEEP-012"}');
