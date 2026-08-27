-- Une destination actionnable, hors de l'apex de l'expéditeur, vers un domaine
-- fraîchement enregistré, reste suspecte MÊME quand l'expéditeur est authentifié :
-- l'authentification prouve la maîtrise du domaine émetteur, pas l'innocuité de
-- la destination. C'est le motif du phishing par abus d'ESP (SendGrid & co.),
-- où un domaine établi et aligné DMARC renvoie vers un site enregistré la veille.
-- Discriminant sûr contre les faux positifs (newsletters authentifiées à
-- redirection : Fulli, Synology) : celles-ci pointent vers des apex établis.
WITH edition AS (
    SELECT id FROM code_editions
    WHERE code_name='Code Sentinel' AND status='active'
)
INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters
)
SELECT edition.id, article_code, title, principle, direction, strength,
       severity, limitations, parameters::jsonb
FROM edition
CROSS JOIN (VALUES
    ('DOMAIN-004','Destination inter-apex récente',
     'Un lien actionnable menant, hors de l’apex de l’expéditeur, vers un domaine enregistré depuis peu augmente le doute même sous authentification : l’alignement DMARC couvre le domaine émetteur, jamais la destination.',
     'adverse',60,'high','Une marque authentifiée peut légitimement renvoyer vers un partenaire ou une campagne ; le doute ne naît que si la destination est récente, pas de tout renvoi inter-apex.','{"high_risk_days":30}')
) AS article(article_code,title,principle,direction,strength,severity,limitations,parameters)
ON CONFLICT (edition_id, article_code) DO UPDATE SET
    title=EXCLUDED.title, principle=EXCLUDED.principle,
    default_direction=EXCLUDED.default_direction,
    default_strength=EXCLUDED.default_strength, severity=EXCLUDED.severity,
    limitations=EXCLUDED.limitations, parameters=EXCLUDED.parameters,
    enabled=true;
