-- Le montage ciblé n'imite aucune marque connue : il crée un domaine pour
-- l'occasion et détourne les réponses. Aucun référentiel ne peut le prévoir ;
-- seule la convergence des deux faits le décrit.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, 'CORR-005', 'Convergence : approche préparée',
       'Un domaine créé récemment dont les réponses partent ailleurs décrit une approche montée pour ce message, et non une correspondance ordinaire.',
       'adverse', 70, 'high',
       'Une entreprise nouvelle utilise parfois un domaine récent et un prestataire distinct : la convergence signale, elle ne conclut pas.',
       '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
WHERE NOT EXISTS (SELECT 1 FROM code_articles a WHERE a.article_code = 'CORR-005');

UPDATE attack_techniques
SET indicator_clues = '["IDENTITY_COUSIN_DOMAIN", "CORRELATION_COUSIN_DOMAIN_APPROACH", "CORRELATION_PREPARED_APPROACH"]'::jsonb
WHERE technique_code = 'COUSIN_DOMAIN';
