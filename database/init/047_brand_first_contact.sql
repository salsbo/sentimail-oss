-- L'usurpateur soigneux enregistre son propre domaine et y publie SPF, DKIM et
-- DMARC en règle : « La Poste-Colissimo » depuis notif-colissimo-laposte.info
-- est authentifié sans être authentique. Exiger un défaut d'authentification
-- ne voyait que les montages bâclés ; quatre messages de ce type ont été
-- livrés les 12, 13 et 14 août avec un verdict légitime à 92 %.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, 'CORR-006', 'Convergence : marque connue en premier contact',
       'Une organisation connue qui écrit pour la première fois depuis un domaine qui ne lui appartient pas emprunte sa réputation, que son domaine d''envoi soit correctement authentifié ou non.',
       'adverse', 70, 'high',
       'Une agence mandatée écrit parfois pour la première fois au nom d''un client : la convergence signale, elle ne conclut pas.',
       '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
WHERE NOT EXISTS (SELECT 1 FROM code_articles a WHERE a.article_code = 'CORR-006');

UPDATE attack_techniques
SET indicator_clues = '["IDENTITY_BRAND_MISMATCH", "CORRELATION_BRAND_SPOOFING", "CORRELATION_BRAND_FIRST_CONTACT"]'::jsonb
WHERE technique_code = 'BRAND_IMPERSONATION';
