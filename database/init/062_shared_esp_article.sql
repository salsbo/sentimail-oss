-- AUTH-009 : infrastructure d'envoi mutualisée. Neutre - il retire à
-- l'authentification son crédit de légitimité de marque sans accuser seul.
-- Recherche du 20/08 : motif du compte ESP jetable (SendGrid & co).

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
CROSS JOIN (VALUES
    ('AUTH-009', 'Infrastructure d''envoi mutualisée',
     'Un message parti d''une plateforme d''emailing partagée (SendGrid, Mailgun, SES…) est authentifié pour le domaine de la plateforme, non pour la marque affichée : l''authentification n''est plus une preuve de légitimité de marque. Le fait est neutre en soi, la plupart des envois honnêtes en relèvent ; il ne pèse que corrélé à une marque imitée, un domaine jeune ou une collecte de mot de passe.',
     'neutral', 0, 'info',
     'Un client qui configure son propre domaine de bounce et d''authentification n''est pas concerné : c''est ce qui distingue l''envoi délégué propre du compte jetable.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a WHERE a.article_code = v.article_code
);
