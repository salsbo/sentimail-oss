-- 25 septembre 2026 : « lnfosPRlME <noreply@a2ztelehealth.com> » annonce le
-- renouvellement d'un abonnement Prime Video (M-8d026c). Deux l minuscules y
-- tiennent la place de deux I ; le détecteur de caractères ne cherchait que des
-- fautes précises et n'y a rien vu. Le domaine étant authentifié, le dossier
-- ne portait qu'une incohérence d'activité, et le juge a posé la question.
--
-- DEEP-026 : le nom affiché se lit comme l'organisation que le corps
-- revendique, à condition de confondre des caractères sosies, et ne l'écrit
-- pas. Le squelette seul ne dit rien - « Charlie » en porte un comme tout nom -
-- seule la comparaison à ce que le message revendique lui-même fonde la charge.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (
    SELECT id FROM code_editions
    WHERE status = 'active'
    ORDER BY created_at DESC LIMIT 1
) e
CROSS JOIN (VALUES
    ('DEEP-026', 'Nom affiché déguisé en l''organisation revendiquée',
     'Le message revendique une organisation dans son texte, et son nom affiché ne se lit comme elle qu''en confondant des caractères sosies : un l pour un I, un zéro pour un o, « rn » pour « m ». Le nom a été écrit pour tromper la lecture rapide. C''est une identité empruntée, même quand le domaine qui l''envoie est authentique.',
     'adverse', 70, 'high',
     'Ne vaut que rapporté à une organisation que le message écrit lui-même : un caractère ambigu isolé reste un fait neutre (IDENTITY-007). Un domaine que la recherche attribue à l''organisation l''écarte.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a
    WHERE a.article_code = v.article_code AND a.edition_id = e.id
);

UPDATE attack_techniques
SET indicator_clues = indicator_clues || '["IDENTITY_DISPLAY_NAME_DISGUISED"]'::jsonb
WHERE technique_code IN ('DISPLAY_NAME_IMPERSONATION', 'BRAND_IMPERSONATION', 'HOMOGLYPH_UNICODE')
  AND NOT indicator_clues ? 'IDENTITY_DISPLAY_NAME_DISGUISED';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'policy.disguised_display_name',
    '{"article":"DEEP-026","clue":"IDENTITY_DISPLAY_NAME_DISGUISED","techniques":["DISPLAY_NAME_IMPERSONATION","BRAND_IMPERSONATION","HOMOGLYPH_UNICODE"],"cases":["M-8d026c"]}'::jsonb
);
