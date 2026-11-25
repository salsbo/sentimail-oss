-- 16 septembre 2026 : « Account Team Support <support@mundololita.com> »,
-- « Storage Is Full », gabarit à la manière d'Apple. DMARC en échec, SPF et
-- DKIM absents, domaine d'une boutique de vêtements. Le lien menait, sur
-- storage.googleapis.com, à « Cloudflare Verification Required. Slide to
-- verify ». Le juge a demandé l'avis du destinataire : « aucune preuve
-- matérielle de dommage ». Deux trous, deux articles.
--
-- DEEP-024 : la page de vérification factice devient une preuve matérielle de
-- tromperie. Mesure sur 60 jours : aucune page servie en 200, courte, sans
-- lien, hors du domaine de l'expéditeur, sur un message légitime ; les vrais
-- murs anti-robot répondaient 403.
--
-- CORR-015 : l'incohérence d'activité sans authentification décrit une
-- adresse empruntée. CORR-007 disait « s'authentifie correctement » sans le
-- vérifier ; elle exige désormais DMARC validé. Mesure sur 60 jours : 93
-- messages en première observation réunissaient les trois faits, aucun légitime.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, v.parameters, true
FROM (
    SELECT id FROM code_editions
    WHERE status = 'active'
    ORDER BY created_at DESC LIMIT 1
) e
CROSS JOIN (VALUES
    ('DEEP-024', 'Fausse page de vérification humaine',
     'Un vrai contrôle anti-robot refuse d''abord le visiteur automatique : il répond par une erreur (403) et ne sert la page qu''ensuite. Une page servie normalement, hors du domaine de l''expéditeur, qui ne contient que le décor d''une vérification (« Verify you are human », « Slide to verify », captcha) et aucun lien, ne protège rien : elle imite un site protégé et arrête les contrôles avant la page qui suit, où se fait la collecte. C''est une tromperie établie sur pièce.',
     'adverse', 80, 'high',
     'Un vrai mur anti-robot servi en erreur n''est pas concerné : il reste neutre. Une page plus longue, ou qui porte des liens, dit autre chose qu''une vérification et n''est pas retenue. Cette qualification est une barrière de livraison explicite même si le LLM conclut légitime.',
     '{"delivery_barrier":"material_danger","material_kind":"deceptive_verification_gate"}'::jsonb),
    ('CORR-015', 'Convergence : adresse empruntée, métier sans rapport',
     'L''adresse n''est pas authentifiée, le domaine qu''elle affiche publie une activité sans rapport avec le propos du message, et cet expéditeur écrit pour la première fois. Aucun des trois faits ne suffit. Réunis, ils décrivent une usurpation : quelqu''un écrit sous un domaine qui ne reconnaît pas l''envoi et dont le métier n''a rien à voir avec ce qui est annoncé.',
     'adverse', 80, 'high',
     'Un apex qui a déjà livré ici l''exclut. Une configuration d''authentification bancale chez un correspondant connu n''entre pas : la première observation est exigée.',
     '{}'::jsonb)
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations, parameters)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a
    WHERE a.article_code = v.article_code AND a.edition_id = e.id
);

UPDATE code_articles
SET limitations = limitations ||
    ' Elle exige un DMARC validé et aucun défaut d''authentification : sans authentification, c''est CORR-015 qui s''applique.'
WHERE article_code = 'CORR-007'
  AND limitations NOT LIKE '%CORR-015%';

UPDATE attack_techniques
SET indicator_clues = indicator_clues || '["CORRELATION_SPOOFED_UNRELATED_SENDER"]'::jsonb
WHERE technique_code = 'SENDER_SPOOFING'
  AND NOT indicator_clues ? 'CORRELATION_SPOOFED_UNRELATED_SENDER';

UPDATE attack_techniques
SET indicator_clues = indicator_clues || '["URL_FAKE_HUMAN_VERIFICATION"]'::jsonb
WHERE technique_code = 'CREDENTIAL_PHISHING_LINK'
  AND NOT indicator_clues ? 'URL_FAKE_HUMAN_VERIFICATION';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'policy.fake_verification_gate_and_spoofed_unrelated_sender',
    '{"material_articles":["DEEP-024"],"new_correlation":"CORR-015","narrowed_correlation":"CORR-007","case":"M-16ae76"}'::jsonb
);
