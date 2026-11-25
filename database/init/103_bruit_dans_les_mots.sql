-- 16 et 29 octobre 2026 : une arnaque à la « carte Améli » (M-7156ca, M-96852d)
-- est partie en boîte de réception avec un verdict légitime à 0,92, deux fois.
-- Le nom affiché « L'assuranc e vous informe », l'objet « Carte A′̍meli » (une
-- prime et une marque combinante au milieu du mot) et un corps où presque
-- chaque mot porte un accent aigu (« com´mands », « T´ermius ») se lisent
-- comme du texte ordinaire et ne se cherchent plus. Le HTML ne rendait que
-- « 616 » et un lien : tout le texte Termius était caché, et répété en clair
-- dans la partie text/plain, que le juge lisait seule.
--
-- CONTENT-017 : la coupure d'un mot par un signe qui n'est pas une apostrophe.
-- Mesure sur les 2 724 messages livrés des 60 derniers jours : trois touchés,
-- les deux envois de cette campagne et un transfert du second. Aucun autre.
--
-- CORR-020 : un déguisement (mots coupés, texte caché, écritures mêlées),
-- depuis un expéditeur jamais vu dont personne ne répond. Aucun des trois
-- faits ne suffit ; réunis, ils retirent à l'expéditeur la posture de
-- confiance et font du message un vrai doute.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, v.parameters::jsonb, true
FROM (
    SELECT id FROM code_editions
    WHERE status = 'active'
    ORDER BY created_at DESC LIMIT 1
) e
CROSS JOIN (VALUES
    ('CONTENT-017', 'Mots coupés par des signes parasites',
     'Un mot dont l''intérieur porte un accent aigu, une prime, un modificateur ou une marque combinante qu''aucune lettre voisine ne peut porter se lit comme le mot ordinaire, mais ne se retrouve plus par une recherche. Dans l''objet ou le nom affiché, un seul mot suffit ; dans le corps, il en faut quatre. Le constat est fait sur le texte recomposé (NFC) : un accent écrit en deux codepoints par un client Mac se recompose et ne compte pas.',
     'adverse', 60, 'high',
     'L''apostrophe tapée avec un accent aigu (« l´été », « aujourd´hui », « don´t ») n''est pas une coupure : une seule lettre, ou une contraction connue, de part et d''autre du signe. Un nom propre ou un mot étranger qui porte une marque réellement composée n''est pas relevé. Le constat ne dit rien de l''expéditeur : il dit que le texte lu n''est pas le texte cherché.',
     '{"clue_code":"CONTENT_INTRAWORD_NOISE"}'),
    ('CORR-020', 'Convergence : mots altérés depuis un expéditeur sans répondant',
     'Le message présente des mots coupés (CONTENT-017), un texte caché absent de ce que le HTML rend (CONTENT-013) ou des écritures mêlées (CONTENT-012), et son expéditeur écrit pour la première fois sans que personne ne réponde publiquement de son domaine. L''authentification ne défait pas le faisceau : un domaine jetable signe très bien ses propres envois.',
     'adverse', 75, 'high',
     'Aucun des trois faits ne suffit seul. Un apex qui a déjà livré ici défait le faisceau, et un expéditeur qui a un répondant public l''exclut. Sans preuve matérielle de collecte, il fonde une question à l''utilisateur, pas un classement en indésirable.',
     '{"clue_code":"CORRELATION_DISGUISED_UNKNOWN_SENDER"}')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations, parameters)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a
    WHERE a.article_code = v.article_code AND a.edition_id = e.id
);

UPDATE attack_techniques
SET indicator_clues = indicator_clues || '["CONTENT_INTRAWORD_NOISE","CORRELATION_DISGUISED_UNKNOWN_SENDER"]'::jsonb
WHERE technique_code = 'TEXT_OBFUSCATION'
  AND NOT indicator_clues ? 'CONTENT_INTRAWORD_NOISE';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'policy.intraword_noise_and_disguised_unknown_sender',
    '{"articles":["CONTENT-017","CORR-020"],"technique":"TEXT_OBFUSCATION","cases":["M-7156ca","M-96852d"],"delivered_messages_measured":2724,"messages_touched":3,"false_positives":0}'::jsonb
);
