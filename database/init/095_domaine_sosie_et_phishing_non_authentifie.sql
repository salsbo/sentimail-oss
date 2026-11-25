-- 29 septembre 2026 : deux faisceaux qui ne pouvaient pas se former.
--
-- Mesures sur toute la base disponible, du 11 août au 29 septembre 2026 :
-- 49 jours, 4 565 messages. La consigne des 60 jours couvre donc toute
-- l'histoire que la production garde.
--
-- IDENTITY-010 renaît. Son producteur, une table de 108 marques écrite à la
-- main, a été retiré le 27 août 2026 (0bbb14c) ; CORR-004 exigeait son indice
-- et ne pouvait plus se former. L'adresse d'envoi est désormais comparée aux
-- domaines officiels que les recherches passées ont établis
-- (organisation_lookups, relue avec le filtre du nom) : même squelette de
-- caractères sosies, écriture différente, étiquette de cinq lettres au moins.
-- Mesure : aucun message touché, aucun légitime (658 dossiers avec des
-- domaines officiels revendiqués ; 4 565 messages contre 208 domaines
-- officiels en mémoire) ; aucune collision de squelette parmi 5 025 apex
-- observés. La distance d'édition d'une lettre touchait 15 messages dont 13
-- légitimes : écartée. Protection latente, pas la correction d'un faux
-- négatif connu.
--
-- CORR-018 : l'hypothèse de phishing de Rspamd et un défaut
-- d'authentification, sur le modèle de DEEP-010 et DEEP-011. Sous DMARC
-- validé le symbole reste neutre (94 messages, 52 légitimes) ; sans, 3
-- messages, aucun légitime, tous déjà rangés ou retenus. Le score agrégé
-- reste neutre : il additionne les symboles d'authentification déjà comptés
-- par AUTH-002, AUTH-006 et AUTH-008 (306 messages sous DMARC non validé,
-- dont 2 qualifiés légitimes par l'utilisateur, aucune issue changée).

UPDATE code_articles
SET enabled = true,
    title = 'Domaine sosie d''un domaine officiel',
    principle = 'L''adresse d''envoi reprend le squelette d''un domaine que la recherche a établi officiel pour une organisation, sans l''écrire : un 1 pour un l, un zéro pour un o, « rn » pour « m ». La référence est ce que la recherche a rendu pour les organisations revendiquées par le courrier réel, jamais une liste écrite à la main. Le constat vaut identité empruntée.',
    limitations = 'Ne voit ni une faute de frappe (lettre ajoutée, retirée ou intervertie), ni un tiret ajouté, ni une autre extension, ni une étiquette officielle de moins de cinq lettres, ni les domaines que la recherche ne retient jamais comme officiels (hébergeurs, réseaux sociaux, grandes plateformes). Un apex lui-même officiel ou un fait de propriété (délégation NS, signataire DKIM) l''écartent ; un domaine authentifié déjà livré le rend neutre. N''entre pas dans le profil d''usurpation matériel, réservé au nom accolé.'
WHERE article_code = 'IDENTITY-010';

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
    ('CORR-018', 'Convergence : hypothèse de phishing Rspamd sans authentification',
     'Rspamd pose un symbole d''hameçonnage (PHISHING : un lien dont le texte affiche une autre adresse que celle où il mène) et l''identité de l''expéditeur n''est pas authentifiée : DMARC n''est pas validé et un défaut est constaté. Sous DMARC validé, le symbole est le bruit ordinaire des campagnes authentifiées et reste neutre (RSPAMD-007). Sans authentification, personne ne répond de ce que le filtre soupçonne. Même lecture que DEEP-010 et DEEP-011 : une observation, deux sens selon l''authentification.',
     'adverse', 45, 'medium',
     'Un DMARC validé défait le faisceau, même à côté d''un SPF en échec. Sans aucun résultat d''authentification, il ne se forme pas. Le score agrégé n''y entre pas. Heuristique : ni famille de preuve, ni barrière de livraison ; une question plutôt qu''un classement.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a
    WHERE a.article_code = v.article_code AND a.edition_id = e.id
);

UPDATE attack_techniques
SET indicator_clues = indicator_clues || '["CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC"]'::jsonb
WHERE technique_code = 'URL_OBFUSCATION'
  AND NOT indicator_clues ? 'CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'policy.cousin_domain_and_unauthenticated_phishing',
    '{"revived_article":"IDENTITY-010","clue":"IDENTITY_COUSIN_DOMAIN","revived_correlation":"CORR-004","new_correlation":"CORR-018","window":{"from":"2026-08-11","to":"2026-09-29","days":49,"messages":4565},"measures":{"IDENTITY-010":{"messages":0,"legitimate":0},"CORR-018":{"messages":3,"legitimate":0}},"heuristic_scores_never_veto":true}'::jsonb
);
