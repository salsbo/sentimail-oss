-- Le nom qu'un message affiche, confronté aux domaines réels de l'organisation
-- qu'il désigne.
--
-- Le référentiel de marques ne peut pas suivre : il contient ce qu'on a déjà
-- vu, et le montage suivant se réclame d'un nom qui n'y est pas. « DISNEY+
-- RECOVERY », envoyé le 26 août depuis le domaine authentifié d'une école de
-- langue australienne, n'a rencontré aucun contrôle - « disney » manquait à la
-- table, et la cohérence d'activité ne compare qu'un métier à un registre de
-- livraison ou de paiement.
--
-- La question se pose désormais pour toute organisation nommée, et la réponse
-- se cherche dehors. Ce qui sort : le nom affiché, rien d'autre.

-- Les domaines officiels d'une organisation, tels qu'une recherche les a
-- rendus. La table est une mémoire, pas une autorité : elle évite de
-- redemander dehors ce qu'on a déjà demandé.
CREATE TABLE IF NOT EXISTS organisation_lookups (
    organisation text PRIMARY KEY,
    apexes text[] NOT NULL DEFAULT '{}',
    source text NOT NULL,
    checked_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE organisation_lookups IS
  'Domaines officiels trouvés pour un nom d''organisation ; cache de recherche, jamais une décision.';

-- DEEP-021 était produit par le code depuis sa création sans jamais avoir été
-- écrit au Code : aucun article, donc aucune force par défaut, aucune famille
-- en base et aucune jurisprudence possible. Il est inscrit ici tel que le
-- module le rend.
WITH edition AS (
    SELECT id FROM code_editions ORDER BY created_at DESC LIMIT 1
)
INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters
)
SELECT edition.id,
       'DEEP-021',
       'Organisation revendiquée étrangère au domaine émetteur',
       'Un message qui se présente au nom d''une organisation doit être envoyé depuis un domaine qui lui appartient.',
       'adverse',
       45,
       'medium',
       'Le constat repose sur un nom et un domaine, sans vérification extérieure : une filiale, une marque commerciale ou un prestataire d''envoi peuvent expliquer l''écart.',
       '{}'::jsonb
FROM edition
ON CONFLICT (edition_id, article_code) DO NOTHING;

-- Quand la recherche a rendu les domaines officiels de l'organisation et que
-- celui qui a écrit n'en fait pas partie, le constat cesse d'être une opinion :
-- il s'appuie sur des adresses citables. Il pèse donc davantage, sans atteindre
-- la force d'un fait matériel observé sur le message lui-même.
WITH edition AS (
    SELECT id FROM code_editions ORDER BY created_at DESC LIMIT 1
)
INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters
)
SELECT edition.id,
       'DEEP-022',
       'Organisation revendiquée démentie par ses domaines officiels',
       'Le nom affiché désigne une organisation dont les domaines officiels, recherchés au moment du contrôle, excluent celui qui a envoyé le message.',
       'adverse',
       65,
       'high',
       'Une recherche muette, en panne ou sans résultat exploitable ne produit aucun indice ; les domaines cités doivent figurer dans les faits de l''indice.',
       '{"requires_official_apexes": true}'::jsonb
FROM edition
ON CONFLICT (edition_id, article_code) DO NOTHING;
