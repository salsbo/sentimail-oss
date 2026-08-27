-- Le cloaking n'avait aucun article : le code ne connaissait que la redirection
-- inter-apex (DEEP-001), que tout prestataire de suivi pratique légitimement.
-- Un site qui répond différemment selon l'identité de qui demande est un fait
-- d'une autre nature : la page montrée au scanner n'est pas celle montrée au
-- visiteur. Aucun service authentique n'a de raison de faire cela.
--
-- Quarante pour cent des URL de phishing recensées en 2025 pratiquent ce
-- service conditionnel. Sans le détecter, une inspection reçoit la page anodine
-- que le site a choisi de lui montrer, et rassure faussement l'examen - ce qui
-- est pire qu'une inspection manquante, laquelle se déclare au moins incomplète.
--
-- La force est haute mais non maximale, et il n'y a pas de barrière de
-- livraison : le fait est établi par comparaison, pas par observation d'un
-- dommage. Un site peut servir des pages différentes par géolocalisation ou
-- négociation de langue sans intention hostile - d'où la limitation.
WITH edition AS (
    SELECT id FROM code_editions ORDER BY created_at DESC LIMIT 1
)
INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters
)
SELECT edition.id,
       'DEEP-020',
       'Service conditionnel selon le visiteur',
       'Un lien qui répond différemment selon l''identité de qui le demande dissimule sa destination réelle.',
       'adverse',
       75,
       'high',
       'Une géolocalisation ou une négociation de langue peuvent produire des pages différentes sans intention hostile ; la divergence observée doit être nommée.',
       '{"requires_named_divergence": true}'::jsonb
FROM edition
ON CONFLICT (edition_id, article_code) DO NOTHING;
