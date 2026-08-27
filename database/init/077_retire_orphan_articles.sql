-- Trois articles n'ont plus de producteur depuis la suppression du référentiel
-- de marques : ils resteraient au Code, actifs, sans que rien ne puisse jamais
-- les invoquer. Un article actif que personne ne produit est trompeur - il
-- donne à croire que le contrôle existe.
--
-- Les indices déjà écrits sous ces articles restent en base : les dossiers
-- instruits gardent leur motivation, et la jurisprudence son historique.
UPDATE code_articles SET enabled = false
WHERE article_code IN ('IDENTITY-009', 'IDENTITY-010', 'DEEP-017');
