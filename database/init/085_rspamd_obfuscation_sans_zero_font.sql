-- ZERO_FONT ne relève plus de RSPAMD-009 (13 septembre 2026) : le texte en
-- taille zéro est le texte d'aperçu des gabarits d'envoi, présent sur du
-- courrier authentifié et ordinaire. Le texte caché qui trompe se mesure par
-- CONTENT-013, sur son contenu. L'article ne parle plus que de l'encodage.

UPDATE code_articles
SET principle = 'Un objet ou un nom d''expéditeur encodés en base64 alors qu''ils ne contiennent que des caractères ordinaires sont un procédé pour être lus par un humain sans être lus par un filtre. Un encodage justifié par des caractères non latins n''en est pas un.'
WHERE article_code = 'RSPAMD-009';
