-- Le fil reste analysé. Sa présentation ne prouve ni l'auteur des citations
-- ni un échange préalable auquel le destinataire aurait consenti.
INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT id, 'CONTENT-016', 'Texte actuel et fil cité',
       'Le corps distingue du texte actuel et des citations. Un indice observé dans le fil cité ou dans sa combinaison avec la réponse ne prouve pas que l''expéditeur actuel demande l''action. Le jugement identifie qui demande quoi à qui, et si la réponse adopte les instructions citées.',
       'neutral', 0, 'info',
       'La citation et les en-têtes de fil peuvent être fabriqués. Ils ne prouvent aucun courrier envoyé par le destinataire. Le texte cité, les liens et les fichiers restent examinés ; aucune barrière matérielle ne disparaît.',
       '{"clue_code":"CONTENT_QUOTED_THREAD"}'::jsonb, true
FROM code_editions WHERE code_name='Code Sentinel' AND status='active'
ON CONFLICT (edition_id, article_code) DO NOTHING;

UPDATE code_articles
SET limitations = limitations || ' La fourniture ou la mention d''un RIB ou d''un IBAN ne demande pas un transfert d''argent. Une demande ancienne citée n''est pas imputable à l''expéditeur actuel sans examiner les rôles et une éventuelle reprise de cette demande.'
WHERE article_code IN ('CONTENT-001', 'CONTENT-002', 'CONTENT-003', 'CONTENT-015', 'ACT-001');

UPDATE code_articles
SET limitations = limitations || ' Le nom personnel d''un salarié ou prestataire ne désigne pas à lui seul une organisation étrangère. Contrats, référencement client ou fournisseur, coordonnées bancaires et frais de mission relèvent du fonctionnement courant ; la page d''accueil ne décrit pas tous les services internes.'
WHERE article_code = 'DEEP-019';
