-- 16 septembre 2026 : « Annuel-Famille <noreply@mozn.space> » a livré un faux
-- reçu « Prime Famille » (69,90 €, RIB en décor, un lien « Gérer mon
-- abonnement ») à 0,95. Le nom affiché ne désignait personne, le site était
-- muet, le mail était en HTML seul : les deux contrôles d'identité se sont tus
-- et le juge a écrit « aucun indice défavorable ». Un silence ne laisse rien au
-- dossier. L'enquêteur sender_relation rend désormais toujours un constat ;
-- trois articles écrivent ce qui restait tacite, une technique nomme le montage.

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
    ('DEEP-023', 'Répondant public de l''expéditeur',
     'L''enquêteur qui confronte le domaine réel au message rend toujours un constat. Quand ni la recherche, ni le site, ni le nom affiché ne disent qui répond de ce domaine, le vide est écrit : personne ne répond publiquement de l''expéditeur. Quand une recherche ou un modèle a manqué, le constat dit « non vérifié » et ne vaut pas un vide. Quand le nom affiché reprend le domaine ou lui est attribué par la recherche, le constat dit « concordant » : cela établit qui a écrit, pas que le message est honnête.',
     'neutral', 0, 'info',
     'Neutre par construction : un petit expéditeur peu référencé a le droit d''exister. Seule une convergence avec un contexte financier et une première observation lui donne un poids, et jamais depuis un constat « non vérifié ».'),
    ('CONTENT-015', 'Contexte financier',
     'Un message qui parle d''un paiement, d''un reçu, d''une facture, d''un abonnement ou de coordonnées bancaires le dit au dossier, même sans rien demander. Le fait est neutre : un vrai reçu est un contexte financier lui aussi. Il permet au juge de lire le sujet du message quand aucune demande ni pression ne l''a relevé, et aux convergences de le compter.',
     'neutral', 0, 'info',
     'Ne qualifie ni la demande ni l''urgence, couvertes par CONTENT-001 et CONTENT-002. Le vocabulaire financier d''un pied de page de gabarit suffit à le poser.'),
    ('CORR-014', 'Convergence : leurre de transaction fictive',
     'Le message annonce un paiement, un reçu ou un abonnement ; personne ne répond publiquement du domaine qui l''envoie ; cet expéditeur écrit pour la première fois. Aucun des trois faits ne suffit. Réunis, ils décrivent le leurre de transaction fictive : un paiement « confirmé » pour un achat jamais fait, un montant et un RIB en décor, un seul lien pour « gérer » ou « annuler », qui mène à la collecte. L''authentification du domaine ne dit rien contre : l''attaquant enregistre le sien.',
     'adverse', 55, 'high',
     'Une recherche en panne (constat « non vérifié ») n''entre jamais dans cette convergence. Un apex qui a déjà livré ici l''exclut. Sans preuve matérielle de collecte, elle fonde une question à l''utilisateur, pas un classement en indésirable.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a
    WHERE a.article_code = v.article_code AND a.edition_id = e.id
);

INSERT INTO attack_techniques (
    technique_code, name, category, description, indicator_clues, mitre_refs, advice
) VALUES (
    'FAKE_TRANSACTION_LURE', 'Leurre de transaction fictive', 'social_engineering',
    'Le message confirme un paiement, un renouvellement ou un abonnement que le destinataire n''a jamais souscrit, avec un montant, une référence et parfois un RIB en décor. Le seul acte proposé est un lien pour « gérer », « annuler » ou « contester » : c''est lui qui mène à la collecte de coordonnées bancaires ou d''identifiants. L''expéditeur est authentifié sur un domaine qu''il possède et dont personne ne répond ; la marque imitée est dans le corps, pas dans l''adresse.',
    '["CORRELATION_FAKE_TRANSACTION_LURE","CONTENT_FINANCIAL_CONTEXT","SENDER_WITHOUT_PUBLIC_FOOTPRINT"]'::jsonb,
    '["T1566.002"]'::jsonb,
    'Ne clique pas pour annuler. Vérifie l''achat dans ton compte chez le vrai service, en y allant par tes propres moyens. Un vrai reçu vient d''un service que tu utilises, depuis son domaine.'
)
ON CONFLICT (technique_code) DO NOTHING;
