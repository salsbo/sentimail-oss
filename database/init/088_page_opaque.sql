-- 16 et 17 septembre 2026 : deux faux reçus « Prime » (M-a9e895, livré à 0,95 ;
-- M-373976, soumis pour avis) menaient, par leur seul lien d'action, à une page
-- de 484 octets sur un sous-domaine d'hébergement jetable : servie en 200, sans
-- texte, sans lien, sans formulaire, tout dans un script que le bac à sable
-- n'exécute pas. Il l'avait vue et l'avait rendue comme « rien observé » ; le
-- juge y a lu une absence de charge. Deux articles.
--
-- DEEP-025 : la coquille sans script est écrite, neutre. Mesure sur 60 jours :
-- 105 indésirables, 2 dangereux, 24 suspects, 8 légitimes (désinscriptions,
-- jeu-concours, pages de suivi d'un routeur d'emailing, et le faux reçu
-- lui-même). Trop de légitimes pour une charge, et surtout pas une barrière.
--
-- CORR-016 : finalité de paiement, première observation, page opaque. Mesure
-- sur 60 jours : 7 messages réunissaient les trois faits, aucun légitime (trois
-- indésirables, deux retenus dont un qualifié indésirable par l'utilisateur, le
-- faux reçu du 16 qualifié dangereux après coup, celui du 17).

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
    ('DEEP-025', 'Page d''arrivée opaque sans script',
     'Un lien d''action mène, hors du domaine de l''expéditeur, à une page HTML servie normalement, minuscule, qui ne montre rien à un lecteur sans script : ni texte, ni lien, ni formulaire. Le contrôle du lien n''a rien pu lire de la destination, et le dossier doit le dire : « rien observé » n''est pas « rien à voir ». Le constat est neutre, parce qu''une application rendue par script, une désinscription ou un jeu-concours se présentent pareil.',
     'neutral', 0, 'info',
     'Ne concerne ni une page lourde dont aucun texte ne sort, ni le squelette d''une application qui embarque son amorçage, ni une feuille de style, ni une image, ni un refus. Seul un lien d''action compte : la désinscription en pied de page et la navigation secondaire ne sont pas l''acte proposé. Neutre par construction : seule une convergence lui donne un poids.'),
    ('CORR-016', 'Convergence : leurre de transaction fictive vers une page opaque',
     'Le message annonce un paiement, un reçu ou un abonnement ; cet expéditeur écrit pour la première fois ; son lien d''action mène à une page que le contrôle ne peut pas lire. Aucun des trois faits ne suffit. Réunis, ils décrivent le leurre de transaction fictive : un paiement « confirmé » pour un achat jamais fait, un seul lien pour « gérer » ou « annuler », et la collecte cachée derrière une page vide pour tout lecteur sans script. La sœur de CORR-014 : là où celle-ci lit le vide autour de l''expéditeur, celle-ci lit le vide au bout du lien.',
     'adverse', 55, 'high',
     'Un vrai reçu en première observation mène à une page qui se lit. Un apex qui a déjà livré ici l''exclut. Sans preuve matérielle de collecte, elle fonde une question à l''utilisateur, pas un classement en indésirable.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a
    WHERE a.article_code = v.article_code AND a.edition_id = e.id
);

UPDATE attack_techniques
SET indicator_clues = indicator_clues || '["CORRELATION_OPAQUE_TRANSACTION_LURE","URL_OPAQUE_LANDING"]'::jsonb,
    description = description || ' Le lien mène souvent à une page vide pour tout lecteur sans script, sur un hébergement gratuit : le contrôle n''y lit rien, et c''est voulu.'
WHERE technique_code = 'FAKE_TRANSACTION_LURE'
  AND NOT indicator_clues ? 'CORRELATION_OPAQUE_TRANSACTION_LURE';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'policy.opaque_landing_and_opaque_transaction_lure',
    '{"neutral_article":"DEEP-025","new_correlation":"CORR-016","technique":"FAKE_TRANSACTION_LURE","cases":["M-a9e895","M-373976"]}'::jsonb
);
