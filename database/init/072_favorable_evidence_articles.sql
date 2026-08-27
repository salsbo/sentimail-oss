-- Chantier « indices favorables » (22/08, amendé le 24/08 après revue
-- contradictoire round 1) : un dossier légitime en premier contact ne
-- portait souvent aucune preuve à décharge, seulement l'absence de charge -
-- ce qui ne distingue rien et finissait en ask_user. Ces articles décrivent
-- des faits positifs réels, chacun réuni de plusieurs conditions pour rester
-- difficile à contrefaire seul.
--
-- Amendement du 24/08 (permis une seule fois : cette migration n'a encore
-- été appliquée à aucun environnement réel, seulement à un conteneur
-- Postgres jetable détruit en fin de session) :
--   - HEADERS-004 repasse en 'neutral' : l'alignement syntaxique
--     List-Unsubscribe/From, seul, ne prouve RIEN sur qui a envoyé le
--     message - un From usurpé porte les deux en-têtes aussi facilement
--     qu'un expéditeur réel. Le hook headers n'a pas accès à
--     l'authentification ; il consigne donc un fait structurel, pas une
--     preuve.
--   - CORR-013 est ajouté : la corrélation qui, elle, exige en plus une
--     authentification DMARC réellement alignée avant de créditer quoi que
--     ce soit. C'est elle qui porte le poids favorable, à
--     deep_analysis._signals où `authenticated` est connu.
--   - Deux index d'appui sont ajoutés pour les requêtes d'indice n°2 (apex
--     éprouvé) et n°4 (langue habituelle), déjà bornées côté application
--     (HIST-004 court-circuité si l'adresse a un historique, langue plafonnée
--     à 200 lignes) mais qui bénéficient d'un accès direct par domaine.

INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.default_direction,
       v.default_strength, v.severity, v.limitations, '{}'::jsonb, true
FROM (SELECT id FROM code_editions ORDER BY id DESC LIMIT 1) e
CROSS JOIN (VALUES
    ('CORR-012', 'Cohérence transactionnelle',
     'Une notification déclenchée par l''action même du destinataire (confirmation, reçu, code) tient parole quand elle réunit trois faits distincts : sa nature transactionnelle, une authentification alignée et un domaine expéditeur établi depuis au moins deux ans. Aucun des trois pris seul ne prouve rien - un attaquant écrit lui aussi « confirmez votre commande » - mais aligner son authentification sur un domaine qu''il ne contrôle pas depuis deux ans coûte cher à contrefaire.',
     'favorable', 25, 'info',
     'Un domaine établi mais compromis reste possible ; cette convergence pèse peu et ne dispense d''aucune autre vérification matérielle.'),
    ('HIST-004', 'Apex éprouvé localement',
     'Une adresse jamais vue peut appartenir à un domaine dont d''autres adresses ont déjà livré plusieurs messages sans qu''aucun n''ait été étiqueté indésirable ou dangereux, toutes boîtes confondues. L''ancienneté minimale de sept jours et l''absence de toute étiquette humaine défavorable distinguent un apex réellement éprouvé d''un domaine qui s''auto-blanchirait en enchaînant des adresses fraîches.',
     'favorable', 25, 'info',
     'Un domaine mutualisé (ESP, hébergeur de masse) peut réunir des expéditeurs sans rapport entre eux ; le fait s''efface dès la première étiquette humaine défavorable sur l''apex.'),
    ('HEADERS-004', 'Structure de désinscription RFC 8058',
     'Un en-tête List-Unsubscribe pointant une adresse https dont l''apex s''écrit comme celui du domaine From, combiné à List-Unsubscribe-Post: List-Unsubscribe=One-Click, décrit une structure de désinscription en un clic conforme à la RFC 8058. C''est un fait purement syntaxique : il ne dit rien de qui a réellement envoyé le message.',
     'neutral', 0, 'info',
     'Un From usurpé peut porter exactement les deux mêmes en-têtes, alignés de la même façon : sans authentification vérifiée, cet alignement ne distingue pas un expéditeur réel d''un expéditeur imité. Voir CORR-013 pour la corrélation qui exige en plus cette authentification.'),
    ('HIST-005', 'Langue habituelle du destinataire',
     'Un message rédigé dans la langue que ce destinataire reçoit déjà très majoritairement (au moins dix messages d''historique, au moins 70 % dans cette langue) s''inscrit dans un usage établi, sans rien dire de l''expéditeur du jour.',
     'favorable', 15, 'info',
     'Un destinataire multilingue ou un historique trop court ne permet aucune dominance fiable ; le fait reste faible et ne se combine avec aucun autre pour fonder seul une décision.'),
    ('CORR-013', 'Désinscription RFC 8058 authentifiée',
     'La structure de désinscription en un clic (HEADERS-004), seule syntaxique, devient une preuve faible quand elle se combine à une authentification DMARC réellement alignée sur le même domaine : deux faits indépendants - un structurel, un cryptographique - qu''un expéditeur usurpé ne réunit pas ensemble aussi facilement que l''un des deux seul.',
     'favorable', 20, 'info',
     'Un domaine authentifié mais compromis, ou un ESP légitimement partagé par plusieurs marques, reste possible : le poids accordé reste modeste et ne dispense d''aucune autre vérification.')
) AS v(article_code, title, principle, default_direction, default_strength,
       severity, limitations)
WHERE NOT EXISTS (
    SELECT 1 FROM code_articles a WHERE a.article_code = v.article_code
);

-- Amendement 24/08 : sur un article déjà seedé une première fois par ce
-- fichier (ex. dans un environnement où 072 a déjà tourné avant cet
-- amendement), le WHERE NOT EXISTS ci-dessus ne réécrit rien. On corrige
-- donc explicitement HEADERS-004 s'il existe encore avec son ancienne
-- direction 'favorable' - idempotent, sans effet si la ligne est déjà à jour
-- ou absente.
UPDATE code_articles
SET default_direction = 'neutral',
    default_strength = 0,
    title = 'Structure de désinscription RFC 8058',
    principle = 'Un en-tête List-Unsubscribe pointant une adresse https dont l''apex s''écrit comme celui du domaine From, combiné à List-Unsubscribe-Post: List-Unsubscribe=One-Click, décrit une structure de désinscription en un clic conforme à la RFC 8058. C''est un fait purement syntaxique : il ne dit rien de qui a réellement envoyé le message.',
    limitations = 'Un From usurpé peut porter exactement les deux mêmes en-têtes, alignés de la même façon : sans authentification vérifiée, cet alignement ne distingue pas un expéditeur réel d''un expéditeur imité. Voir CORR-013 pour la corrélation qui exige en plus cette authentification.'
WHERE article_code = 'HEADERS-004' AND default_direction <> 'neutral';

-- Index d'appui pour l'apex éprouvé (indice n°2) : accès direct par domaine
-- d'expéditeur, restreint aux messages effectivement délivrés - exactement
-- le prédicat de la requête dans _history(), déjà court-circuitée quand
-- l'adresse a un historique propre.
CREATE INDEX IF NOT EXISTS ix_messages_delivered_sender_domain
    ON messages ((lower(split_part(envelope_from, '@', 2))))
    WHERE delivery_status = 'delivered';

-- Index d'appui pour les étiquettes défavorables sur un apex : même logique,
-- côté `labels`, restreint aux libellés humains actifs spam/dangereux -
-- exactement le prédicat de la seconde requête de l'indice n°2.
CREATE INDEX IF NOT EXISTS ix_labels_adverse_sender_domain
    ON labels ((lower(split_part(coalesce(sender_normalized, ''), '@', 2))))
    WHERE is_ground_truth = true AND active = true
      AND label IN ('spam', 'dangerous');

-- Index d'appui pour la langue habituelle du destinataire (indice n°4) : la
-- requête filtre d'abord sur clue_code, sans index dédié jusqu'ici (seul
-- article_code était indexé sur `clues`). Générique, pas seulement pour ce
-- chantier.
CREATE INDEX IF NOT EXISTS ix_clues_clue_code ON clues (clue_code);
