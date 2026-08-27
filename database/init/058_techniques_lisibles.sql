-- Les techniques d'attaque, dites à qui les reçoit.
--
-- Le registre s'adressait à qui connaît le courrier électronique : SPF, DKIM,
-- DMARC, Reply-To, Unicode, ISO dans ZIP. Ces mots ne disent rien à la
-- personne qui reçoit l'avis, et le paragraphe qui les portait faisait deux à
-- trois lignes là où le message est déjà classé - elle ne lira pas.
--
-- Chaque technique tient désormais en une phrase, dans les mots de tous les
-- jours, et porte un conseil : que faire de ce message-là. Ce n'est pas de
-- l'ornement. Un avis qui nomme une manœuvre sans dire quoi en faire laisse
-- la personne devant sa décision, exactement là où l'attaque la veut.
--
-- Les codes, les catégories, les indices et les références MITRE ne bougent
-- pas : c'est le texte lu qui change, jamais ce que le registre reconnaît.

ALTER TABLE attack_techniques
    ADD COLUMN IF NOT EXISTS advice text NOT NULL DEFAULT '';

UPDATE attack_techniques SET description = v.description, advice = v.advice
FROM (VALUES
('SENDER_SPOOFING',
 'Le message a été écrit sous une adresse qui n''appartient pas à celui qui l''envoie.',
 'Ne réponds pas à cette adresse. Si le sujet compte, contacte l''organisation par un moyen que tu connais déjà.'),
('DISPLAY_NAME_IMPERSONATION',
 'Le nom affiché n''est pas celui de l''adresse réelle, et sur un téléphone seul le nom se voit.',
 'Regarde l''adresse complète avant de répondre, pas le nom.'),
('BRAND_IMPERSONATION',
 'Le message imite l''apparence d''une entreprise connue sans venir d''elle.',
 'N''utilise aucun lien du message. Passe par le site ou l''application que tu utilises d''habitude.'),
('COUSIN_DOMAIN',
 'L''adresse ressemble presque à la vraie : une lettre changée, un tiret ajouté.',
 'Compare lettre à lettre avec un message authentique que tu as déjà reçu.'),
('HOMOGLYPH_UNICODE',
 'Des lettres venues d''autres alphabets, identiques à l''œil, fabriquent une fausse adresse.',
 'Ne te fie pas à l''apparence de l''adresse : ouvre le site depuis tes favoris.'),
('REPLY_TO_SWITCH',
 'Ta réponse n''irait pas à l''expéditeur affiché, mais à une autre adresse.',
 'Si tu dois répondre, écris un message neuf à l''adresse que tu connais.'),
('THREAD_HIJACKING',
 'Le message s''insère dans une conversation réelle pour profiter de la confiance déjà installée.',
 'Vérifie par un autre canal - téléphone, message - avant de faire ce qui est demandé.'),
('CREDENTIAL_PHISHING_LINK',
 'Le lien mène à une fausse page de connexion qui recopie la vraie.',
 'N''entre nulle part ton mot de passe depuis un lien reçu par courrier.'),
('MALICIOUS_ATTACHMENT',
 'La pièce jointe contient un programme déguisé en document.',
 'Ne l''ouvre pas. Si tu attendais ce fichier, demande à l''expéditeur de te le renvoyer autrement.'),
('HTML_SMUGGLING',
 'La pièce jointe se fabrique toute seule une fois ouverte, pour passer les contrôles.',
 'Ne l''ouvre pas, même si elle porte un nom rassurant.'),
('QUISHING',
 'Le lien piégé est caché dans un code à scanner, pour te faire basculer sur ton téléphone.',
 'Ne scanne pas ce code. Un vrai service ne demande jamais de le faire depuis un courrier.'),
('CALLBACK_PHISHING',
 'Une fausse facture et un numéro à appeler : au téléphone, on te fera installer un outil.',
 'N''appelle pas ce numéro. Cherche le vrai sur tes factures ou sur le site officiel.'),
('REDIRECT_CHAIN',
 'Le lien visible n''est que le premier d''une suite de sauts vers une autre destination.',
 'Ne clique pas. Rien ne permet de savoir où l''on arrive avant d''y être.'),
('OPEN_REDIRECT_ABUSE',
 'Le lien part d''un site connu, qui renvoie ensuite n''importe où.',
 'La réputation du site de départ ne dit rien de l''arrivée : ne clique pas.'),
('URL_SHORTENER_ABUSE',
 'Le lien est raccourci : sa destination réelle est invisible.',
 'Ne clique pas sur un lien raccourci dans un message que tu n''attendais pas.'),
('URL_OBFUSCATION',
 'L''adresse du lien est écrite de façon à cacher où elle mène vraiment.',
 'Ne clique pas. Va sur le site par tes propres moyens.'),
('TEXT_OBFUSCATION',
 'Le texte contient des caractères invisibles destinés à tromper les filtres.',
 'Rien à faire de ton côté : c''est un signe que le message cherche à passer inaperçu.'),
('URGENCY_PRESSURE',
 'Un délai court est imposé pour t''empêcher de vérifier.',
 'Prends le temps. Aucune organisation sérieuse ne perd un dossier parce que tu as vérifié.'),
('AUTHORITY_IMPERSONATION',
 'Le message se réclame d''une autorité - banque, impôts, police - pour obtenir l''obéissance.',
 'Une administration n''exige jamais un paiement ou un mot de passe par courrier.'),
('ACCOUNT_SUSPENSION_LURE',
 'La menace de fermer ton compte sert à te faire cliquer sans réfléchir.',
 'Connecte-toi à ton compte comme d''habitude : s''il y a un problème, tu le verras là.'),
('EXTORTION_SEXTORSION',
 'Le message menace de diffuser des données prétendument volées et réclame un paiement.',
 'Ne paie pas, ne réponds pas. Ces messages sont envoyés en masse, au hasard.'),
('BEC_WIRE_FRAUD',
 'Quelqu''un se fait passer pour un dirigeant ou un fournisseur, et amène à un virement.',
 'Confirme de vive voix, à un numéro que tu connais, avant tout paiement.'),
('GIFT_CARD_SCAM',
 'On te demande d''acheter des cartes cadeaux et d''en envoyer les codes.',
 'Aucun employeur ne demande cela. N''envoie jamais un code de carte cadeau.'),
('ADVANCE_FEE_FRAUD',
 'Un gain ou un héritage est promis contre de petits frais à régler d''abord.',
 'Les frais sont le seul argent qui circulera. N''envoie rien.')
) AS v(code, description, advice)
WHERE attack_techniques.technique_code = v.code;
