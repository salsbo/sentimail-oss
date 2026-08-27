-- Le registre des techniques d'attaque : nommer ce qu'on a reconnu.
--
-- Étiqueter un message « hameçonnage » dit ce qu'il est ; nommer la technique
-- dit comment il s'y prend, et c'est ce qui s'enseigne. Le registre est une
-- donnée versionnée avec le code, jamais un savoir appris dans des poids : il
-- s'audite ligne à ligne, se met à jour par migration relue, et le modèle ne
-- peut que CHOISIR dedans - jamais y écrire, jamais inventer un code. C'est la
-- réponse au risque d'empoisonnement : la surface d'entrée du registre est le
-- dépôt Git, pas le courrier analysé.
--
-- Les références MITRE ATT&CK sont portées par le registre et dérivées côté
-- serveur : le modèle ne produit jamais un « T15xx » de lui-même.

CREATE TABLE IF NOT EXISTS attack_techniques (
    technique_code text PRIMARY KEY,
    name text NOT NULL,
    category text NOT NULL CHECK (category IN (
        'impersonation', 'delivery', 'url', 'obfuscation',
        'social_engineering', 'objective'
    )),
    description text NOT NULL,
    -- Indices déterministes qui suggèrent la technique. Des repères, jamais
    -- une preuve : la reconnaissance finale appartient au verdict.
    indicator_clues jsonb NOT NULL DEFAULT '[]'::jsonb,
    mitre_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    enabled boolean NOT NULL DEFAULT true,
    -- Le registre est vivant : chaque reconnaissance compte et se date.
    observations bigint NOT NULL DEFAULT 0,
    last_seen_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO attack_techniques (technique_code, name, category, description, indicator_clues, mitre_refs) VALUES
('SENDER_SPOOFING','Usurpation d''adresse expéditeur','impersonation',
 'L''expéditeur écrit sous une adresse qui ne lui appartient pas : l''authentification (SPF, DKIM, DMARC) échoue car le vrai propriétaire du domaine n''a pas autorisé cet envoi. C''est la fondation de la plupart des hameçonnages.',
 '["AUTH_DMARC_FAIL","AUTH_SPF_FAIL"]','["T1598","T1656"]'),
('DISPLAY_NAME_IMPERSONATION','Usurpation du nom affiché','impersonation',
 'Le nom visible (« Banque Postale ») ne correspond pas à l''adresse réelle, souvent une messagerie gratuite. Redoutable sur mobile, où seul le nom s''affiche.',
 '[]','["T1656"]'),
('BRAND_IMPERSONATION','Usurpation de marque','impersonation',
 'Le message imite l''apparence d''une entreprise connue (logos, mise en page, ton) sans venir d''elle. L''habillage rassure, l''adresse et les liens trahissent.',
 '[]','["T1656"]'),
('COUSIN_DOMAIN','Domaine cousin (typosquatting)','impersonation',
 'Un domaine presque identique au vrai : lettre doublée, tiret ajouté, extension changée (micros0ft-support.com). L''œil pressé n''y voit que du feu.',
 '[]','["T1656"]'),
('HOMOGLYPH_UNICODE','Homographes Unicode','obfuscation',
 'Des caractères d''autres alphabets remplacent des lettres identiques à l''œil (le « а » cyrillique pour le « a » latin) afin de fabriquer un domaine ou un texte trompeur qui échappe aux comparaisons exactes.',
 '[]','[]'),
('REPLY_TO_SWITCH','Détournement de la réponse (Reply-To)','impersonation',
 'Le message part d''une adresse plausible mais la réponse est aiguillée vers une autre, contrôlée par l''attaquant. On croit répondre à l''expéditeur affiché.',
 '["HEADERS_REPLY_TO_DIFFERENT_DOMAIN"]','["T1598"]'),
('THREAD_HIJACKING','Détournement de conversation','impersonation',
 'L''attaquant répond dans un fil existant, souvent depuis un compte compromis : l''historique authentique met en confiance et fait baisser la garde.',
 '[]','["T1566"]'),
('CREDENTIAL_PHISHING_LINK','Lien de collecte d''identifiants','delivery',
 'Un lien mène à une fausse page de connexion qui recopie la vraie. L''identifiant et le mot de passe saisis partent chez l''attaquant.',
 '["URL_GENERIC_FORM"]','["T1566.002"]'),
('MALICIOUS_ATTACHMENT','Pièce jointe piégée','delivery',
 'La pièce jointe porte la charge : exécutable déguisé, macro de document, archive imbriquée (ISO dans ZIP) pour esquiver les protections de provenance.',
 '[]','["T1566.001"]'),
('HTML_SMUGGLING','Contrebande HTML','delivery',
 'Le fichier HTML joint assemble sa charge dans le navigateur, après les contrôles de la messagerie : rien de malveillant ne transite en clair.',
 '[]','["T1566.001"]'),
('QUISHING','Hameçonnage par QR code (quishing)','delivery',
 'Le lien piégé est encodé dans un QR code : l''attaque bascule sur le téléphone, hors des protections du poste de travail, et le lien n''apparaît nulle part en texte.',
 '[]','["T1566.002"]'),
('CALLBACK_PHISHING','Hameçonnage par rappel téléphonique','delivery',
 'Ni lien ni pièce jointe : une fausse facture et un numéro à appeler. Au téléphone, un faux support fait installer un outil de prise en main.',
 '[]','["T1566"]'),
('REDIRECT_CHAIN','Chaîne de redirections','url',
 'Le lien visible ne montre que le premier maillon : plusieurs sauts successifs mènent à la destination réelle, révélée seulement au bout du chemin.',
 '["URL_UNAUTHENTICATED_CROSS_APEX"]','["T1566.002"]'),
('OPEN_REDIRECT_ABUSE','Abus de redirection ouverte','url',
 'Le lien part d''un site légitime et réputé dont une page de redirection mal protégée renvoie n''importe où : la réputation du site couvre la destination.',
 '[]','["T1566.002"]'),
('URL_SHORTENER_ABUSE','Abus de raccourcisseur d''URL','url',
 'Le raccourcisseur (bit.ly et semblables) masque la destination et neutralise la lecture du lien au survol.',
 '[]','["T1566.002"]'),
('URL_OBFUSCATION','Brouillage d''URL','url',
 'La destination est maquillée : encodages superflus, identifiants factices avant le @, adresse IP littérale, sous-domaines à rallonge qui imitent le vrai domaine en début de lien.',
 '[]','["T1566.002"]'),
('TEXT_OBFUSCATION','Texte brouillé pour les filtres','obfuscation',
 'Des caractères invisibles (largeur nulle), du texte en corps zéro ou des découpages cassent les mots-clés que cherchent les filtres, tout en restant lisibles pour l''humain.',
 '["CONTENT_OBFUSCATION"]','[]'),
('URGENCY_PRESSURE','Pression par l''urgence','social_engineering',
 'Compte suspendu « sous 24 h », offre qui « expire » : l''urgence fabriquée court-circuite la réflexion. Un organisme réel laisse le temps de vérifier.',
 '["CONTENT_URGENCY"]','[]'),
('AUTHORITY_IMPERSONATION','Abus d''autorité','social_engineering',
 'Le message se réclame d''une autorité (banque, impôts, direction, police) pour obtenir l''obéissance sans vérification.',
 '[]','["T1656"]'),
('ACCOUNT_SUSPENSION_LURE','Leurre de suspension de compte','social_engineering',
 'Le prétexte le plus rodé : « votre compte sera fermé, vérifiez maintenant ». La peur de perdre l''accès pousse à cliquer.',
 '[]','[]'),
('EXTORTION_SEXTORSION','Chantage et sextorsion','objective',
 'Le message menace de divulguer des données ou images prétendument volées et réclame un paiement, souvent en cryptomonnaie, intraçable. Le « piratage » allégué est presque toujours du bluff.',
 '["CONTENT_EXTORTION"]','[]'),
('BEC_WIRE_FRAUD','Fraude au virement (BEC)','objective',
 'Sans lien ni pièce jointe : un échange qui se fait passer pour un dirigeant ou un fournisseur et amène, message après message, à un virement ou un changement de RIB. La discrétion est la technique.',
 '[]','["T1598"]'),
('GIFT_CARD_SCAM','Arnaque aux cartes cadeaux','objective',
 'Une demande pressante et confidentielle d''acheter des cartes cadeaux et d''envoyer les codes : intraçable et immédiatement monnayable.',
 '[]','["T1598"]'),
('ADVANCE_FEE_FRAUD','Fraude à l''avance de frais','objective',
 'Gain, héritage ou prix inespéré, contre de « petits frais » à régler d''abord. Les frais sont le seul argent qui circulera jamais.',
 '[]','[]')
ON CONFLICT (technique_code) DO NOTHING;

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'attack.registry_created',
    '{"version":"1.0.0","techniques":24,"model_may":"select_only","mitre":"derived_server_side"}'
);
