"""Ce que MAIA dit à un humain, à la place de ce que le Code observe.

Un avis arrive un mardi matin dans une boîte : il doit se lire sans connaître le
Code Sentinel, sans savoir ce qu'est DMARC, et sans avoir à interpréter un score.
La preuve technique reste intacte en base, dans les journaux et dans le registre ;
seule sa formulation change ici.

Trois règles tenues par ce module : aucun code interne ni score dans un message,
une limite d'analyse n'est jamais présentée comme un danger, et rien n'est
inventé — chaque phrase traduit un indice réellement observé.

Une phrase dit le constat, pas ce qu'on imagine qu'il entraîne. Elle ne nomme
une conséquence (« s'exécute », « prend la main »), une intention (« pour
cacher ») ou une certitude que si le détecteur l'a établie, dans le contexte
réel d'une messagerie. Compter des balises <script> ne prouve pas qu'un code
s'exécute : aucune messagerie ne les lance. Les expressions de ce genre sont
réservées aux indices qui les prouvent ; un test tient la liste.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from email.utils import parseaddr

# Traduction d'un indice observé vers ce qu'il signifie pour le destinataire.
# Une entrée par article du Code ; l'énoncé technique sert de repli.
_PLAIN = {
    "URL_ACTION_DESTINATION_MISMATCH": "La page atteinte par le bouton ne correspond pas à l'opération annoncée dans le message.",
    "URL_ACTION_DESTINATION_UNVERIFIED": "Je n'ai pas pu établir si le bouton permet bien l'opération annoncée.",
    "URL_ACTION_DESTINATION_CONSISTENT": "La destination observée ne contredit pas l'opération annoncée. Cela ne prouve pas que le message est honnête.",
    "SENDER_ACTIVITY_UNVERIFIED": "Je n'ai pas pu comparer le contenu avec une activité vérifiable de l'expéditeur.",
    "CORRELATION_UNVERIFIED_IDENTITY_DESTINATION": "Je n'ai pas établi qui se présente derrière cet expéditeur, et son bouton ne mène pas à l'opération annoncée. Je te demande ton avis avant de donner suite.",
    "AUTH_DMARC_FAIL": "Le domaine affiché ne reconnaît pas cet envoi : quelqu’un prétend peut-être écrire en son nom, à moins que sa configuration soit mal réglée.",
    "AUTH_SPF_FAIL": "Le serveur qui a envoyé ce message n’est pas autorisé par le domaine affiché.",
    "AUTH_SPF_SOFTFAIL": "Le domaine affiché n’autorise qu’à moitié le serveur d’envoi.",
    "AUTH_DKIM_INCONCLUSIVE": "Rien ne prouve que le message n’a pas été modifié en chemin.",
    "AUTH_NO_TRUSTED_RESULTS": "Je n’ai pas pu vérifier l’identité de l’expéditeur.",
    # « L'expéditeur est bien celui qu'il annonce » se lisait comme une
    # légitimité. DMARC prouve que le domaine affiché a écrit, rien de plus :
    # on peut être le bon domaine sans être qui l'on prétend.
    "AUTH_DMARC_PASS": "L’adresse d’envoi est authentique : le domaine affiché a bien écrit ce message. Reste à savoir qui est derrière ce domaine.",
    # « Non modifié » disait vrai du texte, et laissait croire à l'authenticité
    # de l'expéditeur : une signature valide peut appartenir à n'importe quel
    # hébergeur d'envoi. La phrase dit maintenant ce qu'elle prouve.
    "AUTH_DKIM_PASS": "Le domaine affiché a bien signé ce message, qui n’a pas été modifié en chemin.",
    "AUTH_DKIM_FAIL": "La signature du message est invalide.",
    "AUTH_DKIM_UNALIGNED": "Le message est signé par une autre organisation que celle qu’il affiche.",
    "AUTH_SPF_INCONCLUSIVE": "Le domaine affiché ne dit pas quels serveurs ont le droit d’envoyer en son nom.",
    "AUTH_DMARC_INCONCLUSIVE": "Le domaine affiché ne publie aucune règle permettant de vérifier son identité.",
    # Plus émis depuis la suppression du référentiel de marques (27 août
    # 2026), mais encore relu par la conversation et le récapitulatif tant
    # que la rétention garde ses dossiers : à retirer après le 2027-02-23.
    "IDENTITY_BRAND_MISMATCH": "Le nom affiché est celui d’une marque connue, mais le message vient d’ailleurs.",
    "IDENTITY_CLAIMED_ORGANISATION_UNRELATED": "Le message se présente au nom d’une organisation, depuis un domaine qui n’est pas le sien.",
    "IDENTITY_CLAIMED_ORGANISATION_REFUTED": "Le message se présente au nom d’une organisation dont les sites officiels, vérifiés à l’instant, ne comprennent pas le domaine qui a écrit.",
    # La référence est un domaine que la recherche a établi officiel, pas
    # forcément une marque ; et « rn » pour « m » change deux caractères.
    "IDENTITY_COUSIN_DOMAIN": "L’adresse d’envoi imite le domaine officiel d’une organisation : des caractères sosies y remplacent les vrais (un 1 pour un l, un zéro pour un o).",
    "IDENTITY_ASCII_LOOKALIKE": "L’adresse utilise des caractères qui se ressemblent à l’œil (un zéro pour un o, un 1 pour un l).",
    "IDENTITY_DISPLAY_NAME_DISGUISED": "Le nom affiché imite l’organisation que le message annonce, avec des lettres sosies (un l pour un I, un zéro pour un o).",
    "HEADERS_RECIPIENT_NOT_ADDRESSED": "Ton adresse n’apparaît pas dans le message : tu es en copie cachée.",
    "NATURE_MESSAGE_LANGUAGE": "Voici la langue dans laquelle ce message est écrit.",
    "CONTENT_ACTIVE_HTML": "Le message embarque un script ou un formulaire, comme une page web. Ta messagerie ne les exécute pas, mais un courrier ordinaire n’en contient pas.",
    "RSPAMD_PHISHING_HEURISTIC": "Le filtre antispam reconnaît une tournure habituelle des tentatives d’hameçonnage.",
    "CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC": "Le filtre antispam soupçonne un hameçonnage, et rien n’authentifie l’expéditeur.",
    "URL_STATIC_RISK": "Un lien du message présente une construction inhabituelle.",
    "URL_UNAUTHENTICATED_CROSS_APEX": "Un expéditeur non vérifié te renvoie vers un site qui ne lui appartient pas.",
    "CORRELATION_BRAND_SPOOFING": "Ce message se présente sous le nom d’une marque connue, depuis un expéditeur que rien n’authentifie.",
    "CORRELATION_CREDENTIAL_HARVESTING": "Ce message mène à un formulaire qui réclame tes identifiants, sur un site qui n’est pas le sien.",
    "CORRELATION_UNSOLICITED_BULK": "Ce message est une publicité envoyée en masse, que tu n’as pas demandée.",
    "ATTACHMENT_MACRO_SHELL": "Un fichier joint contient une macro qui peut lancer des commandes sur ton ordinateur.",
    "ATTACHMENT_MACRO_AUTO": "Un document joint contient une macro programmée pour se lancer à l’ouverture, si les macros sont autorisées.",
    "ATTACHMENT_ACTIVE_DOCUMENT": "Un document joint mentionne du code actif ou une action de lancement, sans preuve qu’il en contienne vraiment.",
    "ATTACHMENT_ENCRYPTED_ARCHIVE": "Un fichier joint est protégé par un mot de passe : personne n’a pu vérifier ce qu’il contient.",
    "ATTACHMENT_EXECUTABLE_MEMBER": "Un fichier joint contient un programme à exécuter.",
    "ATTACHMENT_COMPRESSION_ANOMALY": "Un fichier joint est compressé d’une façon anormale.",
    "ATTACHMENT_YARA_MATCH": "Un fichier joint ressemble à un logiciel malveillant connu.",
    "ATTACHMENT_IMAGE_TEXT": "Une image jointe contient du texte, que j’ai lu par reconnaissance de caractères.",
    "ATTACHMENT_EMBEDDED_URL": "Un fichier joint contient des liens vers Internet.",
    "ATTACHMENT_ANALYSIS_BLOCKED": "Je n’ai pas pu inspecter entièrement un fichier joint.",
    "CORRELATION_ANALYSIS_EVASION": "Ce message joint un fichier protégé par mot de passe, que personne n’a donc pu vérifier, et te presse de l’ouvrir.",
    "CORRELATION_MALICIOUS_ATTACHMENT": "Ce message joint un fichier capable d’exécuter du code, et t’invite à l’ouvrir.",
    "ACTION_PAYMENT_TRANSFER": "Ce message te demande de faire un virement ou un paiement.",
    "ACTION_BANK_DETAILS_CHANGE": "Ce message te demande de changer des coordonnées bancaires.",
    "ACTION_GIFT_CARD_PURCHASE": "Ce message te demande d’acheter des cartes cadeaux.",
    "ACTION_CREDENTIAL_ENTRY": "Ce message te demande de saisir ton identifiant ou ton mot de passe.",
    "ACTION_MFA_CODE_DISCLOSURE": "Ce message te demande de communiquer un code de sécurité reçu.",
    "ACTION_IDENTITY_DOCUMENT": "Ce message te demande d’envoyer une pièce d’identité.",
    "ACTION_FILE_EXECUTION": "Ce message te demande d’ouvrir ou de lancer un fichier.",
    "ACTION_SOFTWARE_INSTALL": "Ce message te demande d’installer un logiciel.",
    "ACTION_QR_CODE_SCAN": "Ce message te demande de scanner un code QR.",
    "ACTION_PHONE_CALLBACK": "Ce message te demande d’appeler un numéro.",
    "ACTION_PERSONAL_DATA": "Ce message te demande des informations personnelles.",
    "ACTION_PROCEDURE_BYPASS": "Ce message te demande de contourner la procédure habituelle.",
    "ACTION_CONFIDENTIALITY": "Ce message te demande de n’en parler à personne.",
    "ACTION_CLICK_LINK": "Ce message t’invite à cliquer sur un lien.",
    "ACTION_REPLY_MESSAGE": "Ce message attend une réponse de ta part.",
    "CORRELATION_FINANCIAL_FRAUD": "Ce message réclame de l’argent ou un changement bancaire, et son expéditeur n’est pas vérifié.",
    "SENDER_ACTIVITY_INCOHERENT": "Ce message parle de quelque chose qui n’a rien à voir avec ce que fait cet expéditeur.",
    "SENDER_ACTIVITY_COHERENT": "Ce message correspond bien à l’activité de cet expéditeur.",
    # Les trois constats neutres de l'enquêteur sender_relation : ne pas savoir
    # s'écrit, il n'accuse pas. Leur vocabulaire est celui de la doctrine du
    # faux reçu, c'est par lui que le juge la retrouve.
    "SENDER_WITHOUT_PUBLIC_FOOTPRINT": "Personne ne répond de ce domaine : pas de site lisible, rien dans la recherche, et le message ne se présente au nom d’aucune organisation connue. Ce n’est pas une preuve, c’est un vide.",
    "SENDER_RELATION_UNVERIFIED": "Je n’ai pas pu vérifier le rapport entre l’expéditeur et ce que dit le message.",
    "SENDER_RELATION_CONSISTENT": "Le nom que le message affiche et le domaine qui a écrit concordent. Cela dit qui a écrit, pas que le message est honnête.",
    "CONTENT_FINANCIAL_CONTEXT": "Ce message parle d’un paiement, d’un reçu, d’un abonnement ou de coordonnées bancaires.",
    "CORRELATION_FAKE_TRANSACTION_LURE": "Ce message annonce un paiement ou un abonnement depuis un expéditeur jamais vu dont personne ne répond : c’est le procédé du faux reçu, qui pousse à cliquer pour annuler.",
    # Plus émis depuis le 25 août 2026, relu comme IDENTITY_BRAND_MISMATCH
    # jusqu'à la purge de rétention : à retirer après le 2027-02-23.
    "SENDER_SITE_CLAIMS_FOREIGN_BRAND": "Le site de cet expéditeur se fait passer pour une marque qui n’est pas la sienne.",
    "URL_SAME_ORGANISATION_DESTINATION": "Le lien mène à un site appartenant à la même organisation que l’expéditeur.",
    "CORRELATION_COMPROMISED_SENDER": "L’adresse est authentifiée, mais le contenu paraît sans rapport avec l’activité publiée. Cela peut signaler un compte détourné, ou une mauvaise interprétation.",
    "CORRELATION_SPOOFED_UNRELATED_SENDER": "L’adresse n’est pas authentifiée, et le domaine qu’elle affiche exerce un tout autre métier que celui dont parle le message : quelqu’un écrit sous un nom qui n’est pas le sien.",
    "CORRELATION_BRAND_FIRST_CONTACT": "Une marque connue t’écrit pour la première fois, depuis une adresse qui n’est pas la sienne.",
    "CORRELATION_PREPARED_APPROACH": "Ce message vient d’un domaine récemment créé, dont les réponses partent ailleurs.",
    "CORRELATION_COUSIN_DOMAIN_APPROACH": "Ce message vient d’une adresse qui imite le domaine officiel d’une organisation, et ce domaine est récent ou renvoie tes réponses ailleurs.",
    "AUTH_SPF_PASS": "Le serveur d’envoi est autorisé par le domaine affiché.",
    "IDENTITY_ENVELOPE_VISIBLE_ALIGNED": "L’adresse visible et l’adresse technique concordent.",
    "IDENTITY_ENVELOPE_FROM_CROSS_APEX": "L’adresse technique d’envoi appartient à un autre domaine que l’adresse affichée.",
    "HEADERS_REPLY_TO_DIFFERENT_DOMAIN": "Une réponse partirait vers un autre domaine que l’expéditeur affiché.",
    "HEADERS_MULTIPLE_FROM": "Le message déclare plusieurs expéditeurs différents.",
    "CONTENT_SENSITIVE_REQUEST": "Le message demande une information sensible.",
    "CONTENT_URGENCY": "Le message cherche à te faire agir vite.",
    "CONTENT_OBFUSCATION": "Le texte contient des caractères invisibles ou un encodage inhabituel, un signe possible de dissimulation.",
    "CONTENT_SOCIAL_ENGINEERING_COMBINATION": "Le message combine urgence et demande sensible, comme une tentative de manipulation.",
    "CONTENT_NO_SENSITIVE_PRESSURE": "Je n’ai repéré ni demande sensible ni pression, mais je ne peux pas l’affirmer.",
    "CONTENT_EXTORTION": "Le message te menace ou réclame un versement pour ne pas nuire.",
    "CONTENT_ONE_TIME_CREDENTIAL_PROVIDED_NOT_REQUESTED": "Le message fournit un code de connexion sans te demander de le communiquer.",
    "URL_SANDBOX_FORM": "Un lien mène à un formulaire qui réclame des informations personnelles.",
    "URL_FAKE_HUMAN_VERIFICATION": "Un lien mène à une page qui imite une vérification « vérifiez que vous êtes humain », sans rien d’autre derrière ce décor.",
    "URL_OPAQUE_LANDING": "Le lien d’action mène à une page vide pour qui n’exécute pas ses scripts : je n’ai rien pu lire de la destination.",
    "CORRELATION_BRAND_TRANSACTION_LURE": "Ce message te facture un paiement ou un abonnement au nom d’une marque connue, mais il vient d’un expéditeur qui n’est pas cette marque et qui t’écrit pour la première fois : c’est le procédé de la fausse facture.",
    "CORRELATION_OPAQUE_TRANSACTION_LURE": "Un paiement ou un abonnement annoncé par un expéditeur jamais vu, et un lien d’action qui mène à une page vide sans script : cela ressemble au montage du faux reçu, qui pousse à cliquer pour « annuler ».",
    "URL_AMBIENT_SENSITIVE_FORM": "La page visée contient un formulaire sensible, sans que le message le demande.",
    "URL_SANDBOX_CROSS_APEX": "Un bouton conduit vers un site qui n’appartient pas à l’expéditeur.",
    "URL_CROSS_APEX": "Le message renvoie vers des sites extérieurs à l’expéditeur.",
    "URL_DECEPTIVE_LINK_TEXT": "Un lien affiche une destination différente de celle où il mène vraiment.",
    "URL_SANDBOX_INCOMPLETE": "Je n’ai pas pu ouvrir tous les liens pour les vérifier.",
    "URL_PROTECTED_ACTION_NOT_VISITED": "Un lien à usage unique n’a pas été ouvert, pour ne pas le consommer à ta place.",
    "URL_GENERIC_FORM": "La page visée propose un formulaire ordinaire, sans donnée sensible.",
    "URL_AUTHENTICATED_TRACKING_CONVERGENCE": "Les liens de suivi mènent bien au site de l’expéditeur.",
    "ATTACHMENT_EXECUTABLE": "Une pièce jointe peut exécuter du code sur ton appareil.",
    "ATTACHMENT_DOUBLE_EXTENSION": "Une pièce jointe déguise son type réel.",
    "ATTACHMENT_MACRO": "Un document joint contient des macros.",
    "ATTACHMENT_SANDBOX_INCOMPLETE": "Je n’ai pas pu inspecter toutes les pièces jointes.",
    "NATURE_BULK_MAILING": "C’est un envoi de masse, comme une lettre d’information.",
    "NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS": "Le message promet des résultats invérifiables.",
    "NATURE_SOLICITATION_WITHOUT_OPT_OUT": "Cette sollicitation n’offre aucun moyen de se désinscrire.",
    "HISTORY_FIRST_OBSERVATION": "C’est la première fois que cet expéditeur t’écrit.",
    # Au moins trois messages qualifiés légitimes, aucun défavorable.
    "HISTORY_CONFIRMED_LEGITIMATE_SENDER": "Tu as déjà confirmé plusieurs messages de cet expéditeur, sans jamais en signaler un comme indésirable.",
    "HISTORY_CONFIRMED_MAIL_PROFILE": "Tu as déjà validé ce type de courrier de la même identité vérifiée.",
    # Heure, taille ou pays inhabituels, sur dix messages d'historique au moins.
    "HISTORY_BEHAVIOR_DEVIATION": "L’heure, la taille ou le pays d’envoi de ce message s’écarte des habitudes de cet expéditeur.",
    "SENDER_DOMAIN_RECENT": "Le domaine de l’expéditeur a été créé récemment.",
    "SENDER_DOMAIN_ESTABLISHED": "Le domaine de l’expéditeur existe depuis des années.",
    "RSPAMD_MATERIAL_SYMBOL": "Le filtre antispam relève un signal défavorable précis.",
    "RSPAMD_OBFUSCATION_SYMBOL": "L’objet ou l’expéditeur du message est encodé de façon inhabituelle, un procédé qui sert souvent à tromper les filtres.",
    "RSPAMD_HIGH_SCORE": "Le filtre antispam trouve ce message très inhabituel.",
    "RSPAMD_LOW_SCORE": "Le filtre antispam ne relève rien d’inhabituel.",
    "RSPAMD_NO_REPUTATION_HIT": "Aucune liste de mauvaise réputation ne signale ce message.",
    "RSPAMD_RESULT_MISSING": "Le filtre antispam n’a pas rendu de résultat.",
    "EVIDENCE_INCOMPLETE": "Une partie de mes vérifications n’a pas abouti.",
    "STRUCT_PARSEABLE": "Le message est correctement formé.",
    "STRUCT_MESSAGE_ID_PRESENT": "Le message porte un identifiant normal.",
    "DATE_PARSEABLE": "La date d’envoi est cohérente.",
    "DATE_MISSING_OR_INVALID": "La date d’envoi est absente ou incohérente.",
    "CORRELATION_TRANSACTIONAL_COHERENCE": "C’est une notification liée à une action que tu as toi-même déclenchée (confirmation, reçu, code), envoyée par un expéditeur vérifié et établi.",
    "HISTORY_APEX_ESTABLISHED_LOCALLY": "C’est une nouvelle adresse, mais son domaine t’a déjà écrit plusieurs fois sans jamais poser problème.",
    "HISTORY_RECIPIENT_USUAL_LANGUAGE": "Le message est écrit dans la langue que tu reçois d’habitude.",
    "CORRELATION_AUTHENTICATED_RFC8058_UNSUBSCRIBE": "Le message propose une désinscription en un clic sur le domaine de l’expéditeur, et cet expéditeur est authentifié.",
}
# Ces indices décrivent le fonctionnement de l'analyse, pas le message : ils
# n'ont rien à faire dans un avis adressé à un humain.
_OPERATIONAL = {
    "STRUCT_PARSEABLE",
    "STRUCT_MESSAGE_ID_PRESENT",
    "DATE_PARSEABLE",
    "RSPAMD_TRANSACTIONAL_ENVELOPE_VARIATION",
    "IDENTITY_MESSAGE_ID_CROSS_APEX",
    # Alignement syntaxique seul, sans authentification : un From usurpé
    # l'obtient aussi facilement qu'un expéditeur réel. Seule la corrélation
    # CORRELATION_AUTHENTICATED_RFC8058_UNSUBSCRIBE, qui exige en plus une
    # authentification vérifiée, doit atteindre un humain.
    "HEADERS_RFC8058_STRUCTURE",
}
# Seuls ces indices disent qu'une vérification n'a pas abouti. Les autres faits
# neutres décrivent un contexte : les présenter comme des limites laisserait
# croire à une défaillance, ou pire, à un danger que l'on n'aurait pas su voir.
_INCOMPLETENESS = {
    "URL_SANDBOX_INCOMPLETE",
    "ATTACHMENT_SANDBOX_INCOMPLETE",
    "EVIDENCE_INCOMPLETE",
    "AUTH_NO_TRUSTED_RESULTS",
    "RSPAMD_RESULT_MISSING",
    "URL_PROTECTED_ACTION_NOT_VISITED",
}
_CODE_REFERENCE = re.compile(r"\b[A-Z][A-Z0-9]*(?:[-_.][A-Z0-9_]+)+\b")
_SCORE = re.compile(
    # « 72/100 », mais aussi « score=42 » ou « confidence = 0.8 » : un
    # chiffrage interne n'apprend rien à qui lit, et donne à une mesure
    # d'étape l'autorité d'un résultat.
    r"\b\d{1,3}\s*/\s*100\b"
    r"|\b[a-zA-Zà-öø-ÿ_]{3,}\s*=\s*-?\d+(?:[.,]\d+)?\b"
    # « (force 55) » : la pondération d'un indice, que le modèle recopie
    # volontiers dans sa motivation. Elle situe une pièce dans le barème
    # interne et ne dit rien à qui lit son courrier.
    r"|\(?\bforces?\s+\d{1,3}\)?"
)


# Une explication tient en une phrase ou deux ; au-delà, elle raconte le
# dossier et non le grief, et l'avis n'a pas cette place.
EXPLICATION_MAX = 220


def _explication(facts: object) -> str:
    """Ce que le juge a réellement constaté, quand il l'a écrit.

    Deux contrôles interrogent un modèle sur une question précise - l'activité
    de l'expéditeur, l'identité revendiquée - et rangent sa réponse dans les
    faits de l'indice. La colonne porte tantôt ces faits, tantôt le dossier
    entier de l'indice qui les contient, et tantôt du texte JSON : les trois
    formes se lisent ici, parce qu'aucune ne dit autre chose.
    """
    if isinstance(facts, str):
        try:
            facts = json.loads(facts)
        except ValueError:
            return ""
    if not isinstance(facts, dict):
        return ""
    valeur = facts.get("explication")
    if not valeur and isinstance(facts.get("facts"), dict):
        valeur = facts["facts"].get("explication")
    texte = _SCORE.sub("", _CODE_REFERENCE.sub("", str(valeur or ""))).strip()
    texte = re.sub(r"\(\s*[,;\s]*\)", "", texte)
    texte = re.sub(r"\s{2,}", " ", texte).strip(" .:;-")
    if not texte:
        return ""
    return f"{texte[:EXPLICATION_MAX].strip()}."


# Quelques marques s'écrivent autrement que leur clé : les nommer comme leur
# propriétaire les écrit évite un « Paypal » à la place de « PayPal ».
_BRAND_LABELS = {
    "paypal": "PayPal",
    "linkedin": "LinkedIn",
    "youtube": "YouTube",
    "tiktok": "TikTok",
    "playstation": "PlayStation",
    "wetransfer": "WeTransfer",
    "docusign": "DocuSign",
    "aliexpress": "AliExpress",
    "primevideo": "Prime Video",
    "creditagricole": "Crédit Agricole",
    "labanquepostale": "La Banque Postale",
    "caissedepargne": "Caisse d’Épargne",
    "banquepopulaire": "Banque Populaire",
    "creditmutuel": "Crédit Mutuel",
    "societegenerale": "Société Générale",
    "bnpparibas": "BNP Paribas",
    "bouyguestelecom": "Bouygues Telecom",
    "francetravail": "France Travail",
    "disneyplus": "Disney+",
    "paramountplus": "Paramount+",
    "canalplus": "Canal+",
}


def _as_dict(facts: object) -> dict:
    if isinstance(facts, str):
        try:
            facts = json.loads(facts)
        except ValueError:
            return {}
    if not isinstance(facts, dict):
        return {}
    interne = facts.get("facts")
    return dict(interne) if isinstance(interne, dict) else dict(facts)


def _nom_de_marque(valeur: object) -> str:
    marque = str(valeur or "").strip()
    return _BRAND_LABELS.get(marque.casefold(), marque.capitalize())


def _domaines(facts: dict, limite: int = 2) -> str:
    apexes = [str(value) for value in facts.get("official_apexes") or []][:limite]
    return " ou ".join(apexes)


def _dit_la_marque(facts: dict) -> str:
    """Quelle marque, envoyée d'où, alors qu'on l'attendait d'où."""
    marque = _nom_de_marque(facts.get("brand"))
    domaine = str(facts.get("from_apex") or "").strip()
    if not marque or not domaine:
        return ""
    officiels = _domaines(facts)
    phrase = f"Le nom annonce {marque}, mais le message a été envoyé depuis {domaine}"
    return phrase + (f", alors que {marque} écrit depuis {officiels}." if officiels else ".")


def _dit_le_deguisement(facts: dict) -> str:
    """Le nom tel qu'il est écrit, ce qu'on y lit, et qui il imite."""
    nom = str(facts.get("display_name") or "").strip()
    imite = str(facts.get("imite") or "").strip()
    organisation = str(facts.get("claimed_organisation") or "").strip()
    if not nom or not imite or not organisation:
        return ""
    return (
        f"Le nom affiché « {nom} » se lit « {imite} », comme {organisation} "
        "que le message annonce, mais il ne l’écrit pas : des lettres sosies "
        "y remplacent les vraies."
    )


def _dit_le_domaine_sosie(facts: dict) -> str:
    """Les deux domaines, celui qui écrit et celui qu'il imite.

    Le message peut ne rien annoncer : « Le nom annonce » dirait un nom qu'il
    n'a pas écrit. L'organisation n'est citée que pour dire à qui appartient
    le domaine imité, selon la recherche.
    """
    domaine = str(facts.get("from_domain") or facts.get("from_apex") or "").strip()
    imite = str(facts.get("imite") or "").strip()
    organisation = str(facts.get("imitated_organisation") or "").strip()
    if not domaine or not imite:
        return ""
    phrase = f"L’adresse d’envoi {domaine} se lit comme {imite}"
    if organisation:
        phrase += f", domaine de {organisation}"
    return phrase + ", mais ne l’écrit pas : des caractères sosies y remplacent les vrais."


def _dit_l_adresse_authentique(facts: dict) -> str:
    """Ce que l'authentification prouve, et la question qu'elle laisse ouverte.

    Le domaine a bien écrit ; reste à savoir s'il est bien l'organisation que
    le nom affiche. Quand le nom reprend le domaine, la question ne se pose
    pas en ces termes et l'on demande seulement qui est derrière.
    """
    from sentimail_v3.code.identity_relation import obvious_relation

    domaine = str(facts.get("from_apex") or "").strip()
    if not domaine:
        return ""
    organisation = str(facts.get("claimed_organisation") or "").strip()
    debut = f"L’adresse d’envoi est authentique : {domaine} a bien écrit ce message."
    if organisation and not obvious_relation(organisation, domaine):
        return f"{debut} Reste à savoir si {domaine} est bien {organisation}."
    return f"{debut} Reste à savoir qui est derrière {domaine}."


def _dit_l_organisation(facts: dict) -> str:
    """L'organisation revendiquée, d'où vient le message, et d'où elle écrit.

    Même tournure que pour une marque imitée : « le nom annonce X, mais le
    message a été envoyé depuis Y, alors que X écrit depuis Z ». Un lecteur
    qui ne sait pas ce qu'est un domaine lit tout de même que Y n'est pas Z.
    """
    organisation = str(facts.get("claimed_organisation") or "").strip()
    domaine = str(facts.get("from_apex") or "").strip()
    if not organisation or not domaine:
        return ""
    officiels = _domaines(facts)
    phrase = f"Le nom annonce {organisation}, mais le message a été envoyé depuis {domaine}"
    return phrase + (
        f", alors que {organisation} écrit depuis {officiels}." if officiels else "."
    )


def _dit_l_identite_invérifiable(facts: dict) -> str:
    """Ce qu'une authentification muette veut dire, en une phrase pour les trois.

    DMARC, SPF et DKIM en temperror donnaient trois lignes qui disaient la
    même chose avec des mots faux : « ne publie aucune règle » pour un DNS qui
    ne répond pas. Une seule phrase, la même pour les trois contrôles, que la
    liste ne répète pas.
    """
    domaine = str(facts.get("from_apex") or "").strip()
    if not domaine:
        return ""
    resultat = str(facts.get("result") or "").strip().casefold()
    if resultat in {"temperror", "permerror"}:
        return (
            f"Je n’ai pas pu vérifier que ce message vient bien de {domaine} : "
            "son domaine ne répond pas aux contrôles d’identité."
        )
    return (
        f"Rien ne permet de vérifier que ce message vient bien de {domaine} : "
        "son domaine ne publie pas ce qu’il faut pour cela."
    )


# Les indices qui disent qui se présente et qui écrit réellement, du plus sûr
# au moins sûr. Le premier trouvé fait la carte.
_IDENTITY_CARD_CODES = (
    "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
    "IDENTITY_BRAND_MISMATCH",
    "IDENTITY_COUSIN_DOMAIN",
    "IDENTITY_ASCII_LOOKALIKE",
    "CORRELATION_BRAND_SPOOFING",
    "IDENTITY_CLAIMED_ORGANISATION_UNRELATED",
)


def identity_card(rows: list[dict[str, object]]) -> dict[str, object] | None:
    """Qui se présente, d'où le message est parti, d'où l'organisation écrit.

    Trois lignes valent mieux qu'une phrase pour qui ne lit pas les adresses :
    le nom annoncé, le domaine qui a réellement écrit, et celui qu'on
    attendait. Rien n'est inventé : la carte ne se fait que sur un indice
    d'identité observé, avec ses faits. Sans indice, pas de carte.
    """
    for code in _IDENTITY_CARD_CODES:
        for row in rows:
            if str(row.get("clue_code") or "") != code:
                continue
            facts = _as_dict(row.get("facts"))
            nom = str(facts.get("claimed_organisation") or "").strip()
            if not nom and facts.get("brand"):
                nom = _nom_de_marque(facts.get("brand"))
            apex = str(facts.get("from_apex") or "").strip()
            if not nom or not apex:
                continue
            domaine = str(facts.get("from_domain") or "").strip() or apex
            return {
                "claimed": nom,
                "from_domain": domaine,
                "from_apex": apex,
                "official": [str(value) for value in facts.get("official_apexes") or []][:2],
            }
    return None


def identity_lines(card: object) -> list[str]:
    """La carte en trois lignes de texte, pour l'avis sans mise en forme.

    Une carte relue depuis la base peut être incomplète, et ce texte sert
    jusque dans le dernier repli de la livraison, où lever une erreur ferait
    perdre plus qu'une ligne. Sans nom ou sans domaine, il n'y a rien à écrire.
    """
    if not isinstance(card, dict):
        return []
    nom = str(card.get("claimed") or "").strip()
    domaine = str(card.get("from_domain") or card.get("from_apex") or "").strip()
    if not nom or not domaine:
        return []
    lignes = [f"Se présente comme : {nom}", f"Écrit depuis : {domaine}"]
    officiels = [str(value) for value in card.get("official") or []]
    if officiels:
        lignes.append(f"{nom} écrit depuis : {' ou '.join(officiels)}")
    return lignes


def sender_addresses(
    from_header: object, envelope_from: object, reply_to: object = None
) -> list[str]:
    """L'adresse que l'expéditeur affiche, et celle qu'il a réellement annoncée.

    Le « De : » d'un message est déclaratif : son nom et son adresse s'écrivent
    librement. L'adresse d'enveloppe est celle que le serveur d'envoi a donnée
    pour lui-même, et l'adresse de réponse celle où ira une réponse. Les mettre
    côte à côte est ce qui rend l'écart visible sans rien y connaître : un avis
    qui ne recopie que le « De : » redit ce que l'expéditeur dit de lui-même.

    L'enveloppe est toujours dite, même identique - son absence de la ligne
    ferait croire qu'on ne l'a pas regardée. L'adresse de réponse ne paraît que
    lorsqu'elle diffère, sinon elle n'apprend rien.
    """
    displayed = parseaddr(str(from_header or ""))[1]
    envelope = parseaddr(str(envelope_from or ""))[1]
    answer = parseaddr(str(reply_to or ""))[1]
    lignes = []
    differente = bool(displayed) and bool(envelope) and (
        envelope.casefold() != displayed.casefold()
    )
    libelle = "Adresse d’enveloppe différente" if differente else "Adresse d’enveloppe"
    lignes.append(f"{libelle} : {envelope or '(non disponible)'}")
    if displayed and answer and answer.casefold() != displayed.casefold():
        lignes.append(f"Adresse de réponse différente : {answer}")
    return lignes


def sender_lines(
    from_header: object, envelope_from: object, reply_to: object = None
) -> list[str]:
    """Ce que l'expéditeur affiche, puis ce que son serveur a annoncé.

    Les avis unitaires (douteux, indésirable) posent les deux adresses l'une
    sous l'autre : l'affichée se recopie librement, l'enveloppe non. Le nom
    affiché passe devant, parce que c'est lui que l'œil lit dans la boîte.
    """
    nom, affichee = parseaddr(str(from_header or ""))
    lignes = [f"Nom affiché : {nom}"] if nom.strip() else []
    lignes.append(f"Adresse affichée : {affichee or '(non disponible)'}")
    return lignes + sender_addresses(from_header, envelope_from, reply_to)


def gap_lines(card: object, gap: object) -> list[str]:
    """L'écart entre l'annoncé et le réel, en lignes de texte brut.

    Le même contenu et le même vocabulaire que l'encart de l'avis : lire la
    version texte et la version mise en forme ne doit pas demander de traduire
    « se présente comme » en « annoncé ».
    """
    lignes: list[str] = []
    if isinstance(card, dict) and card.get("claimed") and card.get("from_apex"):
        lignes.append(f"Annoncé : {card['claimed']}")
        lignes.append(
            f"Écrit depuis : {card.get('from_domain') or card['from_apex']}"
        )
        officiels = [str(value) for value in card.get("official") or []]
        if officiels:
            lignes.append(f"{card['claimed']} écrit depuis : {' ou '.join(officiels)}")
    if isinstance(gap, dict) and gap.get("displayed"):
        lignes.append(f"Affiché : {gap['displayed']}")
        if gap.get("real"):
            lignes.append(f"Réel : {gap['real']}")
        if gap.get("reply_to"):
            lignes.append(f"Réponse : {gap['reply_to']}")
    return lignes


def sender_gap(
    from_header: object, envelope_from: object, reply_to: object = None
) -> dict[str, str | None] | None:
    """L'écart entre l'adresse que l'expéditeur affiche et celle qu'il a donnée.

    Le « De : » d'un message est déclaratif ; l'adresse d'enveloppe est celle
    que le serveur d'envoi a annoncée pour lui-même, et l'adresse de réponse
    celle où partira une réponse. Quand elles coïncident, les répéter n'apprend
    rien : la carte ne se fait que sur un écart réel, et c'est la comparaison
    des deux lignes - pas une phrase - qui montre l'usurpation.
    """
    displayed = parseaddr(str(from_header or ""))[1]
    envelope = parseaddr(str(envelope_from or ""))[1]
    answer = parseaddr(str(reply_to or ""))[1]
    if not displayed:
        return None
    reel = envelope if envelope and envelope.casefold() != displayed.casefold() else None
    reponse = answer if answer and answer.casefold() != displayed.casefold() else None
    if not reel and not reponse:
        return None
    return {"displayed": displayed, "real": reel, "reply_to": reponse}


# Trois niveaux, pas un score : un chiffre invite à négocier le chiffre, là où
# un mot et une couleur se lisent d'un coup d'œil, sur un téléphone, sans rien
# connaître au sujet.
_NIVEAUX = {
    "danger": ("DANGEREUX", "#b91c1c"),
    "doute": ("DOUTEUX", "#b45309"),
    "sain": ("SAIN", "#15803d"),
}


def confidence_badge(classification: object, gaps: int = 0) -> dict[str, str]:
    """L'indice de confiance : un niveau, un mot, une couleur, une icône.

    Il remplace la motivation recopiée, la technique nommée et la liste des
    vérifications inabouties : trois blocs qui disaient à trois endroits ce
    qu'un lecteur voulait savoir en une ligne - dois-je m'en méfier.
    """
    verdict = str(classification or "").strip().casefold()
    if verdict == "dangerous":
        level = "danger"
    elif verdict == "legitimate":
        level = "sain"
    else:
        level = "doute"
    word, color = _NIVEAUX[level]
    count = max(int(gaps or 0), 0)
    if not count:
        detail = "aucun écart relevé"
    else:
        detail = f"{count} écart{'s' if count > 1 else ''} relevé{'s' if count > 1 else ''}"
    return {
        "level": level,
        "word": word,
        "color": color,
        "detail": detail,
        "cid": f"sm-indice-{level}",
    }


def _dit_les_identites(facts: dict) -> str:
    """Les adresses constatées, sans inventer une identité usurpée."""
    identity = facts.get("identity")
    identity = identity if isinstance(identity, dict) else {}
    claimed_name = str(identity.get("claimed_name") or "").strip()
    displayed = str(identity.get("displayed_email") or "").strip()
    technical = str(identity.get("technical_email") or "").strip()
    reply_to = str(identity.get("reply_to_email") or "").strip()
    parts = []
    if claimed_name:
        parts.append(f"identité annoncée : {claimed_name}")
    if displayed:
        parts.append(f"adresse affichée : {displayed}")
    if technical:
        parts.append(f"adresse technique : {technical}")
    if reply_to and reply_to.casefold() not in {
        displayed.casefold(),
        technical.casefold(),
    }:
        parts.append(f"adresse de réponse : {reply_to}")
    return ("Identités constatées : " + " ; ".join(parts) + ".") if parts else ""


def _extrait(value: object, limite: int) -> str:
    texte = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(texte) <= limite:
        return texte
    return texte[: limite - 1].rstrip(" ,;:-") + "…"


def _dit_l_activite_comparee(facts: dict) -> str:
    """Qui écrit, quel métier il publie et quel propos est comparé."""
    activity = facts.get("activity")
    activity = activity if isinstance(activity, dict) else facts
    identity = facts.get("identity")
    identity = identity if isinstance(identity, dict) else {}
    name = str(
        activity.get("claimed_name") or identity.get("claimed_name") or ""
    ).strip()
    address = str(identity.get("displayed_email") or "").strip()
    apex = str(activity.get("sender_apex") or "").strip()
    published = _extrait(activity.get("published_activity"), 180)
    subject = _extrait(activity.get("message_subject"), 140)
    actor = name or address or apex
    if actor and address and address.casefold() != actor.casefold():
        actor += f" ({address})"
    parts = []
    if published:
        source = f" sur {apex}" if apex else ""
        owner = f" par {actor}" if actor else ""
        parts.append(f"Activité publiée{owner}{source} : « {published} ».")
    elif actor and not identity:
        parts.append(f"Expéditeur observé : {actor}.")
    if subject:
        parts.append(f"Objet comparé : « {subject} ».")
    identities = _dit_les_identites(facts)
    if identities:
        parts.append(identities)
    return " ".join(parts)


# Ce qu'un grief doit dire en plus de lui-même, article par article. La phrase
# toute faite nomme le grief ; celle-ci le rend vérifiable par le lecteur, qui
# n'a plus à croire sur parole que le domaine n'est pas le bon.
_PRECISIONS = {
    "AUTH_DMARC_PASS": _dit_l_adresse_authentique,
    "IDENTITY_BRAND_MISMATCH": _dit_la_marque,
    "IDENTITY_COUSIN_DOMAIN": _dit_le_domaine_sosie,
    "IDENTITY_ASCII_LOOKALIKE": _dit_la_marque,
    "IDENTITY_DISPLAY_NAME_DISGUISED": _dit_le_deguisement,
    "IDENTITY_CLAIMED_ORGANISATION_REFUTED": _dit_l_organisation,
    "IDENTITY_CLAIMED_ORGANISATION_UNRELATED": _dit_l_organisation,
    "AUTH_DMARC_INCONCLUSIVE": _dit_l_identite_invérifiable,
    "AUTH_SPF_INCONCLUSIVE": _dit_l_identite_invérifiable,
    "AUTH_DKIM_INCONCLUSIVE": _dit_l_identite_invérifiable,
    "SENDER_ACTIVITY_INCOHERENT": _dit_l_activite_comparee,
    "SENDER_ACTIVITY_COHERENT": _dit_l_activite_comparee,
    "CORRELATION_COMPROMISED_SENDER": _dit_l_activite_comparee,
    "CORRELATION_SPOOFED_UNRELATED_SENDER": _dit_l_activite_comparee,
}


# Ces précisions-là disent le grief en même temps que son fondement : les faire
# suivre la phrase toute faite reviendrait à écrire deux fois la même chose, la
# seconde en mieux. Elles la remplacent donc.
_AUTONOMES = frozenset(
    {
        "AUTH_DMARC_PASS",
        "IDENTITY_BRAND_MISMATCH",
        "IDENTITY_COUSIN_DOMAIN",
        "IDENTITY_ASCII_LOOKALIKE",
        "IDENTITY_DISPLAY_NAME_DISGUISED",
        "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
        "IDENTITY_CLAIMED_ORGANISATION_UNRELATED",
        "AUTH_DMARC_INCONCLUSIVE",
        "AUTH_SPF_INCONCLUSIVE",
        "AUTH_DKIM_INCONCLUSIVE",
    }
)


def _precision(clue_code: str, facts: object) -> str:
    redacteur = _PRECISIONS.get(clue_code)
    return redacteur(_as_dict(facts)) if redacteur else ""


def _redit(explication: str, connue: str) -> bool:
    """L'explication ne fait-elle que reformuler le grief déjà écrit ?

    Un modèle qui répond « ce message n'a rien à voir avec l'activité de cet
    expéditeur » ne dit rien de plus que la phrase toute faite : l'ajouter
    donnerait la même phrase deux fois, ce qui se lit comme une insistance
    plutôt que comme une raison.
    """
    mots = _mots(explication)
    if not mots:
        return True
    return len(mots & _mots(connue)) / len(mots) >= _REDITE


def plain_clue(
    clue_code: str, statement: str, facts: object = None
) -> str | None:
    """Phrase lisible pour un indice, ou None s'il ne concerne pas l'humain.

    La phrase toute faite dit le grief ; elle ne dit pas sur quoi il repose.
    « Ce message parle de quelque chose qui n'a rien à voir avec ce que fait
    cet expéditeur » laissait un lecteur sans recours : le motif réel - le site
    lu était une page anti-robot, pas celui de l'expéditeur - existait dans
    l'indice et restait en base. Un grief sans son motif ne s'explique pas, il
    s'impose.
    """
    if clue_code in _OPERATIONAL:
        return None
    if _as_dict(facts).get("text_scope") == "quoted_or_combined":
        known = _PLAIN.get(clue_code) or statement
        return "Dans le texte cité ou mêlé à la réponse : " + known[:1].lower() + known[1:]
    known = _PLAIN.get(clue_code)
    if known:
        precision = _precision(clue_code, facts)
        morceaux = [precision] if precision and clue_code in _AUTONOMES else [known]
        if precision and clue_code not in _AUTONOMES:
            morceaux.append(precision)
        explication = _explication(facts)
        if explication and not _redit(explication, " ".join(morceaux)):
            morceaux.append(explication)
        return " ".join(morceaux)
    # Repli : l'énoncé du Code, débarrassé de ses références internes.
    fallback = _SCORE.sub("", _CODE_REFERENCE.sub("", statement)).strip(" .:;-")
    return f"{fallback}." if fallback else None


# Le modèle raisonne avec le vocabulaire du Code et le recopie parfois dans sa
# motivation : « deep_execution_complete=false », « impose undetermined et
# ask_user ». Ces phrases décrivent la procédure interne, pas le message : elles
# ne sont pas adressées au destinataire, et les traduire mot à mot donne une
# phrase bancale. On retire donc la phrase entière, en gardant celles qui
# décrivent réellement le courrier reçu.
_INTERNAL_FLAG = re.compile(r"\(?\b[a-z][a-z0-9_]{6,}\s*=\s*(?:true|false)\b\)?")
_PROCEDURAL = re.compile(
    r"\b(undetermined|ask_user|deliver|junk|delivery_decision|judgment_rules|"
    r"conform[ée]ment aux r[èe]gles|le code (?:impose|exige)|"
    r"les r[èe]gles (?:imposent|exigent))\b",
    re.IGNORECASE,
)


def _sentences(value: str) -> list[str]:
    """Découpe en phrases, sans confondre un point avec une fin de phrase.

    Un point qui n'est suivi de rien d'autre qu'une lettre appartient au mot :
    c'est celui de « chatgpt.com » ou de « 0.85 ». Couper là fabriquait deux
    phrases dont la seconde s'ouvrait sur « com est expliquée par le contexte
    de tracking » - et la conclusion, qui ne garde que la fin, présentait ce
    morceau de domaine comme s'il en était un.

    La fin d'une phrase se reconnaît à ce qui la suit : une espace, une fin de
    texte. Rien de plus n'est nécessaire ici, et un analyseur grammatical
    serait hors de proportion pour trancher entre « .com » et « . Le ».
    """
    parts: list[str] = []
    current: list[str] = []
    for index, char in enumerate(value):
        current.append(char)
        if char not in ".!?":
            continue
        suivant = value[index + 1 : index + 2]
        if char == "." and suivant and not suivant.isspace():
            continue
        parts.append("".join(current).strip())
        current = []
    if current and "".join(current).strip():
        parts.append("".join(current).strip())
    return parts


def plain_rationale(rationale: str | None) -> str:
    """Motivation du verdict final, sans les références de preuve citées."""
    if not rationale:
        return "Je préfère te demander avant de décider."
    cleaned = _INTERNAL_FLAG.sub("", rationale)
    kept = [
        sentence for sentence in _sentences(cleaned) if not _PROCEDURAL.search(sentence)
    ]
    cleaned = " ".join(kept) if kept else ""
    cleaned = _CODE_REFERENCE.sub("", _SCORE.sub("", cleaned))
    cleaned = re.sub(r"\(\s*[,;\s]*\)", "", cleaned)
    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()
    return cleaned or "Je préfère te demander avant de décider."


# Un mot de moins de quatre lettres ne distingue rien : « et », « les », « pour »
# se retrouvent dans toutes les phrases et feraient passer n'importe quel texte
# pour la redite de n'importe quel autre.
_MOT = re.compile(r"[a-zà-öø-ÿ0-9]{4,}")
# Au-delà, la phrase ne dit plus rien que la liste ne dise déjà.
_REDITE = 0.55


def _mots(value: str) -> set[str]:
    return set(_MOT.findall(value.casefold()))


def short_conclusion(
    rationale: str | None,
    *,
    listed: Sequence[str] = (),
    max_sentences: int = 1,
    max_chars: int = 300,
) -> str:
    """La conclusion, débarrassée de ce que l'avis a déjà dit au-dessus.

    Elle reprenait, phrase par phrase, les lignes de « ce qui me gêne » et
    « ce qui me rassure », puis concluait en dernière phrase. Lire deux fois la
    même chose n'apporte rien et enterre la seule ligne qui répond à « et
    donc ? ».

    Deux coupes, dans cet ordre. La première sur le vocabulaire : une phrase
    dont la plus grande part des mots figure déjà dans la liste au-dessus ne
    fait que la redire. Elle ne suffit pas seule - le modèle paraphrase, et
    « aucun texte exploitable » ne partage presque aucun mot avec « le message
    ne contient aucun texte ».

    La seconde est donc positionnelle : on ne garde que la fin. Une motivation
    expose puis conclut ; sa dernière phrase répond à « et donc ? », et c'est
    la seule que l'avis a besoin de porter. Une phrase trop brève pour se
    suffire en entraîne une seconde.

    Rien n'est réécrit ni résumé : on retire, on ne reformule pas. Le verdict
    complet reste intact dans le dossier ; seule la lettre est allégée.
    """
    complet = plain_rationale(rationale)
    phrases = _sentences(complet)
    if len(phrases) <= max_sentences and len(complet) <= max_chars:
        return complet
    deja = set().union(*(_mots(value) for value in listed)) if listed else set()
    gardees = []
    for phrase in phrases:
        mots = _mots(phrase)
        if mots and deja and len(mots & deja) / len(mots) >= _REDITE:
            continue
        gardees.append(phrase)
    # Tout couper laisserait un avis sans conclusion : la dernière phrase d'une
    # motivation porte presque toujours la décision.
    gardees = gardees or phrases[-1:]
    retenues = gardees[-max_sentences:]
    # « Je te demande. » ne dit pas pourquoi : trop courte pour se suffire.
    if len(" ".join(retenues)) < 60 and len(gardees) > len(retenues):
        retenues = gardees[-(max_sentences + 1):]
    while retenues and len(" ".join(retenues)) > max_chars and len(retenues) > 1:
        retenues = retenues[1:]
    return " ".join(retenues).strip()


# Les échecs que le hook d'authentification émet réellement : une signature
# d'un autre domaine (AUTH_DKIM_UNALIGNED) en fait partie, un contrôle muet
# à côté n'apprend rien de plus.
_AUTH_FAILED = {"AUTH_DMARC_FAIL", "AUTH_SPF_FAIL", "AUTH_DKIM_FAIL", "AUTH_DKIM_UNALIGNED"}
_AUTH_MUTE = {"AUTH_DMARC_INCONCLUSIVE", "AUTH_SPF_INCONCLUSIVE", "AUTH_DKIM_INCONCLUSIVE"}


def _sans_controles_muets(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Quand un contrôle a échoué, dire qu'un autre n'a pas répondu n'ajoute rien.

    « Le domaine ne le reconnaît pas » puis « rien ne permet de vérifier » se
    lisaient comme deux griefs, et presque comme une contradiction.
    """
    codes = {str(row.get("clue_code") or "") for row in rows}
    if not codes & _AUTH_FAILED:
        return rows
    return [row for row in rows if str(row.get("clue_code") or "") not in _AUTH_MUTE]


def plain_points(rows: list[dict[str, object]], limit: int) -> list[str]:
    """Retient les indices les plus parlants, sans répéter la même idée."""
    seen: set[str] = set()
    points: list[str] = []
    for row in _sans_controles_muets(rows):
        sentence = plain_clue(
            str(row.get("clue_code") or ""),
            str(row.get("statement") or ""),
            row.get("facts"),
        )
        if not sentence or sentence in seen:
            continue
        seen.add(sentence)
        points.append(sentence)
        if len(points) >= limit:
            break
    return points


# Le vocabulaire des avis : le grief, en une phrase qui se lit sans effort.
# Ces formules-là remplacent la phrase toute faite quand celle-ci dit la même
# chose en deux temps, ou quand plusieurs indices désignent un même reproche :
# le lecteur d'un avis n'a pas à distinguer trois constats qui l'inquiètent
# pour la même raison.
_SHORT = {
    "AUTH_DMARC_FAIL": "Usurpation possible : le domaine affiché ne reconnaît pas cet envoi.",
    "AUTH_SPF_SOFTFAIL": "Envoi depuis un serveur que le domaine affiché n’a pas déclaré.",
    "AUTH_SPF_FAIL": "Envoi depuis un serveur que le domaine affiché refuse.",
    "AUTH_DKIM_INCONCLUSIVE": "Identité de l’expéditeur non vérifiable.",
    "AUTH_DMARC_INCONCLUSIVE": "Identité de l’expéditeur non vérifiable.",
    "AUTH_SPF_INCONCLUSIVE": "Identité de l’expéditeur non vérifiable.",
    "IDENTITY_CLAIMED_ORGANISATION_REFUTED": "Usurpation possible : domaine étranger à l’organisation annoncée.",
    "IDENTITY_CLAIMED_ORGANISATION_UNRELATED": "Usurpation possible : domaine étranger à l’organisation annoncée.",
    "IDENTITY_BRAND_MISMATCH": "Usurpation possible : domaine étranger à l’organisation annoncée.",
    "CORRELATION_BRAND_SPOOFING": "Usurpation possible : domaine étranger à l’organisation annoncée.",
    "IDENTITY_DISPLAY_NAME_DISGUISED": "Nom affiché déguisé avec des lettres sosies.",
    "IDENTITY_COUSIN_DOMAIN": "Adresse d’envoi qui imite un domaine officiel par des caractères sosies.",
    "CORRELATION_COUSIN_DOMAIN_APPROACH": "Domaine sosie, récent ou qui renvoie les réponses ailleurs.",
    "CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC": "Hameçonnage soupçonné par le filtre, expéditeur non authentifié.",
    "CONTENT_URGENCY": "Pression pour agir vite.",
    "CONTENT_MIXED_SCRIPT": "Texte déguisé avec des lettres sosies.",
    "CONTENT_INTRAWORD_NOISE": "Mots coupés à l’intérieur par des signes parasites.",
    "CORRELATION_DISGUISED_UNKNOWN_SENDER": "Mots altérés, texte caché ou lettres sosies, et expéditeur inconnu dont personne ne répond.",
    "CONTENT_OBFUSCATION": "Texte encodé ou caché de façon inhabituelle.",
    "RSPAMD_OBFUSCATION_SYMBOL": "Texte encodé ou caché de façon inhabituelle.",
    "CORRELATION_COMPROMISED_SENDER": "Contenu sans rapport avec l’activité publiée ; compte détourné possible.",
    "CORRELATION_SPOOFED_UNRELATED_SENDER": "Adresse non authentifiée, d’un domaine sans rapport avec le message.",
    "URL_FAKE_HUMAN_VERIFICATION": "Lien vers une fausse vérification « êtes-vous humain ».",
    "URL_OPAQUE_LANDING": "Lien d’action vers une page vide sans script.",
    "CORRELATION_BRAND_TRANSACTION_LURE": "Fausse facture probable : paiement au nom d’une marque, envoyé par un autre expéditeur.",
    "CORRELATION_OPAQUE_TRANSACTION_LURE": "Faux reçu probable : paiement annoncé, expéditeur inconnu, page d’arrivée vide sans script.",
    "SENDER_ACTIVITY_INCOHERENT": "Contenu sans rapport avec l’activité publiée.",
}

# Le courrier déjà rangé dans les indésirables se lit comme une fiche, pas
# comme une démonstration. Les mêmes preuves y deviennent des libellés courts.
# Les autres surfaces gardent les phrases de ``_SHORT`` : elles posent encore
# une question, là où cet avis annonce une décision déjà appliquée.
_TELEGRAPHIQUE = {
    "AUTH_DMARC_FAIL": "Authentification : échec",
    "AUTH_SPF_SOFTFAIL": "Serveur d’envoi : non déclaré",
    "AUTH_SPF_FAIL": "Serveur d’envoi : refusé par le domaine",
    "AUTH_DKIM_FAIL": "Signature de l’expéditeur : échec",
    "AUTH_DKIM_UNALIGNED": "Signature de l’expéditeur : autre domaine",
    "AUTH_DKIM_INCONCLUSIVE": "Signature de l’expéditeur : absente",
    "AUTH_DMARC_INCONCLUSIVE": "Authentification : non vérifiable",
    "AUTH_SPF_INCONCLUSIVE": "Serveur d’envoi : non vérifiable",
    "IDENTITY_CLAIMED_ORGANISATION_REFUTED": "Identité : domaine sans rapport",
    "IDENTITY_CLAIMED_ORGANISATION_UNRELATED": "Identité : domaine sans rapport",
    "IDENTITY_BRAND_MISMATCH": "Identité : domaine sans rapport",
    "CORRELATION_BRAND_SPOOFING": "Identité : usurpation probable",
    "IDENTITY_DISPLAY_NAME_DISGUISED": "Identité : nom déguisé par des sosies",
    "IDENTITY_COUSIN_DOMAIN": "Identité : domaine sosie d’un domaine officiel",
    "CORRELATION_COUSIN_DOMAIN_APPROACH": "Identité : domaine sosie, récent ou réponses détournées",
    "CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC": "Filtre antispam : hameçonnage soupçonné, expéditeur non authentifié",
    "CONTENT_URGENCY": "Contenu : pression pour agir vite",
    "CONTENT_MIXED_SCRIPT": "Contenu : lettres sosies",
    "CONTENT_INTRAWORD_NOISE": "Contenu : mots coupés par des signes",
    "CORRELATION_DISGUISED_UNKNOWN_SENDER": "Déguisement : inconnu sans répondant",
    "CONTENT_OBFUSCATION": "Contenu : encodage inhabituel",
    "RSPAMD_OBFUSCATION_SYMBOL": "Contenu : encodage inhabituel",
    "CORRELATION_COMPROMISED_SENDER": "Activité : sans rapport avec l’expéditeur",
    "CORRELATION_SPOOFED_UNRELATED_SENDER": "Identité : adresse empruntée, métier sans rapport",
    "URL_FAKE_HUMAN_VERIFICATION": "Lien : fausse vérification anti-robot",
    "URL_OPAQUE_LANDING": "Lien : page d’arrivée vide sans script",
    "CORRELATION_BRAND_TRANSACTION_LURE": "Fausse facture : marque empruntée, premier contact",
    "CORRELATION_OPAQUE_TRANSACTION_LURE": "Faux reçu : paiement annoncé, page d’arrivée vide",
    "SENDER_ACTIVITY_INCOHERENT": "Activité : sans rapport avec l’expéditeur",
    "NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS": "Promesses : non vérifiables",
    "NATURE_SOLICITATION_WITHOUT_OPT_OUT": "Désinscription : absente",
    "HEADERS_RECIPIENT_NOT_ADDRESSED": "Destinataire : copie cachée",
}

# Les indices qui disent tous « ce message se fait passer pour quelqu'un
# d'autre ». Le plus fort suffit : les autres reformulent le même reproche.
_USURPATION = frozenset(_IDENTITY_CARD_CODES) | {
    "CORRELATION_COUSIN_DOMAIN_APPROACH",
    "IDENTITY_DISPLAY_NAME_DISGUISED",
}
# L'adresse empruntée sans marque : le faisceau dit à la fois le défaut
# d'authentification et le métier sans rapport. Il n'entre pas dans la carte
# d'identité, qui compare un nom annoncé à ses domaines officiels.
_ADRESSE_EMPRUNTEE = frozenset({"CORRELATION_SPOOFED_UNRELATED_SENDER"})

# Un constat que son voisin dit déjà, en plus fort : le retenir allongerait la
# liste sans rien apprendre. « Le domaine ne reconnaît pas cet envoi » couvre
# « rien ne permet de vérifier » et le serveur mal déclaré ; « compte détourné
# possible » couvre « contenu sans rapport avec l'activité ». Et quand une
# usurpation est établie, l'échec d'authentification n'est plus un grief à
# part : c'est par quoi elle se voit. Trois lignes disaient « ce n'est pas eux »
# de trois façons ; une seule le dit, la plus explicite.
_ABSORBES = {
    "AUTH_SPF_SOFTFAIL": _AUTH_FAILED,
    "AUTH_DKIM_INCONCLUSIVE": _AUTH_FAILED,
    "AUTH_DMARC_INCONCLUSIVE": _AUTH_FAILED,
    "AUTH_SPF_INCONCLUSIVE": _AUTH_FAILED,
    "AUTH_DMARC_FAIL": _USURPATION | _ADRESSE_EMPRUNTEE,
    "AUTH_SPF_FAIL": _USURPATION | _ADRESSE_EMPRUNTEE,
    "AUTH_DKIM_FAIL": _USURPATION | _ADRESSE_EMPRUNTEE,
    "AUTH_DKIM_UNALIGNED": _USURPATION | _ADRESSE_EMPRUNTEE,
    "CORRELATION_BRAND_FIRST_CONTACT": _USURPATION,
    "SENDER_ACTIVITY_INCOHERENT": frozenset(
        {"CORRELATION_COMPROMISED_SENDER"} | _ADRESSE_EMPRUNTEE
    ),
    # Le faisceau dit le soupçon du filtre et le défaut d'identité à la fois.
    "RSPAMD_PHISHING_HEURISTIC": frozenset(
        {"CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC"}
    ),
}


def _une_phrase(value: str | None) -> str:
    """La première phrase, seule : le grief sans ce qui le fonde."""
    phrases = _sentences(value or "")
    return phrases[0].strip() if phrases else ""


def _en_telegramme(value: str) -> str:
    """Donne une étiquette à une phrase qui n'a pas de libellé dédié."""
    texte = value.strip().rstrip(". ")
    if not texte:
        return ""
    for debut, etiquette in (
        ("Le message ", "Message : "),
        ("L’envoi ", "Envoi : "),
        ("L'expéditeur ", "Expéditeur : "),
        ("La sollicitation ", "Sollicitation : "),
    ):
        if texte.startswith(debut):
            return etiquette + texte[len(debut) :]
    return "Analyse : " + texte[:1].lower() + texte[1:]


def short_points(
    rows: list[dict[str, object]],
    limit: int,
    *,
    deja_dits: frozenset[str] = frozenset(),
    telegraphique: bool = False,
) -> list[str]:
    """Les mêmes indices que `plain_points`, mais un grief par ligne.

    Un avis se lit sur un téléphone, entre deux choses. Le fondement d'un
    grief - la page lue, l'objet comparé, les identités relevées - vaut
    quand on enquête ; recopié dans la puce, il donnait dix lignes où le
    reproche se perdait. Il reste au dossier, où il se consulte.

    `deja_dits` désigne les indices qu'un autre bloc de l'avis montre déjà :
    ils ne font pas de puce, mais comptent toujours pour l'absorption - sinon
    retirer le plus fort ferait remonter celui qu'il couvrait.
    """
    codes = {str(row.get("clue_code") or "") for row in rows}
    points: list[str] = []
    for row in _sans_controles_muets(rows):
        code = str(row.get("clue_code") or "")
        if code in deja_dits:
            continue
        if _ABSORBES.get(code, frozenset()) & codes:
            continue
        # Sans les faits, `plain_clue` rend la phrase toute faite, et rien
        # d'autre : c'est exactement le grief seul.
        sentence = (
            _TELEGRAPHIQUE.get(code) if telegraphique else _SHORT.get(code)
        )
        if _as_dict(row.get("facts")).get("text_scope") == "quoted_or_combined":
            sentence = "Texte cité ou mêlé à la réponse : " + (
                sentence or _une_phrase(_PLAIN.get(code) or str(row.get("statement") or ""))
            )
        if not sentence:
            sentence = _une_phrase(
                plain_clue(code, str(row.get("statement") or ""))
            )
            if telegraphique:
                sentence = _en_telegramme(sentence)
        if not sentence or sentence in points:
            continue
        points.append(sentence)
        if len(points) >= limit:
            break
    return points


def classification_reasons(
    adverse_rows: list[dict[str, object]],
    rationale: object,
    limit: int = 3,
    *,
    carte: object = None,
    telegraphique: bool = False,
) -> list[str]:
    """Pourquoi un message est classé : ses indices adverses, sinon son juge.

    Un classement appris ou jugé sans indice matériel laissait l'avis muet
    (« Un faisceau d'indices concordants ») alors que la motivation du verdict
    existait en base. Elle vaut mieux qu'une formule creuse.

    Quand la carte d'identité est dessinée, elle montre l'usurpation en trois
    lignes que l'œil compare : la redire en toutes lettres juste dessous ne
    fait pas un second grief, seulement une seconde lecture du même. Toute la
    famille de l'usurpation se tait alors - le domaine sosie comme le domaine
    étranger, la carte les montre pareillement - et l'avis n'a pas à se
    rabattre sur la motivation du juge, puisque la carte explique déjà.
    """
    points = short_points(
        adverse_rows,
        limit,
        deja_dits=_USURPATION if carte else frozenset(),
        telegraphique=telegraphique,
    )
    if points or carte:
        return points
    return short_points(
        [{"clue_code": "", "statement": str(rationale or "")}],
        1,
        telegraphique=telegraphique,
    )


def plain_limits(rows: list[dict[str, object]], limit: int) -> list[str]:
    """Ce qui n'a pas pu être vérifié, et rien d'autre."""
    return short_points(
        [
            row
            for row in rows
            if str(row.get("clue_code") or "") in _INCOMPLETENESS
        ],
        limit,
    )
