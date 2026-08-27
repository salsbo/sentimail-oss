"""Ce que MAIA dit à un humain, à la place de ce que le Code observe.

Un avis arrive un mardi matin dans une boîte : il doit se lire sans connaître le
Code Sentinel, sans savoir ce qu'est DMARC, et sans avoir à interpréter un score.
La preuve technique reste intacte en base, dans les journaux et dans le registre ;
seule sa formulation change ici.

Trois règles tenues par ce module : aucun code interne ni score dans un message,
une limite d'analyse n'est jamais présentée comme un danger, et rien n'est
inventé — chaque phrase traduit un indice réellement observé.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence

# Traduction d'un indice observé vers ce qu'il signifie pour le destinataire.
# Une entrée par article du Code ; l'énoncé technique sert de repli.
_PLAIN = {
    "AUTH_DMARC_FAIL": "Le message n’est pas envoyé par qui il prétend : le domaine affiché ne le reconnaît pas.",
    "AUTH_SPF_FAIL": "Le serveur qui a envoyé ce message n’est pas autorisé par le domaine affiché.",
    "AUTH_SPF_SOFTFAIL": "Le domaine affiché n’autorise qu’à moitié le serveur d’envoi.",
    "AUTH_DKIM_INCONCLUSIVE": "Rien ne prouve que le message n’a pas été modifié en chemin.",
    "AUTH_UNALIGNED": "La signature du message appartient à un autre domaine que celui affiché.",
    "AUTH_NO_TRUSTED_RESULTS": "Je n’ai pas pu vérifier l’identité de l’expéditeur.",
    "AUTH_DMARC_PASS": "L’expéditeur est bien celui qu’il annonce.",
    # « Non modifié » disait vrai du texte, et laissait croire à l'authenticité
    # de l'expéditeur : une signature valide peut appartenir à n'importe quel
    # hébergeur d'envoi. La phrase dit maintenant ce qu'elle prouve.
    "AUTH_DKIM_PASS": "Le domaine affiché a bien signé ce message, qui n’a pas été modifié en chemin.",
    "AUTH_DKIM_FAIL": "La signature du message est invalide.",
    "AUTH_DKIM_UNALIGNED": "Le message est signé par une autre organisation que celle qu’il affiche.",
    "AUTH_SPF_INCONCLUSIVE": "Le domaine affiché ne dit pas quels serveurs ont le droit d’envoyer en son nom.",
    "AUTH_DMARC_INCONCLUSIVE": "Le domaine affiché ne publie aucune règle permettant de vérifier son identité.",
    "IDENTITY_BRAND_MISMATCH": "Le nom affiché est celui d’une marque connue, mais le message vient d’ailleurs.",
    "IDENTITY_CLAIMED_ORGANISATION_UNRELATED": "Le message se présente au nom d’une organisation, depuis un domaine qui n’est pas le sien.",
    "IDENTITY_CLAIMED_ORGANISATION_REFUTED": "Le message se présente au nom d’une organisation dont les sites officiels, vérifiés à l’instant, ne comprennent pas le domaine qui a écrit.",
    "IDENTITY_COUSIN_DOMAIN": "L’adresse d’envoi imite celle d’une marque connue, à un caractère près.",
    "IDENTITY_ASCII_LOOKALIKE": "L’adresse utilise des caractères qui se ressemblent à l’œil (un zéro pour un o, un 1 pour un l).",
    "HEADERS_RECIPIENT_NOT_ADDRESSED": "Ton adresse n’apparaît pas dans le message : tu es en copie cachée.",
    "NATURE_MESSAGE_LANGUAGE": "Voici la langue dans laquelle ce message est écrit.",
    "CONTENT_ACTIVE_HTML": "Le message contient du code qui s’exécute à l’ouverture.",
    "RSPAMD_PHISHING_HEURISTIC": "Le filtre antispam reconnaît une tournure habituelle des tentatives d’hameçonnage.",
    "URL_STATIC_RISK": "Un lien du message présente une construction inhabituelle.",
    "URL_UNAUTHENTICATED_CROSS_APEX": "Un expéditeur non vérifié te renvoie vers un site qui ne lui appartient pas.",
    "CORRELATION_BRAND_SPOOFING": "Ce message se fait passer pour une marque connue : le nom est le bon, l’expéditeur non.",
    "CORRELATION_CREDENTIAL_HARVESTING": "Ce message mène à un formulaire qui réclame tes identifiants, sur un site qui n’est pas le sien.",
    "CORRELATION_UNSOLICITED_BULK": "Ce message est une publicité envoyée en masse, que tu n’as pas demandée.",
    "ATTACHMENT_MACRO_SHELL": "Un fichier joint contient un programme caché capable de prendre la main sur ton ordinateur.",
    "ATTACHMENT_MACRO_AUTO": "Un fichier joint contient un programme qui se lance tout seul à l’ouverture.",
    "ATTACHMENT_ACTIVE_DOCUMENT": "Un document joint contient du code qui s’exécute quand on l’ouvre.",
    "ATTACHMENT_ENCRYPTED_ARCHIVE": "Un fichier joint est protégé par un mot de passe : personne n’a pu vérifier ce qu’il contient.",
    "ATTACHMENT_EXECUTABLE_MEMBER": "Un fichier joint contient un programme à exécuter.",
    "ATTACHMENT_COMPRESSION_ANOMALY": "Un fichier joint est compressé d’une façon anormale.",
    "ATTACHMENT_YARA_MATCH": "Un fichier joint ressemble à un logiciel malveillant connu.",
    "ATTACHMENT_IMAGE_TEXT": "Une image jointe contient du texte, invisible à une lecture automatique.",
    "ATTACHMENT_EMBEDDED_URL": "Un fichier joint contient des liens vers Internet.",
    "ATTACHMENT_ANALYSIS_BLOCKED": "Je n’ai pas pu inspecter entièrement un fichier joint.",
    "CORRELATION_ANALYSIS_EVASION": "Ce message joint un fichier protégé par mot de passe et te presse de l’ouvrir : le mot de passe sert à empêcher toute vérification.",
    "CORRELATION_MALICIOUS_ATTACHMENT": "Ce message joint un fichier capable de prendre la main sur ton ordinateur, et t’invite à l’ouvrir.",
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
    "SENDER_SITE_CLAIMS_FOREIGN_BRAND": "Le site de cet expéditeur se fait passer pour une marque qui n’est pas la sienne.",
    "URL_SAME_ORGANISATION_DESTINATION": "Le lien mène à un site appartenant à la même organisation que l’expéditeur.",
    "CORRELATION_COMPROMISED_SENDER": "Cet expéditeur existe vraiment, mais ce message n’a rien à voir avec son métier : son compte a sans doute été détourné.",
    "CORRELATION_BRAND_FIRST_CONTACT": "Une marque connue t’écrit pour la première fois, depuis une adresse qui n’est pas la sienne.",
    "CORRELATION_PREPARED_APPROACH": "Ce message vient d’une adresse créée pour l’occasion, dont les réponses partent ailleurs.",
    "CORRELATION_COUSIN_DOMAIN_APPROACH": "Ce message vient d’une adresse créée pour ressembler à une marque connue.",
    "AUTH_SPF_PASS": "Le serveur d’envoi est autorisé par le domaine affiché.",
    "IDENTITY_ENVELOPE_VISIBLE_ALIGNED": "L’adresse visible et l’adresse technique concordent.",
    "IDENTITY_ENVELOPE_FROM_CROSS_APEX": "L’adresse technique d’envoi appartient à un autre domaine que l’adresse affichée.",
    "IDENTITY_DISPLAY_NAME_LOOKS_LIKE_ADDRESS": "Le nom affiché imite une adresse email.",
    "HEADERS_REPLY_TO_DIFFERENT_DOMAIN": "Une réponse partirait vers un autre domaine que l’expéditeur affiché.",
    "HEADERS_MULTIPLE_FROM": "Le message déclare plusieurs expéditeurs différents.",
    "CONTENT_SENSITIVE_REQUEST": "Le message demande une information sensible.",
    "CONTENT_URGENCY": "Le message cherche à te faire agir vite.",
    "CONTENT_COERCIVE_PRESSURE": "Le message menace d’une conséquence si tu n’agis pas.",
    "CONTENT_OBFUSCATION": "Le texte contient des caractères cachés qui masquent son contenu réel.",
    "CONTENT_SOCIAL_ENGINEERING_COMBINATION": "Le message combine urgence et demande sensible, comme une tentative de manipulation.",
    "CONTENT_NO_SENSITIVE_PRESSURE": "Je n’ai repéré ni demande sensible ni pression, mais je ne peux pas l’affirmer.",
    "CONTENT_EXTORTION": "Le message te menace ou réclame un versement pour ne pas nuire.",
    "CONTENT_ONE_TIME_CREDENTIAL_PROVIDED_NOT_REQUESTED": "Le message fournit un code de connexion sans te demander de le communiquer.",
    "URL_SANDBOX_FORM": "Un lien mène à un formulaire qui réclame des informations personnelles.",
    "URL_AMBIENT_SENSITIVE_FORM": "La page visée contient un formulaire sensible, sans que le message le demande.",
    "URL_SANDBOX_CROSS_APEX": "Un bouton conduit vers un site qui n’appartient pas à l’expéditeur.",
    "URL_CROSS_APEX": "Le message renvoie vers des sites extérieurs à l’expéditeur.",
    "URL_DECEPTIVE_LINK_TEXT": "Un lien affiche une destination différente de celle où il mène vraiment.",
    "URL_CLOAKING": "Un lien cache sa véritable destination derrière des redirections.",
    "URL_KNOWN_MALICIOUS": "Un lien de ce message est répertorié comme malveillant.",
    "URL_SANDBOX_INCOMPLETE": "Je n’ai pas pu ouvrir tous les liens pour les vérifier.",
    "URL_PROTECTED_ACTION_NOT_VISITED": "Un lien à usage unique n’a pas été ouvert, pour ne pas le consommer à ta place.",
    "URL_GENERIC_FORM": "La page visée propose un formulaire ordinaire, sans donnée sensible.",
    "URL_AUTHENTICATED_TRACKING_CONVERGENCE": "Les liens de suivi mènent bien au site de l’expéditeur.",
    "ATTACHMENT_EXECUTABLE": "Une pièce jointe peut exécuter du code sur ton appareil.",
    "ATTACHMENT_DOUBLE_EXTENSION": "Une pièce jointe déguise son type réel.",
    "ATTACHMENT_MACRO": "Un document joint contient des macros.",
    "ATTACHMENT_KNOWN_MALICIOUS": "Une pièce jointe est reconnue comme malveillante.",
    "ATTACHMENT_SANDBOX_INCOMPLETE": "Je n’ai pas pu inspecter toutes les pièces jointes.",
    "NATURE_BULK_MAILING": "C’est un envoi de masse, comme une lettre d’information.",
    "NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS": "Le message promet des résultats invérifiables.",
    "NATURE_SOLICITATION_WITHOUT_OPT_OUT": "Cette sollicitation n’offre aucun moyen de se désinscrire.",
    "HISTORY_FIRST_OBSERVATION": "C’est la première fois que cet expéditeur t’écrit.",
    "HISTORY_CONFIRMED_SENDER": "Tu as déjà reçu et accepté des messages de cet expéditeur.",
    "SENDER_DOMAIN_RECENT": "Le domaine de l’expéditeur a été créé récemment.",
    "SENDER_DOMAIN_ESTABLISHED": "Le domaine de l’expéditeur existe depuis des années.",
    "TYPOSQUATTING": "Le domaine imite celui d’une marque connue.",
    "RSPAMD_MATERIAL_SYMBOL": "Le filtre antispam relève un signal défavorable précis.",
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


def _dit_l_organisation(facts: dict) -> str:
    """L'organisation revendiquée, ses sites trouvés, et d'où vient le message."""
    organisation = str(facts.get("claimed_organisation") or "").strip()
    domaine = str(facts.get("from_apex") or "").strip()
    officiels = _domaines(facts)
    if not organisation or not domaine or not officiels:
        return ""
    return (
        f"{organisation} publie sur {officiels} ; ce message vient de {domaine}."
    )


# Ce qu'un grief doit dire en plus de lui-même, article par article. La phrase
# toute faite nomme le grief ; celle-ci le rend vérifiable par le lecteur, qui
# n'a plus à croire sur parole que le domaine n'est pas le bon.
_PRECISIONS = {
    "IDENTITY_BRAND_MISMATCH": _dit_la_marque,
    "IDENTITY_COUSIN_DOMAIN": _dit_la_marque,
    "IDENTITY_ASCII_LOOKALIKE": _dit_la_marque,
    "IDENTITY_CLAIMED_ORGANISATION_REFUTED": _dit_l_organisation,
}


# Ces précisions-là disent le grief en même temps que son fondement : les faire
# suivre la phrase toute faite reviendrait à écrire deux fois la même chose, la
# seconde en mieux. Elles la remplacent donc.
_AUTONOMES = frozenset(
    {
        "IDENTITY_BRAND_MISMATCH",
        "IDENTITY_COUSIN_DOMAIN",
        "IDENTITY_ASCII_LOOKALIKE",
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


def plain_points(rows: list[dict[str, object]], limit: int) -> list[str]:
    """Retient les indices les plus parlants, sans répéter la même idée."""
    seen: set[str] = set()
    points: list[str] = []
    for row in rows:
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


def classification_reasons(
    adverse_rows: list[dict[str, object]], rationale: object, limit: int = 5
) -> list[str]:
    """Pourquoi un message est classé : ses indices adverses, sinon son juge.

    Un classement appris ou jugé sans indice matériel laissait l'avis muet
    (« Un faisceau d'indices concordants ») alors que la motivation du verdict
    existait en base. Elle vaut mieux qu'une formule creuse.
    """
    points = plain_points(adverse_rows, limit)
    if points:
        return points
    return plain_points([{"clue_code": "", "statement": str(rationale or "")}], 1)


def plain_limits(rows: list[dict[str, object]], limit: int) -> list[str]:
    """Ce qui n'a pas pu être vérifié, et rien d'autre."""
    return plain_points(
        [
            row
            for row in rows
            if str(row.get("clue_code") or "") in _INCOMPLETENESS
        ],
        limit,
    )
