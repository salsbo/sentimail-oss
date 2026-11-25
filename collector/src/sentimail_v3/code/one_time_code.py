"""Le courrier qu'on attend devant son écran : le livrer sans faire attendre.

Un code de connexion vaut quelques minutes. Le faire passer par l'inspection
complète - bac à sable des liens, interrogation RDAP, jugement du modèle - lui
coûtait quarante-cinq secondes, mesurées sur les envois réels d'OpenAI, de
1Password et d'Anthropic. À ce délai, l'utilisateur a déjà redemandé un code,
et le premier arrive périmé. La lenteur devient alors une panne.

La voie rapide n'est pas une exception de complaisance : c'est une inspection
plus courte pour un courrier dont la forme est très contrainte. Elle ne
s'ouvre que si le message DONNE un code sans en réclamer aucun, si l'identité
de l'expéditeur est établie, s'il ne porte ni pièce jointe ni pression, et si
ses liens restent chez lui. Le moindre écart et le message repart par le
chemin ordinaire : la voie rapide ne peut jamais innocenter, seulement
raccourcir l'attente d'un message déjà sans reproche.

« Rester chez lui » se lit sur les envois réels : OpenAI écrit depuis
tm.openai.com vers openai.com, et 1Password depuis 1password.eu vers
1password.com - même marque, autre extension. C'est ce que « les apex ne
diffèrent pas beaucoup » veut dire ici.

Le 1er septembre 2026, un faux avis de double authentification d'un hébergeur
est parti par cette voie. Il venait d'un domaine d'envoi jetable, authentifié
pour lui-même, jamais vu ici, et ne donnait aucun code : seulement le mot
« code de vérification » et un lien vers une page de collecte sur son propre
domaine. Rien, avant l'analyse profonde, ne compare le nom revendiqué au
domaine réel. La voie exige donc désormais un code montré et une adresse déjà
reçue : une première observation passe toujours par l'examen complet.
"""

from __future__ import annotations

import re

from sentimail_v3.code.organisation import same_organisation

# Ce que le message doit présenter pour être un code livrable vite. Les trois
# marqueurs viennent du courrier réel : OpenAI et 1Password annoncent un code à
# saisir et son expiration ; « code fourni sans être demandé » est le troisième,
# plus rare. Exiger le seul dernier fermait la voie à tous les envois observés.
REQUIRED = frozenset(
    {
        "CONTENT_EXPECTED_ONE_TIME_CODE_INPUT",
        "CONTENT_EXPECTED_ONE_TIME_EXPIRATION",
        "CONTENT_ONE_TIME_CREDENTIAL_PROVIDED_NOT_REQUESTED",
    }
)
# L'identité doit être établie : la vitesse ne se paie pas par l'authenticité.
AUTHENTICATED = frozenset({"AUTH_DMARC_PASS"})
# Une adresse ne vaut « déjà reçue » qu'après une semaine. Même raison que
# l'ancienneté de _history : sans elle, un domaine jetable s'établirait en
# quelques minutes avec un premier envoi anodin.
ANCIENNETE_JOURS = 7

# Le mot qui annonce un code. Les usages voisins qui ne sont pas un secret de
# connexion sont écartés : code promo, code postal, code-barres, code des
# assurances.
_CODE_WORD = re.compile(
    r"\b(?:code|passcode|otp|pin|one[- ]time password|"
    r"mot de passe (?:temporaire|[àa] usage unique))\b"
    r"(?!\s?[-:]?\s?(?:postal|promo\w*|de r[ée]duction|r[ée]duction|barres?|"
    r"avantage|cadeau|parrainage|discount|coupon|qr|source|client|naf|ape|zip|"
    r"des\b|de la\b|civil))",
    re.IGNORECASE,
)
# Le code lui-même : quatre à huit chiffres, ou deux groupes de trois. Isolé :
# ni collé à une lettre, un tiret, un symbole monétaire ou un autre groupe de
# chiffres (dates, plages d'années, numéros de réunion, SIREN), ni précédé
# d'une virgule (« rue X, 76100 Ville »). Les codes alphanumériques du courrier
# réel étaient tous des codes promo : ils ne comptent pas.
_CODE_TOKEN = re.compile(
    r"(?<![\w#€$£%/.,+@=&?~<>'-])(?<!\d[ -])(?<!,\s)"
    r"(\d{3}[ -]\d{3}|\d{4,8})"
    r"(?![\w€$£%/:+@=&?<>-]|[.,]\d|[ -]\d)"
)
_ANNEE = re.compile(r"(?:19|20)\d{2}")
# Le code suit son annonce de près, ou la précède dans l'objet
# (« 482913 est votre code »). Distances en caractères, espaces réduits.
_AVANT, _APRES = 40, 80

# Les codes qui referment la voie même quand ils arrivent neutres. La règle de
# charge (adverse) couvre déjà tout indice adverse ; cette liste garde les
# constats que l'observation pose en neutre mais qui n'ont rien à faire sur un
# code de connexion : RSPAMD_PHISHING_HEURISTIC, RSPAMD_HIGH_SCORE et
# URL_DECEPTIVE_LINK_TEXT sont aujourd'hui tous les trois toujours neutres (97
# indices RSPAMD_PHISHING_HEURISTIC au 29 septembre 2026) ; si un autre
# chantier leur donne un jour une direction conditionnelle, cette liste reste
# la bonne barrière de repli. N'y figurent que des codes qu'un hook synchrone
# émet : la décision précède l'analyse profonde. Un test le vérifie.
DISQUALIFYING = frozenset(
    {
        "CONTENT_SENSITIVE_REQUEST",
        "CONTENT_EXTORTION",
        "CONTENT_SOCIAL_ENGINEERING_COMBINATION",
        "CONTENT_OBFUSCATION",
        "CONTENT_ACTIVE_HTML",
        "IDENTITY_UNICODE_HOMOGRAPH",
        "IDENTITY_DISPLAY_NAME_EMAIL_MISMATCH",
        "IDENTITY_SENDER_CROSS_APEX",
        "HEADERS_REPLY_TO_DIFFERENT_DOMAIN",
        "HEADERS_MULTIPLE_FROM",
        "HEADERS_RECIPIENT_NOT_ADDRESSED",
        "URL_DECEPTIVE_LINK_TEXT",
        "URL_STATIC_RISK",
        "RSPAMD_MATERIAL_SYMBOL",
        "RSPAMD_HIGH_SCORE",
        "RSPAMD_PHISHING_HEURISTIC",
        "AUTH_DKIM_UNALIGNED",
    }
)


# Familles entières qui referment la voie rapide, quel que soit le code précis :
# un code de connexion ne porte aucun fichier, et une convergence d'indices
# décrit un montage - deux choses qui appellent l'examen complet.
DISQUALIFYING_PREFIXES = ("ATTACHMENT_", "CORRELATION_", "SENDER_SITE_")


def _label(apex: str) -> str:
    return apex.split(".", 1)[0]


def apexes_are_close(
    sender_apex: str,
    destinations: list[str] | set[str],
    organisations: dict[str, set[str]],
) -> bool:
    """Vrai quand les liens du message restent chez l'expéditeur.

    Trois façons d'y rester : le même domaine, la même marque sous une autre
    extension, ou le même titulaire enregistré. Un seul lien qui s'en écarte
    referme la voie rapide - c'est justement le cas qu'on veut examiner.
    """
    if not sender_apex:
        return False
    sender_signature = organisations.get(sender_apex) or set()
    for destination in destinations:
        if not destination or destination == sender_apex:
            continue
        if destination.endswith("." + sender_apex):
            continue
        if _label(destination) and _label(destination) == _label(sender_apex):
            continue
        if same_organisation(sender_signature, organisations.get(destination) or set()):
            continue
        return False
    return True


def shows_one_time_code(text: str | None) -> bool:
    """Le texte montre-t-il un code à saisir, et pas seulement le mot ?

    « Lien sécurisé », « code de vérification » disent la finalité, pas la
    chose. Un vrai code se voit : quelques chiffres à côté du mot. Ce constat
    ne prouve rien sur l'expéditeur - un fraudeur peut écrire six chiffres - il
    dit seulement que le message est bien un code. Rend un booléen et jamais
    le code : c'est un secret vivant.
    """
    try:
        sample = re.sub(r"\s+", " ", text or "")
        mots = [(m.start(), m.end()) for m in _CODE_WORD.finditer(sample)]
        if not mots:
            return False
        for jeton in _CODE_TOKEN.finditer(sample):
            if _ANNEE.fullmatch(jeton.group(1)):
                continue
            if any(debut - _AVANT <= jeton.start() <= fin + _APRES for debut, fin in mots):
                return True
        return False
    except Exception:  # noqa: BLE001 - un constat en panne est un constat absent
        return False


def express_delivery_reason(
    clue_codes: set[str],
    sender_apex: str,
    destinations: list[str] | set[str],
    organisations: dict[str, set[str]],
    adverse: set[str] | frozenset[str] | None = None,
    *,
    established: bool = False,
    code_visible: bool = False,
) -> str | None:
    """Le motif d'une livraison accélérée, ou None si le message doit être examiné.

    `adverse` porte les indices que l'observation a retenus contre le message,
    quels qu'ils soient. Une liste nominative de codes ne peut pas suivre les
    articles qu'on ajoute : le 26 août, un faux « DISNEY+ » est parti par cette
    voie en portant du texte masqué par CSS, article écrit après la liste. La
    charge referme donc la voie par sa direction, pas par son nom.

    `code_visible` dit que le texte montre le code lui-même : le vocabulaire
    seul ouvrait la voie à un lien de collecte et à une réclame à code promo.
    `established` dit que l'adresse exacte a déjà été reçue ici, authentifiée,
    après un examen complet : le 1er septembre, une adresse jamais vue est
    passée par cette voie sans qu'aucun contrôle ne confronte le nom revendiqué
    au domaine. Les deux valent faux par défaut : un appelant qui ne les
    fournit pas n'ouvre jamais la voie.
    """
    if not REQUIRED & clue_codes:
        return None
    if not AUTHENTICATED & clue_codes:
        return None
    if adverse:
        return None
    if DISQUALIFYING & clue_codes:
        return None
    if any(
        code.startswith(DISQUALIFYING_PREFIXES) for code in clue_codes
    ):
        return None
    # Le code montré ne dit rien de l'expéditeur : c'est l'adresse déjà reçue
    # qui porte la sécurité. Les deux sont exigés ensemble.
    if not code_visible:
        return None
    if not established:
        return None
    if not apexes_are_close(sender_apex, destinations, organisations):
        return None
    return (
        "Ce message montre un code à usage unique sans rien demander en "
        "retour, son adresse d'expéditeur, authentifiée, a déjà été reçue ici "
        "après un examen complet il y a au moins une semaine, et ses liens "
        "restent chez lui : il est livré sans attendre l'inspection complète."
    )


# Le seul motif de risque statique qu'une appartenance puisse expliquer. Les
# autres - extension détournée, nom internationalisé, empilement de
# sous-domaines - ne s'expliquent par aucune propriété.
_SHORTENER_REASON = "raccourcisseur masquant la destination"


def excusable_static_risk(
    risky_urls: list[dict[str, object]],
    *,
    sender_apex: str,
    organisations: dict[str, set[str]],
) -> bool:
    """Le risque statique se réduit-il à un raccourcisseur de l'expéditeur ?

    « raccourcisseur masquant la destination » est un motif juste : bit.ly peut
    mener n'importe où. Mais t.co appartient à X, et un lien t.co dans un
    message de X ne dissimule pas plus que x.com.

    L'assouplissement est étroit à dessein, et exige trois choses ensemble : le
    raccourcisseur est le seul motif, il relève du même maître que
    l'expéditeur, et cette appartenance est attestée - par la délégation DNS ou
    par un titulaire déclaré, jamais supposée. Une seule URL qui s'en écarte
    referme l'excuse.
    """
    if not risky_urls or not sender_apex:
        return False
    signature = organisations.get(sender_apex) or set()
    if not signature:
        return False
    for url in risky_urls:
        reasons = url.get("reasons")
        if not isinstance(reasons, list) or list(reasons) != [_SHORTENER_REASON]:
            return False
        apex = str(url.get("apex") or "")
        if not apex:
            return False
        if not same_organisation(signature, organisations.get(apex) or set()):
            return False
    return True
