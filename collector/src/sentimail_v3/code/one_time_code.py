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
"""

from __future__ import annotations

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
# Tout ce qui, présent, referme la voie rapide. La liste est volontairement
# large : dans le doute, le chemin ordinaire reste disponible et ne coûte
# qu'une minute.
DISQUALIFYING = frozenset(
    {
        "CONTENT_SENSITIVE_REQUEST",
        "CONTENT_COERCIVE_PRESSURE",
        "CONTENT_EXTORTION",
        "CONTENT_SOCIAL_ENGINEERING_COMBINATION",
        "CONTENT_OBFUSCATION",
        "CONTENT_ACTIVE_HTML",
        "IDENTITY_BRAND_MISMATCH",
        "IDENTITY_COUSIN_DOMAIN",
        "IDENTITY_UNICODE_HOMOGRAPH",
        "IDENTITY_DISPLAY_NAME_EMAIL_MISMATCH",
        "IDENTITY_SENDER_CROSS_APEX",
        "HEADERS_REPLY_TO_DIFFERENT_DOMAIN",
        "HEADERS_MULTIPLE_FROM",
        "HEADERS_RECIPIENT_NOT_ADDRESSED",
        "URL_DECEPTIVE_LINK_TEXT",
        "URL_STATIC_RISK",
        "URL_KNOWN_MALICIOUS",
        "SENDER_DOMAIN_RECENT",
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


def express_delivery_reason(
    clue_codes: set[str],
    sender_apex: str,
    destinations: list[str] | set[str],
    organisations: dict[str, set[str]],
    adverse: set[str] | frozenset[str] | None = None,
) -> str | None:
    """Le motif d'une livraison accélérée, ou None si le message doit être examiné.

    `adverse` porte les indices que l'observation a retenus contre le message,
    quels qu'ils soient. Une liste nominative de codes ne peut pas suivre les
    articles qu'on ajoute : le 26 août, un faux « DISNEY+ » est parti par cette
    voie en portant du texte masqué par CSS, article écrit après la liste. La
    charge referme donc la voie par sa direction, pas par son nom.
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
    if not apexes_are_close(sender_apex, destinations, organisations):
        return None
    return (
        "Ce message fournit un code à usage unique sans rien demander en "
        "retour, son expéditeur est authentifié et ses liens restent sur son "
        "propre domaine : il est livré sans attendre l'inspection complète."
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
