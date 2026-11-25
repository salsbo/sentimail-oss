"""Le nom affiché et le domaine qui écrit ont-ils un rapport ?

La mécanique tient en quatre temps, et c'est le troisième qui la distingue de
ce qui existait :

1. le nom affiché reprend-il déjà le domaine ? « Synology News » depuis
   synology.com : la question ne se pose pas, et rien ne part chercher ;
2. sinon, on cherche dehors ce que chacun est - le nom d'un côté, le domaine de
   l'autre ;
3. le modèle lit ces deux réponses et dit s'il y a un rapport. Il ne répond plus
   de mémoire : il répond sur pièces ;
4. « aucun rapport » devient un indice ; « rapport » et « je ne peux pas dire »
   n'en produisent aucun.

L'ordre importe. Interroger le modèle en premier, comme on le faisait, revenait
à lui faire fermer la porte sur ce qu'il ignore : un nom qu'il ne connaît pas
recevait la réponse prudente - « ça peut appartenir » - et aucune recherche ne
partait jamais. Chercher d'abord retire à la mémoire du modèle le pouvoir
d'empêcher la vérification.

Ce qui sort de la machine : le nom sous lequel le message se présente, et le
domaine émetteur. Depuis le 16 septembre 2026, ce nom peut venir du corps : une
marque écrite par l'expéditeur, recopiée telle quelle, retenue seulement si le
message l'écrit en entier et si elle ne nomme pas le destinataire
(`claimed_in_message`, `names_the_recipient`). Ni le destinataire, ni l'objet,
ni une ligne du message ne partent avec elle.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

# Ces mots accompagnent un nom sans rien désigner : les comparer au domaine ne
# dirait rien de personne.
_HABILLAGE = frozenset(
    {
        "recovery",
        "support",
        "service",
        "services",
        "client",
        "clients",
        "team",
        "equipe",
        "info",
        "infos",
        "contact",
        "notification",
        "notifications",
        "alerte",
        "alertes",
        "securite",
        "security",
        "billing",
        "facturation",
        "noreply",
        "no",
        "reply",
        "mail",
        "email",
        "news",
        "newsletter",
        "the",
        "le",
        "la",
        "les",
        "de",
        "du",
        "des",
        "par",
        "via",
        "and",
        "et",
    }
)
_MIN_TOKEN = 4
# Un sigle désigne quelqu'un dès trois lettres : CIC, BNP, WTW. À deux, il ne
# désigne plus rien qu'on puisse chercher (SG, FR).
_MIN_SIGLE = 3
# Des lettres isolées, séparées par des espaces ou des points : « C I C »,
# « C.I.C. ». C'est un sigle écrit lettre à lettre - et, quand il vient d'un
# expéditeur inconnu, une façon d'échapper à une comparaison de mots.
_LETTRES_ISOLEES = re.compile(r"(?<![A-Za-z])(?:[A-Z][ .]+){2,}[A-Z]\.?(?![A-Za-z])")
# Un mot tout en majuscules de trois lettres exactement : en dessous du seuil
# des mots ordinaires, mais qui désigne quelqu'un précisément parce qu'il est
# écrit ainsi.
_SIGLE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{3}(?![A-Za-z0-9])")


def _sans_accents(value: str) -> str:
    decompose = unicodedata.normalize("NFKD", value.casefold())
    return "".join(char for char in decompose if not unicodedata.combining(char))


def _sigles(value: str) -> list[str]:
    """Les sigles que le nom porte, lus avant que la casse ne soit effacée.

    « C I C » depuis cic-notification.sju.somesepta.best (6 septembre 2026) :
    aucun mot de quatre lettres, donc aucun jeton, donc la question de
    l'identité n'a jamais été posée, et un hameçonnage bancaire évident est
    parti en simple doute. Un sigle est un mot propre comme un autre.
    """
    trouves = [
        re.sub(r"[ .]", "", groupe.group(0)) for groupe in _LETTRES_ISOLEES.finditer(value)
    ]
    trouves.extend(groupe.group(0) for groupe in _SIGLE.finditer(value))
    return [
        sigle.casefold()
        for sigle in trouves
        if len(sigle) >= _MIN_SIGLE and sigle.casefold() not in _HABILLAGE
    ]


def _tokens(value: str) -> list[str]:
    mots = [
        mot
        for mot in re.split(r"[^a-z0-9]+", _sans_accents(value))
        if len(mot) >= _MIN_TOKEN and mot not in _HABILLAGE
    ]
    for sigle in _sigles(value):
        if sigle not in mots:
            mots.append(sigle)
    return mots


def claimed_name(display_name: str) -> str:
    """Le nom tel qu'on le cherche : un sigle écrit lettre à lettre recollé.

    « C I C » cherché tel quel ne rend rien de CIC ; recollé, il désigne la
    banque. Le reste du nom est gardé tel qu'il est écrit.
    """
    return _LETTRES_ISOLEES.sub(
        lambda groupe: re.sub(r"[ .]", "", groupe.group(0)), display_name
    ).strip()


def _label(from_apex: str) -> str:
    """Le nom propre du domaine, sans son suffixe ni ses sous-domaines.

    news.synology.com donne « synology », doctolib-offres.fr donne
    « doctoliboffres » : c'est ce nom-là qu'on compare, et non la chaîne
    entière, où toute marque accolée se retrouverait par hasard.
    """
    parts = [part for part in _sans_accents(from_apex).split(".") if part]
    if not parts:
        return ""
    if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
        # Suffixe à deux étiquettes : co.uk, com.au, gouv.fr.
        parts = parts[:-2]
    elif len(parts) >= 2:
        parts = parts[:-1]
    return parts[-1].replace("-", "") if parts else ""


def obvious_relation(display_name: str, from_apex: str) -> bool:
    """Le domaine qui envoie porte-t-il exactement le nom affiché ?

    C'est le cas de l'immense majorité du courrier légitime, et c'est ce qui
    garde le coût de tout le reste négligeable : aucune recherche, aucun appel
    au modèle.

    L'égalité est exigée, et c'est tout le sujet. Une simple présence du nom
    dans le domaine dispensait de vérifier « doctolib-offres.fr » et
    « decathlon-offres.fr » - deux domaines qui n'appartiennent pas à ces
    enseignes, et dont accoler leur nom est précisément le procédé. La dispense
    ne vaut donc que pour un domaine qui EST le nom : doctolib.fr,
    news.synology.com, credit-agricole.fr.
    """
    label = _label(from_apex)
    if not label:
        return False
    mots = _tokens(display_name)
    if not mots:
        return False
    return label in set(mots) | {"".join(mots)}


def _segments(domain: str) -> set[str]:
    """Les morceaux d'un nom de domaine, étiquette par étiquette, tiret par tiret."""
    return {
        segment
        for segment in re.split(r"[.\-]+", _sans_accents(domain))
        if segment
    }


def appended_to_official(
    from_apex: str, official_apexes: list[str], from_domain: str = ""
) -> str:
    """Le domaine accole-t-il le nom d'un domaine officiel sans être lui ?

    « notif-colissimo-laposte.info » face à « laposte.fr »,
    « doctolib-offres.fr » face à « doctolib.fr » : le nom y est, entier, avec
    un mot devant ou derrière. C'est le procédé le plus courant, et il se
    constate sans avis - le rendre au jugement du modèle, c'est risquer qu'il y
    voie un domaine de service de l'enseigne, ce qu'il a fait.

    Le nom volé ne vit pas toujours dans l'apex : « cic-notification.sju.
    somesepta.best » le porte dans un sous-domaine, que l'apex seul ne montre
    pas. Le domaine complet de l'adresse, quand on l'a, est donc lu aussi. Un
    sigle court y est exigé en segment entier - « cic » entre deux tirets ou
    deux points - et non en sous-chaîne, où « pacific » le contiendrait.

    Rend le domaine officiel imité, ou une chaîne vide.
    """
    label = _label(from_apex)
    if not label:
        return ""
    segments = _segments(from_domain or from_apex) | _segments(from_apex)
    for apex in official_apexes:
        officiel = _label(apex)
        if not officiel or len(officiel) < _MIN_SIGLE:
            continue
        if officiel == label:
            continue
        if len(officiel) >= _MIN_TOKEN and officiel in label:
            return apex
        if officiel in segments:
            return apex
    return ""


def owned_by_official(
    from_apex: str,
    official_apexes: list[str],
    organisations: dict[str, set[str]],
) -> str:
    """Un fait de propriété rattache-t-il le domaine émetteur à un domaine officiel ?

    La graphie accuse, un fait innocente. « e-ca-paris.fr » contient
    « ca-paris » et s'est vu accusé d'imiter ca-paris.com le 3 septembre 2026,
    alors que sa délégation DNS - ramses.credit-agricole.fr - le rattachait à
    un apex officiel que la recherche avait rendu. Ce fait était en base, il
    n'était pas regardé.

    Les signatures sont celles du Code (`organisation.py`) : la délégation NS
    quand elle n'est pas mutualisée, le titulaire RDAP quand il n'est pas
    masqué, le domaine signataire DKIM. Deux façons d'attester : la signature
    de l'émetteur nomme elle-même un apex officiel, ou elle recoupe celle
    d'un apex officiel. Rien d'attestable - Cloudflare, RDAP fermé - ne lève
    rien : on n'assouplit pas sur l'absence de preuve.

    Rend l'apex officiel qui atteste, ou une chaîne vide.
    """
    signature = organisations.get(from_apex.strip().casefold()) or set()
    if not signature:
        return ""
    for apex in official_apexes:
        officiel = apex.strip().casefold()
        if not officiel or officiel == from_apex.strip().casefold():
            continue
        if {"ns:" + officiel, "dkim:" + officiel} & signature:
            return apex
        if signature & (organisations.get(officiel) or set()):
            return apex
    return ""


CLAIM_PROMPT = """Tu lis un message et tu dis au nom de quelle organisation,
marque ou service il se présente : celle dont il parle comme étant
l'expéditeur, celle dont il porte l'en-tête ou le logo, celle dont il annonce
le reçu, la facture, l'abonnement, la livraison ou le compte. Tu ne juges pas
le message et tu ne dis pas s'il est honnête.

Réponds uniquement par cet objet JSON :
{"organisation": "le nom tel qu'il est écrit dans le message, ou null", "sujet": "une phrase courte : de quoi parle le message"}

Recopie le nom tel qu'il est écrit, sans le compléter, le traduire ni le
deviner : « Prime Famille » reste « Prime Famille », pas « Amazon Prime ».
Réponds null si le message ne se présente au nom d'aucune organisation, ou si
ce que tu lirais comme un nom n'est qu'un nom commun (« votre prime de fin
d'année », « la société », « le service client »). Un nom d'expéditeur
générique (« Service Client », « Notification », « Annuel-Famille ») n'est
pas une organisation."""


def claim_question(*, display_name: str, subject: str, text: str) -> str:
    """Ce que le modèle lit pour dire au nom de qui le message se présente.

    Contrairement à la question de rapport, celle-ci porte le message : c'est
    précisément dans le corps que « Prime Famille » était écrit le 16 septembre
    2026, quand le nom affiché ne désignait personne.
    """
    return (
        "NOM AFFICHÉ PAR LE MESSAGE :\n"
        + (display_name.strip() or "(aucun)")
        + "\n\nOBJET :\n"
        + subject.strip()
        + "\n\nTEXTE VISIBLE :\n"
        + text[:1500]
    )


def parse_claim(content: str) -> str:
    """L'organisation lue dans la réponse du modèle, ou une chaîne vide."""
    start, end = content.find("{"), content.rfind("}")
    if start < 0 or end <= start:
        return ""
    try:
        parsed = json.loads(content[start : end + 1])
    except (ValueError, TypeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    organisation = parsed.get("organisation")
    if not isinstance(organisation, str):
        return ""
    return organisation.strip()[:80]


def claimed_in_message(
    organisation: str, *, display_name: str, subject: str, text: str
) -> bool:
    """Le message écrit-il vraiment le nom que le modèle lui prête ?

    Le modèle propose, le message confirme : une identité qu'il n'affiche pas
    ne peut fonder aucune accusation. Tous les mots propres du nom doivent
    être écrits : « Amazon Prime » quand seul « prime » l'est, c'est Amazon lu
    par le modèle, pas revendiqué par le message ; « Société Générale » dans un
    mail qui parle de « votre société » n'est personne.
    """
    mots = _tokens(claimed_name(organisation))
    if not mots:
        return False
    corpus = " ".join((claimed_name(display_name), subject, text))
    ecrits = set(re.split(r"[^a-z0-9]+", _sans_accents(corpus)))
    return all(mot in ecrits for mot in mots)


def names_the_recipient(organisation: str, recipient_address: str) -> bool:
    """Le nom lu désigne-t-il le destinataire lui-même ?

    Ce qui part vers le moteur de recherche ne doit jamais être une personne :
    un modèle qui prendrait « Bonjour MARTIN ALICE » pour une organisation
    enverrait le nom du destinataire dehors. Un mot propre du nom, d'au moins
    quatre lettres, retrouvé dans la partie locale de l'adresse suffit à
    refuser.
    """
    local = _sans_accents(str(recipient_address or "").rsplit("@", 1)[0])
    local = re.sub(r"[^a-z0-9]+", "", local)
    if not local:
        return False
    return any(len(mot) >= _MIN_TOKEN and mot in local for mot in _tokens(organisation))


def worth_asking(display_name: str, clue_codes: set[str]) -> bool:
    """Ce nom désigne-t-il quelque chose qu'on puisse confronter ?

    Un nom qui recopie l'adresse ne revendique rien, un expéditeur déjà confirmé
    n'a rien à prouver, et un intitulé sans le moindre mot propre ne se cherche
    pas.
    """
    nom = display_name.strip()
    if not nom or "@" in nom:
        return False
    if {"HISTORY_CONFIRMED_LEGITIMATE_SENDER", "AUTHENTICATED_SENDER_ALLOW"} & clue_codes:
        return False
    return bool(_tokens(nom))


# « X via Y » : X écrit, Y est le service qui porte le message et dont on
# attend le domaine. « BOURGEOIS Muriel via PRONOTE » depuis
# index-education.net (M-633c24) : l'organisation revendiquée est PRONOTE ;
# chercher le nom entier a rendu le site d'un homonyme de l'enseignante. Les
# autres tournures disent la même chose dans l'autre sens : dans « X pour le
# compte de Y », « X on behalf of Y », « X de la part de Y », « X au nom de
# Y », X agit et Y est l'organisation au nom de laquelle le message se
# présente. « Tino from n8n », « Madina chez Mon Cadre Préféré » (M-480fba,
# DEEP-022 depuis moncadreprefere.fr) sont la forme commerciale de la même
# chose. Dans tous les cas, c'est Y qui se confronte au domaine.
_RELAIS = re.compile(
    r"\s+[(\[]?\s*(?:via|from|chez|on\s+behalf\s+of"
    r"|(?:de\s+la\s+part|pour\s+le\s+compte|au\s+nom|par\s+l['’]interm[ée]diaire)"
    r"\s+(?:de\s+|d['’]\s*))\b\s*",
    re.IGNORECASE,
)
_BORDURES = " \t\"'«»()[]|:-–,."


def _designe(value: str) -> bool:
    """Un morceau de nom désigne-t-il quelqu'un ? « n8n » oui, « Email » non."""
    if _tokens(value):
        return True
    compact = re.sub(r"[^a-z0-9]+", "", _sans_accents(value))
    return len(compact) >= _MIN_SIGLE and compact not in _HABILLAGE


def relayed_organisation(display_name: str) -> str:
    """La partie du nom affiché qui porte l'organisation.

    Sans tournure de relais, le nom est rendu tel quel. Avec, c'est ce qui
    suit la dernière tournure. Quand cette partie n'est que de l'habillage
    (« Service Client Amazon via Email »), c'est ce qui précède qui compte : le
    relais ne doit pas faire perdre un nom revendiqué.
    """
    nom = display_name.strip()
    dernier = None
    for relais in _RELAIS.finditer(nom):
        if relais.start() > 0 and relais.end() < len(nom):
            dernier = relais
    if dernier is None:
        return nom
    avant = nom[: dernier.start()].strip(_BORDURES)
    apres = nom[dernier.end() :].strip(_BORDURES)
    if apres and _designe(apres):
        return apres
    return avant or nom


# Les civilités annoncent une personne, jamais une organisation.
_CIVILITES = frozenset({"dr", "m", "mme", "mlle", "mr", "mrs", "ms", "pr", "me"})
# Un mot de nom propre : des lettres, avec au besoin un trait d'union ou une
# apostrophe à l'intérieur (Dupont-Martin, O'Neil).
_MOT_NOM = re.compile(r"^[^\W\d_]+(?:[-'’][^\W\d_]+)*$")


def _majuscules(mot: str) -> bool:
    lettres = [char for char in mot if char.isalpha()]
    return len(lettres) >= 2 and all(char.isupper() for char in lettres)


def _capitale(mot: str) -> bool:
    lettres = [char for char in mot if char.isalpha()]
    return (
        len(lettres) >= 2
        and lettres[0].isupper()
        and all(char.islower() for char in lettres[1:])
    )


def names_a_person(display_name: str, from_address: str = "") -> bool:
    """Le nom affiché a-t-il la forme d'un nom de personne ?

    Une personne n'a pas de domaine officiel : la chercher comme une
    organisation rend le site d'un homonyme, et le domaine réel passe pour
    usurpateur (« Philippe DUVAL » et philduval.com, « Paige B » et
    paige.ai). Sans lexique de prénoms, on ne retient que des formes qui ne
    trompent guère, et le doute laisse le nom être cherché :

    - une civilité suivie de deux ou trois mots : « Dr. Daniel Foster ». Un
      seul mot après elle fait souvent une marque (« Dr. Martens », « Mr
      Bricolage ») ;
    - deux mots, l'un en capitales (quatre lettres au moins) et l'autre à
      capitale initiale : la convention française « BOURGEOIS Muriel »,
      « Sophie BLET ». À trois lettres ou moins, les capitales font un sigle
      (« Cession PME », « HP Online Store »), et à trois mots un intitulé
      (« USPS Customer Care », « NASA Space Apps ») ;
    - un prénom suivi d'une initiale : « Paige B » ;
    - une adresse d'envoi qui sépare les mots du nom : « sophia.wong@ » pour
      « Sophia Wong ». Un seul mot ne suffit pas : « Pharmacie@ » et « uber@ »
      sont des marques, et les montages s'en servent ;
    - une adresse d'entreprise qui colle l'initiale de l'un au nom entier de
      l'autre : « elambertini@ » pour « Eva Lambertini », « durandj@ » pour
      « Jean Durand ». Le nom entier compte au moins quatre lettres.

    « Muriel Bourgeois » seul ne se distingue pas de « Grandir Ensemble » : il
    reste cherché, et c'est le filtre des domaines officiels qui l'empêche de
    prêter le site d'un homonyme.
    """
    mots = display_name.split()
    if 3 <= len(mots) <= 4 and mots[0].rstrip(".").casefold() in _CIVILITES:
        return all(_MOT_NOM.match(mot.rstrip(".")) for mot in mots[1:])
    if not 2 <= len(mots) <= 3 or not all(_MOT_NOM.match(mot) for mot in mots):
        return False
    if any(_sans_accents(mot) in _HABILLAGE for mot in mots):
        return False
    if len(mots) == 2:
        premier, second = mots
        for nom, prenom in ((premier, second), (second, premier)):
            if _majuscules(nom) and len(nom) > _MIN_SIGLE and _capitale(prenom):
                return True
        if _capitale(premier) and len(second.rstrip(".")) == 1 and second[0].isupper():
            return True
    return _adresse_du_nom(mots, from_address)


def _adresse_du_nom(mots: list[str], from_address: str) -> bool:
    """La partie locale de l'adresse écrit-elle chacun des mots du nom, séparés ?

    « philippe.duval@ » pour « Philippe Duval » : une personne sépare ses
    noms. « DashCam@ » pour « Dash Cam » ne compte pas : une marque les colle.
    """
    adresse = str(from_address or "")
    if "@" not in adresse:
        return False
    local = _sans_accents(adresse.rsplit("@", 1)[0])
    noms = {
        morceau
        for mot in mots
        for morceau in re.split(r"[-'’]", _sans_accents(mot))
        if morceau
    }
    segments = {segment for segment in re.split(r"[^a-z]+", local) if segment}
    if len(noms) >= 2 and noms <= segments:
        return True
    # M-e36c20 : « Eva Lambertini <elambertini@prestataire.example> », cherchée
    # comme une organisation, n'avait aucun rapport public avec son employeur.
    mots_simples = [_sans_accents(mot) for mot in mots]
    if len(mots_simples) != 2 or not all(mot.isalpha() for mot in mots_simples):
        return False
    premier, second = mots_simples
    formes = {
        forme
        for initiale, nom in ((premier[0], second), (second[0], premier))
        if len(nom) >= 4
        for forme in (initiale + nom, nom + initiale)
    }
    return bool(formes & segments)


RELATION_PROMPT = """Tu compares deux choses : le nom qu'un message affiche
comme expéditeur, et le domaine depuis lequel il a réellement été envoyé.

On te donne, pour chacun, ce qu'une recherche sur Internet vient de rendre.
Tu ne juges pas le message, tu ne dis pas s'il est dangereux : tu dis seulement
si ce nom et ce domaine ont un rapport.

Réponds uniquement par cet objet JSON :
{"rapport": true, "organisation": "l'organisation que le nom désigne, ou une chaîne vide", "explication": "une phrase courte et concrète"}

rapport=true dès qu'un lien existe ou reste plausible : même organisation,
filiale, marque commerciale, prestataire d'envoi, domaine régional, ancien nom,
abréviation. Une plateforme d'emailing connue qui envoie pour son client a un
rapport.

rapport=false dans deux cas. Le premier : les deux recherches décrivent des
activités manifestement étrangères l'une à l'autre - une école de langue qui
écrit au nom d'un service de streaming, un garage au nom d'une banque.

Le second : on te donne les domaines officiels de l'organisation, le domaine
qui a écrit n'en fait pas partie, et rien dans ce qui t'est donné n'explique
pourquoi. Un domaine qui accole le nom de l'organisation à un autre mot -
« marque-offres.fr », « marque-securite.com » - n'est pas une explication :
c'est le procédé même du montage. Une explication serait de lire, dans les
extraits, que ce domaine est son prestataire, sa filiale ou son ancien nom.

rapport=null si les recherches ne disent rien d'exploitable, ou si le nom
n'est qu'un intitulé générique. Dans le doute, réponds null : ne jamais
affirmer une absence de rapport qu'on ne lit pas dans ce qui est donné."""


def _extraits(results: list[dict[str, Any]], limite: int = 4) -> str:
    lignes = []
    for item in results[:limite]:
        titre = str(item.get("title") or "").strip()[:120]
        contenu = str(item.get("content") or "").strip()[:300]
        url = str(item.get("url") or "").strip()[:120]
        if titre or contenu:
            lignes.append(f"- {titre} ({url}) : {contenu}")
    return "\n".join(lignes) or "(rien trouvé)"


def relation_question(
    *,
    display_name: str,
    from_apex: str,
    sur_le_nom: list[dict[str, Any]],
    sur_le_domaine: list[dict[str, Any]],
    official_apexes: list[str] | None = None,
) -> str:
    """Les deux noms, ce que la recherche en dit, et les domaines qu'elle prête.

    Cette dernière ligne manquait, et le juge s'en passait mal : la recherche
    rendait « doctolib.fr » pour le nom « Doctolib » sans que rien ne le lui
    dise, et il tenait « doctolib-offres.fr » pour un domaine de l'enseigne.
    """
    question = (
        "NOM AFFICHÉ PAR LE MESSAGE :\n"
        + display_name.strip()
        + "\n\nCE QUE LA RECHERCHE DIT DE CE NOM :\n"
        + _extraits(sur_le_nom)
        + "\n\nDOMAINE QUI A ENVOYÉ LE MESSAGE :\n"
        + from_apex.strip()
        + "\n\nCE QUE LA RECHERCHE DIT DE CE DOMAINE :\n"
        + _extraits(sur_le_domaine)
    )
    cites = [str(apex) for apex in (official_apexes or [])][:5]
    if cites:
        question += (
            "\n\nDOMAINES OFFICIELS TROUVÉS POUR CE NOM :\n"
            + ", ".join(cites)
            + f"\n(le message vient de {from_apex.strip()}, qui n’en fait pas partie)"
        )
    return question


def relation_clue(
    response: Any,
    *,
    display_name: str,
    from_apex: str,
    official_apexes: list[str],
    searched: bool,
    from_domain: str = "",
) -> dict[str, object] | None:
    """L'indice tiré du jugement, ou rien.

    Rien quand le rapport existe, quand le modèle ne peut pas dire, quand il
    répond hors format, ou quand il se tait : une absence de réponse n'accuse
    personne. L'article dépend de ce sur quoi le jugement a pu s'appuyer -
    des sources trouvées, ou le seul rapprochement des deux noms.
    """
    if not isinstance(response, dict):
        return None
    if response.get("rapport") is not False:
        return None
    if not official_apexes:
        # Sans domaine officiel trouvé pour ce nom, l'absence de rapport n'est
        # qu'une impression : une petite entreprise peu référencée n'a pas à
        # payer le silence des moteurs. C'est ce silence qui accusait
        # « Grange Immobilier » depuis grange-immo.fr.
        return None
    organisation = str(response.get("organisation") or "").strip()[:80] or display_name.strip()[:80]
    explication = str(response.get("explication") or "").strip()[:400]
    cites = [apex for apex in official_apexes][:3]
    etaye = bool(searched and cites)
    # Le constat mécanique - un domaine qui accole le nom d'un domaine officiel
    # - se rend ailleurs, à pleine force. Celui-ci repose sur la lecture que le
    # modèle fait de deux recherches, et il se trompe encore : il a tenu
    # « Groupe Banque Populaire » écrivant depuis son routeur d'emailing pour
    # une usurpation. Il pèse donc moins qu'une preuve, le temps de l'observer
    # sur du courrier réel.
    return {
        "clue_code": (
            "IDENTITY_CLAIMED_ORGANISATION_REFUTED"
            if etaye
            else "IDENTITY_CLAIMED_ORGANISATION_UNRELATED"
        ),
        "article_code": "DEEP-022" if etaye else "DEEP-021",
        "direction": "adverse",
        "strength": 50 if etaye else 45,
        "confidence": 0.75 if etaye else 0.7,
        "statement": (
            f"Le message se présente au nom de {organisation}, mais il est "
            f"envoyé depuis un domaine qui ne lui appartient pas. " + explication
        ).strip(),
        "facts": {
            "from_apex": from_apex,
            "from_domain": from_domain or from_apex,
            "claimed_organisation": organisation,
            "explication": explication,
            "official_apexes": cites,
            "verified_by": "search" if etaye else "model",
        },
    }
