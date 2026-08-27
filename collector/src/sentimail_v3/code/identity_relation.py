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

Ce qui sort de la machine : le nom affiché et le domaine émetteur. Ni le
destinataire, ni l'objet, ni une ligne du message.
"""

from __future__ import annotations

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


def _sans_accents(value: str) -> str:
    decompose = unicodedata.normalize("NFKD", value.casefold())
    return "".join(char for char in decompose if not unicodedata.combining(char))


def _tokens(value: str) -> list[str]:
    return [
        mot
        for mot in re.split(r"[^a-z0-9]+", _sans_accents(value))
        if len(mot) >= _MIN_TOKEN and mot not in _HABILLAGE
    ]


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


def appended_to_official(from_apex: str, official_apexes: list[str]) -> str:
    """Le domaine accole-t-il le nom d'un domaine officiel sans être lui ?

    « notif-colissimo-laposte.info » face à « laposte.fr »,
    « doctolib-offres.fr » face à « doctolib.fr » : le nom y est, entier, avec
    un mot devant ou derrière. C'est le procédé le plus courant, et il se
    constate sans avis - le rendre au jugement du modèle, c'est risquer qu'il y
    voie un domaine de service de l'enseigne, ce qu'il a fait.

    Rend le domaine officiel imité, ou une chaîne vide.
    """
    label = _label(from_apex)
    if not label:
        return ""
    for apex in official_apexes:
        officiel = _label(apex)
        if not officiel or len(officiel) < _MIN_TOKEN:
            continue
        if officiel != label and officiel in label:
            return apex
    return ""


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
            "claimed_organisation": organisation,
            "explication": explication,
            "official_apexes": cites,
            "verified_by": "search" if etaye else "model",
        },
    }
