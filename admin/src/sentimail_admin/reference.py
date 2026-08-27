"""La référence courte d'un dossier : ce qu'on cite quand on en parle.

Un identifiant interne est un UUID : personne ne le lit à voix haute, personne
ne le recopie dans un échange, et un objet dont on ne peut pas parler ne peut
pas être instruit. La console nomme donc chaque dossier par une référence
courte, tenue par une lettre qui dit de quoi il s'agit et six caractères qui
disent lequel.

Elle est **dérivée** de l'identifiant, jamais stockée : rien à migrer, rien à
maintenir, et la même référence désigne le même dossier sur n'importe quelle
copie de la base. Elle n'est pas un secret - elle situe, elle ne protège rien -
et six caractères hexadécimaux suffisent à distinguer les quelques milliers de
dossiers qu'une console montre, la lettre écartant déjà les autres familles.

Familles :

- ``M-`` un message capté ;
- ``E-`` un écart entre un jugement humain et un verdict ;
- ``D-`` un récapitulatif envoyé par courrier. Celui-là est tiré au sort à
  l'envoi (il vit dans la lettre, pas dans une table) et n'a donc pas de page
  dans la console ; il est reconnu ici pour pouvoir le dire plutôt que de
  renvoyer une erreur.
"""

from __future__ import annotations

import re

# Six caractères : assez pour désigner sans ambiguïté à l'échelle d'une
# console, assez court pour être dicté.
LONGUEUR = 6

FAMILLES: dict[str, str] = {
    "M": "message",
    "E": "écart",
    "D": "récapitulatif",
}

_REFERENCE = re.compile(r"^\s*([MED])[-\s]?([0-9a-f]{%d})\s*$" % LONGUEUR, re.IGNORECASE)


def reference(famille: str, identifiant: object) -> str:
    """La référence d'un dossier, à partir de son identifiant interne.

    L'identifiant peut arriver sous n'importe quelle forme textuelle d'UUID :
    seuls ses caractères hexadécimaux comptent, dans l'ordre.
    """
    brut = re.sub(r"[^0-9a-f]", "", str(identifiant or "").lower())
    if len(brut) < LONGUEUR:
        return ""
    return f"{famille.upper()}-{brut[:LONGUEUR]}"


def lire_reference(valeur: object) -> tuple[str, str] | None:
    """Lit une référence citée à la main, et rend sa famille et son empreinte.

    Tolérante à la façon dont on la recopie - minuscules, espace au lieu du
    tiret - parce qu'elle circule dans des échanges écrits à la main. Ce qui
    n'est pas une référence rend ``None`` : la console le dit, elle ne cherche
    pas au hasard.
    """
    trouve = _REFERENCE.match(str(valeur or ""))
    if trouve is None:
        return None
    return trouve.group(1).upper(), trouve.group(2).lower()


def nommer_dossier(champs: dict[str, object]) -> dict[str, object]:
    """Ajoute au journal la référence du dossier dont la ligne parle.

    Une ligne de journal citant un UUID oblige à traduire pour la rapprocher
    d'un avis, d'une console ou d'un échange - et personne ne traduit un UUID
    de tête. L'identifiant reste, parce qu'il est exact ; la référence vient à
    côté, parce qu'elle est celle qu'on lit. Une ligne qui ne parle d'aucun
    message n'est pas touchée.
    """
    if "dossier" in champs:
        return champs
    identifiant = champs.get("message_id")
    if identifiant:
        courte = reference("M", identifiant)
        return {**champs, "dossier": courte} if courte else champs
    # Une capture SMTP parle de plusieurs dossiers à la fois : les nommer tous
    # ou aucun, jamais le premier seulement.
    lot = champs.get("message_ids")
    if isinstance(lot, (list, tuple)) and lot:
        courtes = [courte for item in lot if (courte := reference("M", item))]
        if courtes:
            return {**champs, "dossier": courtes}
    return champs
