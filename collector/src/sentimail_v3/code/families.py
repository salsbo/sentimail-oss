"""Les familles de preuve, et ce que chacune a réellement vu.

Le Code compte cent vingt-huit articles. Présentés en vrac, ils se lisent comme
une liste où dix constats d'authentification pèsent visuellement plus lourd
qu'un fichier malveillant isolé - alors que le premier décrit un seul sujet et
le second en ouvre un autre. Le jugement demandait déjà de passer les familles
en revue, mais rien ne les calculait : le modèle devait deviner à quelle
famille appartenait chaque code, et lire le silence d'une famille comme il
l'entendait.

Ce module range chaque article dans sa famille et dit, pour chacune, ce qu'elle
porte à charge, ce qu'elle porte à décharge, et si elle est muette. C'est une
grille de lecture, jamais une note : il n'y a pas de score global ici, et il ne
faut pas en fabriquer un.

Deux règles gouvernent le calcul, et toutes deux protègent de la même erreur -
prendre du volume pour de la preuve :

- la force d'une famille est le MAXIMUM de ses indices, jamais leur somme.
  Cinq broutilles ne valent pas une preuve, et les additionner fabriquerait une
  charge que personne n'a observée ;
- une famille muette ne plaide rien. « Aucune pièce jointe » n'est pas un point
  favorable, c'est une absence d'observation.

Les corrélations en sont exclues à dessein. Une convergence relie des familles
déjà présentes ; la compter comme une famille de plus ferait passer un seul
faisceau pour deux preuves indépendantes - exactement ce que la règle du
verdict dangerous cherche à exiger.
"""

from __future__ import annotations

from typing import Any

# Ni une famille, ni « autre » : ce qui traverse les familles ou ne parle pas du
# message. Une corrélation relie des observations ; une règle utilisateur dit ce
# que l'utilisateur veut, pas ce que le message est.
CROSS_CUTTING = "transverse"
UNKNOWN = "autre"

# Une famille forte, c'est une charge qu'on peut défendre seule. En dessous, un
# signal reste un signal : inviter à cliquer ou attendre une réponse ne fonde
# aucune convergence.
STRONG = 60

FAMILIES: tuple[str, ...] = (
    "identite",
    "structure",
    "reputation",
    "contenu",
    "liens",
    "pieces_jointes",
    "coherence_metier",
)

FAMILY_LABELS: dict[str, str] = {
    "identite": "Qui écrit, et est-ce prouvé",
    "structure": "Comment le message est fabriqué",
    "reputation": "Ce qu'on sait déjà de cet expéditeur",
    "contenu": "Ce que le message dit et réclame",
    "liens": "Où les liens mènent vraiment",
    "pieces_jointes": "Ce que les fichiers contiennent",
    "coherence_metier": "Si l'expéditeur exerce bien ce dont il parle",
}

# Le préfixe suffit presque toujours : il dit le sujet de l'article.
_BY_PREFIX: dict[str, str] = {
    "AUTH": "identite",
    "IDENTITY": "identite",
    "HEADER": "structure",
    "HEADERS": "structure",
    "CHAIN": "structure",
    "DATE": "structure",
    "STRUCT": "structure",
    "RSPAMD": "reputation",
    "HIST": "reputation",
    "CONTENT": "contenu",
    "NATURE": "contenu",
    "ACT": "contenu",
    "URL": "liens",
    "ATT": "pieces_jointes",
    "CORR": CROSS_CUTTING,
    "POLICY": CROSS_CUTTING,
}

# Deux préfixes ne disent pas le sujet mais l'étage qui a produit le constat.
# DEEP- couvre à lui seul la navigation, les fichiers et le métier de
# l'expéditeur ; DOMAIN- parle tantôt de l'expéditeur, tantôt de la destination
# d'un lien. Les ranger par préfixe inventerait une convergence là où un seul
# sujet est observé, ou la masquerait là où deux le sont.
_BY_ARTICLE: dict[str, str] = {
    "DEEP-004": "pieces_jointes",
    "DEEP-005": "pieces_jointes",
    "DEEP-016": "coherence_metier",
    "DEEP-018": "coherence_metier",
    "DEEP-019": "coherence_metier",
    "DEEP-021": "identite",
    "DEEP-022": "identite",
    "DOMAIN-001": "identite",
    "DOMAIN-002": "identite",
    "DOMAIN-003": "identite",
    "DOMAIN-004": "liens",
}
_DEEP_DEFAULT = "liens"


def family_of(article_code: Any) -> str:
    """La famille d'un article, ou « autre » si le Code a évolué sans lui."""
    if not isinstance(article_code, str) or not article_code:
        return UNKNOWN
    code = article_code.strip().upper()
    known = _BY_ARTICLE.get(code)
    if known is not None:
        return known
    prefix = code.split("-", 1)[0]
    if prefix == "DEEP":
        return _DEEP_DEFAULT
    return _BY_PREFIX.get(prefix, UNKNOWN)


def _empty() -> dict[str, object]:
    return {"count": 0, "max_strength": 0, "clue_codes": []}


def family_coverage(clues: Any, *, include_silent: bool = True) -> list[dict[str, object]]:
    """Ce que chaque famille a vu - y compris celles qui n'ont rien vu.

    Le jugement a besoin de lire le silence noir sur blanc, sinon il comble le
    vide. Une archive, elle, peut le déduire : le registre des familles est
    fixe, donc `include_silent=False` économise la place de cinq « rien à
    signaler » sur sept dans une vue conservée pour chaque message.
    """
    tally: dict[str, dict[str, dict[str, object]]] = {
        family: {"adverse": _empty(), "favorable": _empty()} for family in FAMILIES
    }
    for clue in clues if isinstance(clues, list) else []:
        if not isinstance(clue, dict):
            continue
        family = family_of(clue.get("article_code"))
        if family not in tally:
            continue
        direction = str(clue.get("direction") or "")
        if direction not in ("adverse", "favorable"):
            continue
        side = tally[family][direction]
        side["count"] = int(side["count"]) + 1
        try:
            strength = int(clue.get("strength") or 0)
        except (TypeError, ValueError):
            strength = 0
        # Le maximum, jamais la somme : voir l'en-tête du module.
        side["max_strength"] = max(int(side["max_strength"]), strength)
        codes = side["clue_codes"]
        code = str(clue.get("clue_code") or "")
        if isinstance(codes, list) and code and code not in codes and len(codes) < 8:
            codes.append(code)

    coverage: list[dict[str, object]] = []
    for family in FAMILIES:
        sides = tally[family]
        silent = not int(sides["adverse"]["count"]) and not int(
            sides["favorable"]["count"]
        )
        if silent and not include_silent:
            continue
        coverage.append(
            {
                "family": family,
                "subject": FAMILY_LABELS[family],
                "silent": silent,
                "adverse": sides["adverse"],
                "favorable": sides["favorable"],
            }
        )
    return coverage


def converging_families(clues: Any) -> list[str]:
    """Les familles portant une charge forte, comptées une seule fois.

    Le verdict dangerous exige une convergence d'au moins deux familles fortes
    indépendantes. Cette exigence existait dans le Code sans que rien ne la
    mesure : trois constats d'authentification pouvaient passer pour une
    convergence alors qu'ils décrivent un seul sujet.
    """
    return [
        entry["family"]
        for entry in family_coverage(clues)
        if int(entry["adverse"]["max_strength"]) >= STRONG  # type: ignore[index]
    ]
