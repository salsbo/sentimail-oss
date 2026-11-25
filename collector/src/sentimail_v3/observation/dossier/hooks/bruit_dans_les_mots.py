"""Les signes glissés à l'intérieur d'un mot pour qu'il ne se cherche plus.

« com´mands », « T´ermius », « A′̍meli » se lisent comme le mot ordinaire, mais
un filtre qui cherche « commands » ou « Améli » ne les trouve pas. Le
déguisement n'est ni une écriture étrangère (CONTENT-012) ni un invisible
(CONTENT-004) : c'est un accent aigu, une prime, un modificateur ou une marque
combinante qu'aucune lettre voisine ne peut porter.

Deux usages ordinaires ne sont jamais relevés. Les mails écrits sur macOS
portent des accents en deux codepoints : le texte passe d'abord en NFC, où ils
se recomposent, et seules les marques restées orphelines comptent. Et
l'apostrophe tapée avec un accent aigu (« l´été », « aujourd´hui », « don´t »)
n'est pas une coupure : une seule lettre, ou une contraction connue, de part et
d'autre du signe.
"""

from __future__ import annotations

import re
import unicodedata

# Accent aigu et accent grave isolés, modificateurs espacés (sauf les
# apostrophes U+02BB, U+02BC), primes, marques combinantes.
_BRUIT = "´`ʰ-ʺʽ-˿′-‷̀-ͯ"
_LETTRE = r"[^\W\d_]"
_MOT = re.compile(rf"{_LETTRE}+(?:[{_BRUIT}]+{_LETTRE}+)+")
_SEGMENTS = re.compile(rf"([{_BRUIT}]+)")

# Avant le signe : l'élision française. Après : la contraction anglaise.
_AVANT_ELISION = frozenset(
    {"l", "d", "j", "m", "t", "s", "n", "c", "qu", "jusqu", "lorsqu", "puisqu", "quoiqu"}
)
_APRES_CONTRACTION = frozenset({"s", "t", "re", "ll", "ve", "d", "m"})


def _est_marque_orpheline(char: str) -> bool:
    return unicodedata.category(char) == "Mn"


def _est_apostrophe(avant: str, signe: str, apres: str) -> bool:
    """Vrai quand le signe tient lieu d'apostrophe : élision ou contraction."""
    if len(signe) != 1 or signe not in "´`′":
        return False
    gauche, droite = avant.casefold(), apres.casefold()
    if gauche in _AVANT_ELISION or droite in _APRES_CONTRACTION:
        return True
    return gauche == "aujourd" and droite.startswith("hui")


# Sous ce nombre de coupures franches, une élision à une lettre (« l´été ») reste
# une apostrophe. Au-dessus, « T´ermius » et « t´ime » sont de la même main que
# « com´mands » : le texte entier est cassé, pas une apostrophe maladroite.
_SEUIL_CONTEXTE = 3


def _coupures(mot: str) -> tuple[list[int], list[int]]:
    """Les positions des signes qui coupent : (franches, ambiguës)."""
    segments = _SEGMENTS.split(mot)
    franches: list[int] = []
    ambigues: list[int] = []
    for index in range(1, len(segments), 2):
        signe = segments[index]
        avant, apres = segments[index - 1], segments[index + 1]
        if any(_est_marque_orpheline(char) for char in signe):
            franches.append(index)
        elif _est_apostrophe(avant, signe, apres):
            ambigues.append(index)
        else:
            franches.append(index)
    return franches, ambigues


def _analyser(texte: str) -> list[tuple[re.Match[str], list[int], list[int]]]:
    """Les mots coupés, avec leurs coupures franches, puis ambiguës retenues."""
    trouves = []
    for correspondance in _MOT.finditer(texte):
        franches, ambigues = _coupures(correspondance.group(0))
        if franches or ambigues:
            trouves.append((correspondance, franches, ambigues))
    contexte = sum(1 for _, franches, _ in trouves if franches) >= _SEUIL_CONTEXTE
    return [
        (correspondance, franches, ambigues if contexte else [])
        for correspondance, franches, ambigues in trouves
        if franches or (contexte and ambigues)
    ]


def mots_bruites(sample: str) -> list[dict[str, object]]:
    """Les mots coupés à l'intérieur par un signe qui n'est pas une apostrophe."""
    releves: list[dict[str, object]] = []
    texte = unicodedata.normalize("NFC", sample)
    for correspondance, franches, ambigues in _analyser(texte):
        segments = _SEGMENTS.split(correspondance.group(0))
        signes = [segments[index] for index in franches + ambigues]
        releves.append(
            {
                "word": correspondance.group(0)[:40],
                "orphan_mark": any(
                    _est_marque_orpheline(char) for signe in signes for char in signe
                ),
                "offset": correspondance.start(),
            }
        )
        if len(releves) >= 40:
            break
    return releves


def sans_bruit(sample: str) -> str:
    """Le texte une fois les signes parasites retirés, pour le chercher et le lire."""
    texte = unicodedata.normalize("NFC", sample)
    morceaux: list[str] = []
    fin = 0
    for correspondance, franches, ambigues in _analyser(texte):
        segments = _SEGMENTS.split(correspondance.group(0))
        for index in franches + ambigues:
            segments[index] = ""
        morceaux.append(texte[fin : correspondance.start()])
        morceaux.append("".join(segments))
        fin = correspondance.end()
    morceaux.append(texte[fin:])
    return "".join(morceaux)
