"""Sépare le texte HTML rendu du texte masqué par CSS inline.

Un filtre qui lit tout le HTML lit aussi ce que le destinataire ne voit pas :
le texte injecté sous font-size:0 ou display:none dilue les termes suspects et
peut porter des instructions adressées à un juge automatique. On distingue
donc ce qui est rendu de ce qui est caché, pour juger sur le premier et
compter le second.

L'analyse porte sur le style INLINE des éléments : les clients de messagerie
n'appliquent de toute façon pas les feuilles de style externes, et c'est là
que le masquage se joue en pratique.

Toutes les déclarations masquantes ne se transmettent pas de la même façon, et
les confondre a coûté un mail authentique. Un conteneur en `display:none` ne
rend aucun de ses descendants : le masque vaut pour tout le sous-arbre, sans
recours. Un conteneur en `font-size:0` ne fait qu'imposer une valeur héritée,
qu'un enfant redéfinit librement - et c'est précisément ce que fait MJML, qui
pose `font-size:0px` sur chaque cellule de section pour supprimer l'espace
entre colonnes inline-block, puis rétablit une taille lisible sur le texte.
Propager ce masque sans jamais le lever comptait le corps entier d'un message
comme caché : le 1er septembre 2026, une notification Anthropic parfaitement
authentique offrait ainsi 604 caractères « masqués » pour zéro visible.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import NamedTuple

_IGNORED = {"head", "style", "script", "template", "svg"}

# Ce qui retire l'élément et tout son sous-arbre du rendu. Aucun enfant ne
# peut en revenir : le masque se propage sans condition.
_STRUCTURAL_HIDE = (
    # Le nom de la propriété est ancré : « line-height:0 » (Mailchimp le pose sur
    # des paragraphes qui portent le texte), « min-height:0 » ou
    # « margin-left:-300px » ne retirent rien du rendu.
    re.compile(r"(?<![\w-])display\s*:\s*none", re.I),
    re.compile(r"(?<![\w-])opacity\s*:\s*0(?:\.0+)?(?:\D|$)", re.I),
    re.compile(r"(?<![\w-])(?:max-)?height\s*:\s*0(?:px)?(?:\D|$)", re.I),
    re.compile(r"(?<![\w-])(?:max-)?width\s*:\s*0(?:px)?(?:\D|$)", re.I),
    re.compile(r"(?<![\w-])left\s*:\s*-\d{3,}", re.I),
    re.compile(r"(?<![\w-])mso-hide\s*:\s*all", re.I),
)

# Les propriétés héritées : la valeur d'un ancêtre s'applique à défaut, mais
# toute redéclaration chez un descendant la remplace. On lit donc la valeur
# déclarée par l'élément lui-même, et on ne retombe sur celle de l'ancêtre que
# s'il n'en déclare aucune.
_DECLARED_FONT_SIZE = re.compile(r"font-size\s*:\s*([^;]+)", re.I)
_DECLARED_VISIBILITY = re.compile(r"visibility\s*:\s*([^;]+)", re.I)
_DECLARED_TEXT_INDENT = re.compile(r"text-indent\s*:\s*([^;]+)", re.I)

_ILLISIBLE_FONT_SIZE = re.compile(r"^\s*(?:0(?:\.0+)?(?:px|em|rem|pt|%)?|1px)\s*$", re.I)
_INVISIBLE_VISIBILITY = re.compile(r"^\s*(?:hidden|collapse)\s*$", re.I)
_HORS_ECRAN_INDENT = re.compile(r"^\s*-\d{3,}", re.I)

# Couleur de texte et fond. Le fond ne s'hérite pas en CSS, mais ce qui est
# peint derrière le texte est le fond du plus proche ancêtre qui en pose un :
# on propage donc le dernier fond déclaré, faute de quoi le fond par défaut
# d'un client mail est clair (blanc). « color » ne doit pas attraper
# « background-color » ni « border-color » : on l'ancre en début de
# déclaration.
_DECLARED_COLOR = re.compile(r"(?:^|;)\s*color\s*:\s*([^;]+)", re.I)
_DECLARED_BACKGROUND = re.compile(r"background(?:-color)?\s*:\s*([^;]+)", re.I)
# Un fond en image : le texte n'est pas posé sur une teinte unie, on ne conclut
# pas au blanc sur blanc.
_FOND_IMAGE = re.compile(r"background[\w-]*\s*:\s*[^;]*url\(", re.I)
_FOND_TRANSPARENT = ("transparent", "none", "inherit", "initial", "unset")

_NOMS_CLAIRS = {
    "white", "whitesmoke", "snow", "ivory", "floralwhite", "ghostwhite",
    "azure", "mintcream", "honeydew", "aliceblue", "seashell", "oldlace",
    "linen", "beige", "cornsilk",
}


def _rgb(valeur: str) -> tuple[int, int, int] | None:
    """Les canaux RGB d'une couleur CSS simple, ou None si illisible/complexe."""
    v = valeur.strip().lower()
    if "url(" in v:
        return None
    if v in _NOMS_CLAIRS:
        return (255, 255, 255)
    m = re.fullmatch(r"#([0-9a-f]{3})", v)
    if m:
        return tuple(int(c * 2, 16) for c in m.group(1))  # type: ignore[return-value]
    m = re.fullmatch(r"#([0-9a-f]{6})", v)
    if m:
        h = m.group(1)
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    m = re.match(r"rgba?\(\s*(\d+)\D+(\d+)\D+(\d+)", v)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return None


def _clair(valeur: str | None) -> bool:
    """La couleur est-elle si proche du blanc qu'un texte y disparaît ?"""
    if valeur is None:
        return False
    rgb = _rgb(valeur)
    # Seuil haut : on ne vise que le quasi-blanc (blanc sur blanc, gris très
    # clair de preheader), pas un gris moyen lisible.
    return rgb is not None and min(rgb) >= 0xDD


def _couleur_declaree(style: str, regex: re.Pattern[str]) -> str | None:
    trouve = regex.search(style)
    if trouve is None:
        return None
    return trouve.group(1).strip().lower() or None


class _Masque(NamedTuple):
    """L'état de visibilité d'un nœud, propriété par propriété."""

    structurel: bool
    police: bool
    visibilite: bool
    retrait: bool
    couleur: str | None
    fond: str | None

    @property
    def _blanc_sur_blanc(self) -> bool:
        """Texte quasi blanc posé sur un fond quasi blanc : illisible.

        On n'y voit un masque que si une couleur de texte claire a été
        déclarée. Sans couleur déclarée, le texte est sombre par défaut et
        reste visible. Un texte blanc sur un bouton coloré ne tombe pas ici :
        le fond effectif est alors la teinte du bouton, pas le blanc.
        """
        if self.couleur is None:
            return False
        fond = self.fond if self.fond is not None else "#ffffff"
        return _clair(self.couleur) and _clair(fond)

    @property
    def cache(self) -> bool:
        return (
            self.structurel
            or self.police
            or self.visibilite
            or self.retrait
            or self._blanc_sur_blanc
        )


_VISIBLE = _Masque(False, False, False, False, None, None)


def _herite(parent: _Masque, style: str) -> _Masque:
    """Le masque d'un enfant : hérité, sauf là où il redéclare la propriété."""
    couleur_declaree = _couleur_declaree(style, _DECLARED_COLOR)
    couleur = couleur_declaree if couleur_declaree is not None else parent.couleur
    if _FOND_IMAGE.search(style):
        fond: str | None = "url()"
    else:
        fond_declare = _couleur_declaree(style, _DECLARED_BACKGROUND)
        if fond_declare is None or any(t in fond_declare for t in _FOND_TRANSPARENT):
            fond = parent.fond
        else:
            fond = fond_declare
    if parent.structurel or any(motif.search(style) for motif in _STRUCTURAL_HIDE):
        return _Masque(
            True, parent.police, parent.visibilite, parent.retrait, couleur, fond
        )
    return _Masque(
        False,
        _declaree(style, _DECLARED_FONT_SIZE, _ILLISIBLE_FONT_SIZE, parent.police),
        _declaree(
            style, _DECLARED_VISIBILITY, _INVISIBLE_VISIBILITY, parent.visibilite
        ),
        _declaree(style, _DECLARED_TEXT_INDENT, _HORS_ECRAN_INDENT, parent.retrait),
        couleur,
        fond,
    )


def _declaree(
    style: str, declaration: re.Pattern[str], masquante: re.Pattern[str], herite: bool
) -> bool:
    """La valeur portée par l'élément, ou celle de son ancêtre à défaut."""
    trouvee = declaration.search(style)
    if trouvee is None:
        return herite
    return bool(masquante.match(trouvee.group(1)))


def _is_hidden(style: str) -> bool:
    """Un style inline masque-t-il, à lui seul, le texte qu'il porte ?"""
    return _herite(_VISIBLE, style).cache


class _SplitParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._ignored_depth = 0
        # Pile des masques : un nœud hérite de celui de son parent, propriété
        # par propriété, et peut en lever la part héritable.
        self._hidden_stack: list[_Masque] = []
        self.visible: list[str] = []
        self.hidden: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() in _IGNORED:
            self._ignored_depth += 1
            return
        style = ""
        fond_attribut = ""
        for name, value in attrs:
            attr = name.casefold()
            if attr == "style" and value:
                style = value
            elif attr == "bgcolor" and value:
                # Les gabarits mail colorent souvent une cellule par l'attribut
                # bgcolor, pas par CSS : sans le lire, un texte blanc sur en-tête
                # coloré passerait pour blanc sur blanc.
                fond_attribut = f";background-color:{value}"
            elif attr == "background" and value:
                fond_attribut = f";background-image:url({value})"
        parent = self._hidden_stack[-1] if self._hidden_stack else _VISIBLE
        # Le style inline prime : l'attribut est ajouté après, donc la première
        # déclaration lue (celle du style) l'emporte.
        self._hidden_stack.append(_herite(parent, style + fond_attribut))

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in _IGNORED:
            self._ignored_depth = max(0, self._ignored_depth - 1)
            return
        if self._hidden_stack:
            self._hidden_stack.pop()

    def handle_data(self, data: str) -> None:
        if self._ignored_depth or not data.strip():
            return
        if self._hidden_stack and self._hidden_stack[-1].cache:
            self.hidden.append(data)
        else:
            self.visible.append(data)


def split_visible_hidden(html: str) -> tuple[str, str]:
    """Retourne (texte visible, texte masqué par CSS) d'un corps HTML."""
    parser = _SplitParser()
    try:
        parser.feed((html or "")[:200_000])
        parser.close()
    except Exception:  # noqa: BLE001 - garder un résultat partiel plutôt que rien
        pass
    return " ".join(parser.visible), " ".join(parser.hidden)


# Découpage en mots pour comparer le vocabulaire caché au vocabulaire rendu :
# \w+ Unicode, insensible à la casse.
_MOT = re.compile(r"\w+", re.UNICODE)

# Le texte caché n'est du « salting » qu'au-delà de ce volume inédit, et de
# cette part du texte réellement lu.
SEUIL_CACHE_INEDIT = 200
SEUIL_CACHE_RATIO = 0.2


def mots_caches_inedits(html: str) -> tuple[str, str, int]:
    """(texte rendu, texte masqué, caractères masqués absents du texte rendu).

    Le vocabulaire inédit se mesure contre le HTML rendu seul. La partie
    text/plain n'est pas un texte lu : le destinataire ouvre le HTML, et le
    30 octobre 2026 une arnaque a répété en clair dans le text/plain tout ce
    que son HTML cachait (M-96852d), ce qui effaçait l'inédit. Un gabarit
    responsive, lui, répète le texte RENDU dans son bloc masqué : il reste
    écarté, puisque ce vocabulaire-là figure dans le HTML rendu.
    """
    visible, masque = split_visible_hidden(html)
    connus = {mot.casefold() for mot in _MOT.findall(visible)}
    inedits = sum(
        len(mot) for mot in _MOT.findall(masque) if mot.casefold() not in connus
    )
    return visible, masque, inedits


def est_du_salting(inedits: int, visible_chars: int) -> bool:
    return inedits >= SEUIL_CACHE_INEDIT and inedits / (visible_chars or 1) >= SEUIL_CACHE_RATIO

