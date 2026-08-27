"""Sépare le texte HTML rendu du texte masqué par CSS inline.

Un filtre qui lit tout le HTML lit aussi ce que le destinataire ne voit pas :
le texte injecté sous font-size:0 ou display:none dilue les termes suspects et
peut porter des instructions adressées à un juge automatique. On distingue
donc ce qui est rendu de ce qui est caché, pour juger sur le premier et
compter le second.

L'analyse porte sur le style INLINE des éléments : les clients de messagerie
n'appliquent de toute façon pas les feuilles de style externes, et c'est là
que le masquage se joue en pratique.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

_IGNORED = {"head", "style", "script", "template", "svg"}

# Les déclarations qui rendent un élément invisible. Chacune se lit sur le
# style inline ; l'héritage est géré en propageant le masque aux enfants.
_HIDE_PATTERNS = (
    re.compile(r"display\s*:\s*none", re.I),
    re.compile(r"visibility\s*:\s*hidden", re.I),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?(?:\D|$)", re.I),
    re.compile(r"font-size\s*:\s*0(?:\.0+)?(?:px|em|rem|pt)?(?:\D|$)", re.I),
    re.compile(r"font-size\s*:\s*1px", re.I),
    re.compile(r"(?:max-)?height\s*:\s*0(?:px)?(?:\D|$)", re.I),
    re.compile(r"(?:max-)?width\s*:\s*0(?:px)?(?:\D|$)", re.I),
    re.compile(r"text-indent\s*:\s*-\d", re.I),
    re.compile(r"left\s*:\s*-\d{3,}", re.I),
    re.compile(r"mso-hide\s*:\s*all", re.I),
)


def _is_hidden(style: str) -> bool:
    return any(pattern.search(style) for pattern in _HIDE_PATTERNS)


class _SplitParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._ignored_depth = 0
        # Pile de booléens : un nœud est caché s'il l'est lui-même ou hérite
        # d'un ancêtre caché.
        self._hidden_stack: list[bool] = []
        self.visible: list[str] = []
        self.hidden: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() in _IGNORED:
            self._ignored_depth += 1
            return
        style = ""
        for name, value in attrs:
            if name.casefold() == "style" and value:
                style = value
        inherited = self._hidden_stack[-1] if self._hidden_stack else False
        self._hidden_stack.append(inherited or _is_hidden(style))

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in _IGNORED:
            self._ignored_depth = max(0, self._ignored_depth - 1)
            return
        if self._hidden_stack:
            self._hidden_stack.pop()

    def handle_data(self, data: str) -> None:
        if self._ignored_depth or not data.strip():
            return
        if self._hidden_stack and self._hidden_stack[-1]:
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
