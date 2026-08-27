"""Texte réellement rendu d'un corps HTML, partagé par les hooks de contenu.

Plusieurs hooks doivent lire ce que le destinataire voit, sans confondre CSS,
scripts et contenu. L'extraction vit ici pour rester unique : deux définitions
divergentes feraient juger deux textes différents pour un même message.
"""

from __future__ import annotations

from html.parser import HTMLParser

_IGNORED = {"head", "style", "script", "template", "svg"}


class _VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._ignored_depth = 0
        self.values: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag.casefold() in _IGNORED:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in _IGNORED:
            self._ignored_depth = max(0, self._ignored_depth - 1)

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth and data.strip():
            self.values.append(data)


def visible_html_text(html: str) -> str:
    parser = _VisibleTextParser()
    try:
        parser.feed(html[:200_000])
        parser.close()
    except Exception:  # noqa: BLE001 - les autres hooks gardent les défauts HTML
        return ""
    return " ".join(parser.values)
