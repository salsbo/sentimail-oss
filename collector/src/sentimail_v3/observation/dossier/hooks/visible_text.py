"""Texte réellement rendu d'un corps HTML, partagé par les hooks de contenu.

Plusieurs hooks doivent lire ce que le destinataire voit, sans confondre CSS,
scripts et contenu. L'extraction vit ici pour rester unique : deux définitions
divergentes feraient juger deux textes différents pour un même message.
"""

from __future__ import annotations

from html.parser import HTMLParser

from sentimail_v3.observation.dossier.hooks.hidden_text import (
    est_du_salting,
    mots_caches_inedits,
)

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


# Garder les lignes permet de distinguer ce qui est cité. Le texte cité reste
# lu par les hooks : un hameçonnage transféré reste un hameçonnage.
_BLOCKS = frozenset(
    {
        "address", "article", "aside", "blockquote", "dd", "div", "dl", "dt",
        "fieldset", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5",
        "h6", "header", "hr", "li", "main", "nav", "ol", "p", "pre", "section",
        "table", "tbody", "td", "th", "thead", "tr", "ul",
    }
)
# Les éléments vides n'ont pas de balise fermante : les empiler laisserait la
# pile ouverte jusqu'à la fin du message.
_VOID = frozenset(
    {
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr",
    }
)
# Les conteneurs où les clients rangent le message cité. #divRplyFwdMsg
# d'Outlook web n'en est pas un : il ne porte que l'en-tête, l'original suit en
# frère. C'est sa ligne « De : », rendue seule, qui fait couper la réponse.
_QUOTE_CLASSES = frozenset(
    {"gmail_quote", "gmail_quote_container", "yahoo_quoted", "protonmail_quote"}
)
_QUOTE_IDS = frozenset({"mail-editor-reference-message-container"})
# Un téléphone glisse parfois un caractère invisible avant la réponse : il ne
# doit pas empêcher de reconnaître une lettre seule sur sa ligne.
_INVISIBLES = dict.fromkeys(map(ord, "​‌‍⁠﻿"))
_REPLY_LIMIT = 200_000


def _quote_container(tag: str, attrs: list[tuple[str, str | None]]) -> bool:
    if tag == "blockquote":
        return True
    values = {name.casefold(): value or "" for name, value in attrs}
    if set(values.get("class", "").split()) & _QUOTE_CLASSES:
        return True
    return values.get("id", "").casefold() in _QUOTE_IDS


class _ReplyTextParser(HTMLParser):
    """Rend chaque bloc en ligne et préfixe de « > » ce qui est cité."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._ignored_depth = 0
        self._open: list[tuple[str, bool]] = []
        self._quote_depth = 0
        self._fragments: list[str] = []
        self._line_depth: int | None = None
        self.lines: list[str] = []

    def end_line(self) -> None:
        text = " ".join("".join(self._fragments).replace("\xa0", " ").split())
        if text:
            self.lines.append("> " * (self._line_depth or 0) + text)
        self._fragments = []
        self._line_depth = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        if tag in _IGNORED:
            self._ignored_depth += 1
            return
        if self._ignored_depth:
            return
        if tag in _VOID:
            if tag == "br" or tag in _BLOCKS:
                self.end_line()
            return
        quote = _quote_container(tag, attrs)
        if tag in _BLOCKS or quote:
            self.end_line()
        self._open.append((tag, quote))
        if quote:
            self._quote_depth += 1

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag in _IGNORED:
            self._ignored_depth = max(0, self._ignored_depth - 1)
            return
        if self._ignored_depth:
            return
        # On dépile jusqu'à l'ouvrante : des inline laissés ouverts dedans sont
        # tolérés. Une fermante sans ouvrante ne ferme rien.
        for index in range(len(self._open) - 1, -1, -1):
            if self._open[index][0] != tag:
                continue
            closed = self._open[index:]
            del self._open[index:]
            if any(name in _BLOCKS or quote for name, quote in closed):
                self.end_line()
            self._quote_depth -= sum(1 for _, quote in closed if quote)
            return

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        data = data.translate(_INVISIBLES)
        # Le niveau d'une ligne est celui de son premier texte. Un texte qui
        # change de niveau en cours de ligne en commence une autre : une ligne
        # ne peut pas être à moitié citée.
        if data.strip():
            if self._line_depth is None:
                self._line_depth = self._quote_depth
            elif self._line_depth != self._quote_depth:
                self.end_line()
                self._line_depth = self._quote_depth
        self._fragments.append(data)


def reply_html_text(html: str) -> str:
    """Le texte d'une réponse HTML, ligne par ligne, citation marquée « > ».

    Rendu d'un bloc, le texte d'une réponse iPhone et l'avis qu'elle cite
    tenaient sur une seule ligne : la découpe de la citation, qui lit ligne à
    ligne, n'y trouvait rien (M-d8df0e, 28 septembre 2026). Marquer plutôt que
    retirer laisse lire les cases cochées dans la citation d'un récapitulatif.
    """
    parser = _ReplyTextParser()
    try:
        parser.feed(html[:_REPLY_LIMIT])
        parser.close()
        parser.end_line()
    except Exception:  # noqa: BLE001 - une réponse illisible reste sans texte
        return ""
    return "\n".join(parser.lines)


def _rendu_quand_le_html_cache_le_brut(html: str) -> str | None:
    """Le texte rendu du HTML, quand il cache ce que le text/plain dit (CONTENT-013).

    Le text/plain est alors la copie en clair de ce que le destinataire ne voit
    pas : le lui faire lire au juge, c'est lui faire juger un autre message. Le
    30 octobre 2026 il a pris pour une lettre d'information technique un HTML
    qui ne rendait que « 616 » et un lien (M-96852d). None : le texte brut est
    fidèle, ou il n'y a rien à rendre.
    """
    if not html.strip():
        return None
    rendu, _, inedits = mots_caches_inedits(html)
    if est_du_salting(inedits, len(visible_html_text(html).strip())) and rendu.strip():
        return rendu.strip()
    return None


def readable_text(body_text: str | None, body_html: str | None) -> tuple[str, str]:
    """Le texte que le destinataire lit, et d'où il vient.

    Le 16 septembre 2026, un faux reçu en HTML seul a été livré à 0,95 : son
    `body_text` était NULL, le juge et les enquêteurs profonds ont donc reçu un
    corps vide, et seul le hook contenu avait lu le HTML. Trois lecteurs d'un
    même message ne doivent pas lire trois textes différents : celui-ci est le
    seul point de départ. La source rend la provenance vérifiable au dossier.
    """
    plain = str(body_text or "").strip()
    if plain:
        rendu = _rendu_quand_le_html_cache_le_brut(str(body_html or ""))
        if rendu is None:
            return plain, "text/plain"
        return rendu, "html_visible_text"
    visible = reply_html_text(str(body_html or "")).strip()
    if visible:
        return visible, "html_visible_text"
    return "", "none"
