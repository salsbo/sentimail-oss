"""Contrat du texte lisible partagé par le jugement et les revues humaines."""

from __future__ import annotations

from sentimail_v3.observation.dossier.hooks.visible_text import readable_text

VISIBLE_CONTENT_VERSION = "sentimail-visible-content-1"
MAX_VISIBLE_CONTENT_CHARS = 20_000


def build_visible_content(body_text: str | None, body_html: str | None) -> dict[str, object]:
    """Fige le rendu à la capture ; sa version ne réécrit jamais un ancien message."""
    text, source = readable_text(body_text, body_html)
    return {
        "version": VISIBLE_CONTENT_VERSION,
        "text": text[:MAX_VISIBLE_CONTENT_CHARS],
        "source": source,
        "truncated": len(text) > MAX_VISIBLE_CONTENT_CHARS,
    }
