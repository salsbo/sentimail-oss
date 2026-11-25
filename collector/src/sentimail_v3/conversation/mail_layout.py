"""Mise en page minimale partagée par les courriers HTML de MAIA (V2).

Une seule colonne centrée (560 px maximum), fond blanc, typographie système,
chasse fixe pour les adresses et références, filets discrets (#e2e8f0).
Aucun tableau HTML : le rendu reste identique sur ordinateur et téléphone.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from html import escape

from sentimail_v3.observation.risk_text import neutralize_excerpt_links

_HEX_COLOR = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")


def _check_color(value: str) -> str:
    if not _HEX_COLOR.match(value or ""):
        raise ValueError(f"couleur refusée : {value[:32]!r}")
    return value

FONT_SANS = (
    "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
)
FONT_MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"


def wrap_shell(inner: str, *, full_document: bool = False) -> str:
    """Enveloppe le contenu dans la colonne unique V2."""
    container = (
        f'<div style="font-family:{FONT_SANS};max-width:560px;margin:0 auto;'
        "background:#ffffff;color:#0f172a;font-size:14px;line-height:1.5;"
        f'padding:20px 16px;box-sizing:border-box">{inner}</div>'
    )
    if not full_document:
        return container
    return (
        '<!doctype html><html lang="fr"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '</head><body style="margin:0;padding:0;background:#ffffff">'
        f"{container}</body></html>"
    )


def status_pill(
    label: str,
    *,
    color: str,
    background: str,
    detail: str = "",
    hidden_word: str = "",
) -> str:
    """Pastille d'état en tête de courrier, accompagnée d'un détail discret."""
    pill = (
        '<span style="display:inline-block;font-size:11px;font-weight:700;'
        f"letter-spacing:0.04em;color:{_check_color(color)};background:{_check_color(background)};"
        f'padding:4px 10px;border-radius:999px;line-height:1.2">{escape(label)}</span>'
    )
    detail_html = (
        '<span style="margin-left:8px;font-size:12px;color:#64748b">'
        f"{escape(detail)}</span>"
        if detail
        else ""
    )
    hidden_html = (
        f'<span style="display:none">{escape(hidden_word)}</span>'
        if hidden_word and hidden_word not in label
        else ""
    )
    return f'<div style="margin:0 0 12px 0">{pill}{detail_html}{hidden_html}</div>'


def headline(text: str) -> str:
    """Phrase d'accroche claire en une ligne."""
    return (
        '<div style="margin:0 0 16px 0;font-size:17px;line-height:1.35;'
        f'font-weight:600;color:#0f172a">{escape(text)}</div>'
    )


def meta_block(rows: Sequence[tuple[str, str, bool, bool]]) -> str:
    """Bloc compact de métadonnées entre deux filets #e2e8f0.

    Chaque ligne porte (libellé, valeur, chasse_fixe, alerte).
    """
    rendered: list[str] = []
    for label, value, is_mono, is_alert in rows:
        if not value:
            continue
        label_color = "#b91c1c" if is_alert else "#64748b"
        value_color = "#b91c1c" if is_alert else "#0f172a"
        value_font = (
            f"font-family:{FONT_MONO};font-size:13px;word-break:break-all"
            if is_mono
            else "overflow-wrap:anywhere"
        )
        weight = "font-weight:600;" if is_alert else ""
        rendered.append(
            '<div style="margin:0 0 5px 0;font-size:13px;line-height:1.4">'
            f'<span style="color:{label_color};{weight}">{escape(label)}</span>'
            f'<span style="color:#94a3b8"> · </span>'
            f'<span style="color:{value_color};{value_font}">{escape(value)}</span>'
            "</div>"
        )
    if not rendered:
        return ""
    return (
        '<div style="border-top:1px solid #e2e8f0;border-bottom:1px solid #e2e8f0;'
        'padding:10px 0 5px 0;margin:0 0 16px 0">'
        + "".join(rendered)
        + "</div>"
    )


def section_title(title: str) -> str:
    """Titre de section discret."""
    return (
        '<div style="font-size:11px;font-weight:700;text-transform:uppercase;'
        f'letter-spacing:0.04em;color:#64748b;margin:0 0 8px 0">{escape(title)}</div>'
    )


def bullets_block(
    title: str, items: Sequence[str], *, empty_text: str = ""
) -> str:
    """Liste à puces concise sous un titre discret."""
    elements = "".join(
        f'<li style="margin:0 0 5px 0;line-height:1.4">{escape(item)}</li>'
        for item in items
    )
    if not elements and empty_text:
        elements = (
            f'<li style="margin:0;color:#64748b;line-height:1.4">{escape(empty_text)}</li>'
        )
    if not elements:
        return ""
    return (
        '<div style="margin:0 0 16px 0">'
        + section_title(title)
        + '<ul style="margin:0;padding-left:18px;color:#0f172a;font-size:14px">'
        + elements
        + "</ul></div>"
    )


def excerpts_block(title: str, excerpts: Sequence[str]) -> str:
    """Extraits textuels inertes : tous les liens y sont neutralisés."""
    items = [str(value) for value in excerpts if str(value).strip()]
    if not items:
        return ""
    rendered = "".join(
        '<div style="margin:0 0 6px 0;padding:8px 10px;background:#f8fafc;'
        "color:#334155;border-left:2px solid #cbd5e1;border-radius:4px;"
        'font-size:13px;line-height:1.4">'
        f"{escape(neutralize_excerpt_links(value))}</div>"
        for value in items
    )
    return '<div style="margin:0 0 16px 0">' + section_title(title) + rendered + "</div>"


def footer(left_html: str, *, reference: str = "") -> str:
    """Pied de page sur une ligne : MAIA à gauche, référence en chasse fixe à droite."""
    ref_html = (
        f'<span style="float:right;font-family:{FONT_MONO};color:#94a3b8">'
        f"{escape(reference)}</span>"
        if reference
        else ""
    )
    return (
        '<div style="border-top:1px solid #e2e8f0;margin-top:18px;padding-top:12px;'
        'font-size:12px;color:#64748b;line-height:1.45;overflow:hidden">'
        + ref_html
        + left_html
        + "</div>"
    )
