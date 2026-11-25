from __future__ import annotations

import re
import unicodedata
from email.utils import getaddresses, parseaddr
from typing import ClassVar

import tldextract

from sentimail_v3.observation.dossier.hook import EvidenceHook
from sentimail_v3.observation.dossier.models import Clue, InvestigationContext

_extract = tldextract.TLDExtract(suffix_list_urls=())
_EMAIL_IN_NAME = re.compile(r"[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,63})", re.IGNORECASE)
_ASCII_IDENTITY_TOKEN = re.compile(r"[A-Za-z0-9]{3,}")
_ASCII_SUBSTITUTIONS = {"0": "o", "1": "l"}
_LOOKALIKE_SCRIPTS = {"LATIN", "CYRILLIC", "GREEK"}


def _apex(domain: str) -> str:
    value = _extract(domain.casefold().rstrip("."))
    return ".".join(part for part in (value.domain, value.suffix) if part)


def _address(value: str) -> tuple[str, str, str]:
    display, address = parseaddr(value)
    domain = address.rsplit("@", 1)[-1].casefold() if "@" in address else ""
    return display, address.casefold(), _apex(domain)


def _script(char: str) -> str | None:
    name = unicodedata.name(char, "")
    return next((value for value in _LOOKALIKE_SCRIPTS if value in name), None)


def _unicode_identity_markers(value: str, field: str) -> list[dict[str, object]]:
    scripts = {_script(char) for char in value if char.isalpha()}
    scripts.discard(None)
    if len(scripts) < 2:
        return []
    return [
        {
            "field": field,
            "character": char,
            "codepoint": f"U+{ord(char):04X}",
            "name": unicodedata.name(char, "UNKNOWN"),
            "offset": index,
        }
        for index, char in enumerate(value)
        if _script(char) in {"CYRILLIC", "GREEK"}
    ][:12]


def _ascii_identity_markers(value: str, field: str) -> list[dict[str, object]]:
    markers: list[dict[str, object]] = []
    for token_match in _ASCII_IDENTITY_TOKEN.finditer(value):
        token = token_match.group(0)
        if not any(char.isalpha() for char in token):
            continue
        for index, char in enumerate(token):
            replacement = _ASCII_SUBSTITUTIONS.get(char)
            embedded_capital_i = (
                char == "I"
                and index > 0
                and any(neighbor.islower() for neighbor in token[max(0, index - 1): index + 2])
            )
            # Le sens inverse : un l minuscule (ou un 1) lu comme un I majuscule à
            # une jointure camelCase - « Primelnfos » pour « PrimeInfos ». Le l est
            # partout dans les vrais mots (« Charlie », « Village ») ; on n'ouvre le
            # soupçon qu'à une frontière où le relire « I » recompose un second mot
            # capitalisable : jeton de type Nom/Marque, segment gauche d'au moins
            # trois lettres, segment droit d'au moins trois lettres dont deux
            # consonnes. Le fait reste neutre - c'est l'arbitre qui tranche.
            tail = token[index + 1:]
            camelcase_lowercase_i = (
                char in {"l", "1"}
                and token[:1].isupper()
                and index >= 3
                and token[index - 1].islower()
                and len(tail) >= 3
                and sum(1 for c in tail if c.isalpha() and c.lower() not in "aeiou") >= 2
            )
            # « lnfosPRlME » (M-8d026c) : le l minuscule en tête de mot devant une
            # consonne, qu'aucun mot n'écrit ainsi (« ln », « lr »), et le l
            # minuscule pris entre deux majuscules, là où l'œil attend un I.
            # Neutres comme les autres : le squelette les compare ensuite à
            # l'organisation revendiquée (DEEP-026). Un domaine s'écrit en
            # minuscules et abrège volontiers (lnkd.in) : la tête de mot ne se
            # lit que dans le nom affiché.
            suivant = token[index + 1] if index + 1 < len(token) else ""
            leading_lowercase_i = (
                field == "display_name"
                and char == "l"
                and index == 0
                and suivant.isalpha()
                and suivant.lower() not in "aeiouylh"
            )
            lowercase_i_among_capitals = (
                char == "l"
                and 0 < index < len(token) - 1
                and token[index - 1].isupper()
                and suivant.isupper()
            )
            lowercase_i = (
                camelcase_lowercase_i or leading_lowercase_i or lowercase_i_among_capitals
            )
            if replacement is None and not embedded_capital_i and not lowercase_i:
                continue
            looks_like = "I" if lowercase_i else (replacement or "l")
            markers.append(
                {
                    "field": field,
                    "token": token[:80],
                    "character": char,
                    "looks_like": looks_like,
                    "offset": token_match.start() + index,
                }
            )
    return markers[:12]


def _idn_identity_markers(domain: str) -> list[dict[str, object]]:
    markers: list[dict[str, object]] = []
    for label in domain.split("."):
        if not label.startswith("xn--"):
            continue
        try:
            decoded = label.encode("ascii").decode("idna")
        except UnicodeError:
            decoded = ""
        scripts = sorted(
            {script for char in decoded if (script := _script(char)) is not None}
        )
        markers.append(
            {
                "field": "from_domain",
                "encoded_label": label[:80],
                "decoded_label": decoded[:80],
                "scripts": scripts,
            }
        )
    return markers[:12]


class IdentityHook(EvidenceHook):
    name: ClassVar[str] = "identity"
    version: ClassVar[str] = "1.1.0"

    async def observe(
        self, context: InvestigationContext
    ) -> tuple[list[Clue], dict[str, object]]:
        grouped: dict[str, list[str]] = {}
        for header in context.parsed.headers:
            grouped.setdefault(str(header["name_normalized"]), []).append(
                str(header["value_decoded"])
            )
        from_values = getaddresses(grouped.get("from", []))
        display = from_values[0][0] if len(from_values) == 1 else ""
        from_address = from_values[0][1].casefold() if len(from_values) == 1 else ""
        from_domain = from_address.rsplit("@", 1)[-1] if "@" in from_address else ""
        from_apex = _apex(from_domain)
        _, envelope_address, envelope_apex = _address(context.envelope_from)
        _, sender_address, sender_apex = _address(
            grouped.get("sender", [""])[0] if grouped.get("sender") else ""
        )
        message_id = str(context.parsed.message.get("message_id") or "")
        message_id_domain = (
            message_id.strip().strip("<>").rsplit("@", 1)[-1].casefold()
            if "@" in message_id
            else ""
        )
        message_id_apex = _apex(message_id_domain)
        clues: list[Clue] = []
        if from_apex and envelope_apex and from_apex != envelope_apex:
            clues.append(
                Clue(
                    "IDENTITY-001",
                    "IDENTITY_ENVELOPE_FROM_CROSS_APEX",
                    "neutral",
                    0,
                    0.9,
                    "Le domaine d’enveloppe diffère du domaine visible.",
                    {"from_apex": from_apex, "envelope_apex": envelope_apex},
                    {"source": "smtp-envelope+header:from"},
                )
            )
        if from_apex and sender_apex and from_apex != sender_apex:
            clues.append(
                Clue(
                    "IDENTITY-002",
                    "IDENTITY_SENDER_CROSS_APEX",
                    "adverse",
                    20,
                    0.8,
                    "Le champ Sender désigne une identité distincte du From.",
                    {"from_apex": from_apex, "sender_apex": sender_apex},
                    {"source": "headers:from,sender"},
                )
            )
        if from_apex and message_id_apex and from_apex != message_id_apex:
            clues.append(
                Clue(
                    "IDENTITY-003",
                    "IDENTITY_MESSAGE_ID_CROSS_APEX",
                    "neutral",
                    0,
                    0.75,
                    "Le Message-ID est émis sous un autre apex que le From.",
                    {"from_apex": from_apex, "message_id_apex": message_id_apex},
                    {"source": "headers:from,message-id"},
                )
            )
        # La confrontation du nom affiché à l'organisation qu'il désigne ne se
        # fait plus ici. Elle demandait une table de marques écrite à la main,
        # qui ignorait ce qu'on n'y avait pas mis et se trompait sur ce qu'on y
        # avait mal mis - « ca-paris.fr » accusé d'usurper le Crédit Agricole,
        # dont c'est pourtant un domaine. Elle se fait dans l'analyse profonde,
        # sur ce qu'une recherche rend du nom et du domaine.
        displayed_domain = _EMAIL_IN_NAME.search(display)
        if displayed_domain and _apex(displayed_domain.group(1)) != from_apex:
            clues.append(
                Clue(
                    "IDENTITY-004",
                    "IDENTITY_DISPLAY_NAME_EMAIL_MISMATCH",
                    "adverse",
                    65,
                    0.95,
                    "Le nom affiché présente une adresse différente de l’adresse réelle.",
                    {"actual_apex": from_apex},
                    {"source": "header:from:display-name"},
                )
            )
        if from_apex and envelope_apex == from_apex and not sender_address:
            clues.append(
                Clue(
                    "IDENTITY-005",
                    "IDENTITY_ENVELOPE_VISIBLE_ALIGNED",
                    "favorable",
                    10,
                    0.8,
                    "L’identité visible et l’enveloppe utilisent le même apex.",
                    {"apex": from_apex},
                    {"source": "smtp-envelope+header:from"},
                )
            )
        idn_markers = _idn_identity_markers(from_domain)
        unicode_markers = [
            *_unicode_identity_markers(display, "display_name"),
            *_unicode_identity_markers(from_domain, "from_domain"),
        ]
        for marker in idn_markers:
            decoded = str(marker.get("decoded_label") or "")
            if len(marker.get("scripts") or []) > 1:
                unicode_markers.extend(
                    _unicode_identity_markers(decoded, "from_domain_decoded")
                )
        if unicode_markers:
            clues.append(
                Clue(
                    "IDENTITY-006",
                    "IDENTITY_UNICODE_HOMOGRAPH",
                    "adverse",
                    75,
                    0.9,
                    "L’identité de l’expéditeur mélange des caractères visuellement proches issus de scripts différents ou utilise un libellé IDNA.",
                    {"markers": unicode_markers[:12]},
                    {"source": "header:from:unicode"},
                )
            )
        elif idn_markers:
            clues.append(
                Clue(
                    "IDENTITY-008",
                    "IDENTITY_IDN_CONTEXT",
                    "neutral",
                    0,
                    0.9,
                    "Le domaine expéditeur utilise un libellé internationalisé ; aucun mélange de scripts n’est établi et ce fait reste neutre.",
                    {"markers": idn_markers},
                    {"source": "header:from:idna"},
                )
            )
        ascii_markers = [
            *_ascii_identity_markers(display, "display_name"),
            *_ascii_identity_markers(from_domain, "from_domain"),
        ]
        if ascii_markers:
            clues.append(
                Clue(
                    "IDENTITY-007",
                    "IDENTITY_ASCII_LOOKALIKE",
                    "neutral",
                    0,
                    0.85,
                    "L’identité contient des caractères ASCII pouvant se ressembler visuellement (0/o, 1/l ou I/l) ; sans marque de référence, ce fait reste à contextualiser.",
                    {"markers": ascii_markers[:12]},
                    {"source": "header:from:visual-identity"},
                )
            )
        return clues, {
            "from_address": from_address,
            "from_apex": from_apex,
            "envelope_address": envelope_address,
            "envelope_apex": envelope_apex,
            "sender_address": sender_address,
            "sender_apex": sender_apex,
            "message_id_apex": message_id_apex,
            "unicode_homograph_markers": unicode_markers,
            "ascii_lookalike_markers": ascii_markers,
            "idn_markers": idn_markers,
        }
