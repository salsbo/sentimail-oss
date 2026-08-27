from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

from sentimail_v3 import PARSER_VERSION

_WORD_RE = re.compile(r"\b[\wÀ-ÿ'-]+\b", re.UNICODE)
_TAG_RE = re.compile(r"<\s*([a-zA-Z][\w:-]*)\b", re.IGNORECASE)
_TRACE_HEADERS = {"received", "return-path", "delivered-to"}
_SECURITY_PREFIXES = (
    "authentication-results",
    "arc-",
    "dkim-",
    "domainkey-",
    "received-spf",
    "x-spam-",
    "x-spamd-",
    "x-rspamd-",
)


@dataclass(frozen=True)
class ParsedMessage:
    message: dict[str, object]
    headers: list[dict[str, object]]
    parts: list[dict[str, object]]
    facts: dict[str, object]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def scrub(value: object) -> str:
    """Rend une chaîne stockable, sans perdre ce que l'expéditeur a écrit.

    Le module email décode certains en-têtes en `surrogateescape` : chaque
    octet non-ASCII devient un demi-codet isolé, que PostgreSQL refuse
    d'encoder. Or ces octets sont très souvent de l'UTF-8 parfaitement valide
    (« \udcc3\udca9 » est un « é ») : on récupère donc d'abord les octets
    d'origine, puis on décode pour de bon. Un vrai octet invalide devient �,
    et un message étrange reste un message capturé - jamais un message qui
    tourne en boucle devant la porte de la base.
    """
    text = str(value)
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        return text.encode("utf-8", errors="surrogateescape").decode(
            "utf-8", errors="replace"
        )


def _decode_text(part: EmailMessage) -> str | None:
    try:
        content = part.get_content()
    except Exception:  # noqa: BLE001 - les MIME malformes restent observables
        return None
    if isinstance(content, str):
        return content
    if isinstance(content, bytes):
        return content.decode(part.get_content_charset() or "utf-8", errors="replace")
    return None


def _decoded_payload(part: EmailMessage) -> bytes:
    if part.is_multipart():
        return b""
    try:
        payload = part.get_payload(decode=True)
    except Exception:  # noqa: BLE001 - les MIME malformes restent observables
        payload = None
    if isinstance(payload, bytes):
        return payload
    text = _decode_text(part)
    return text.encode("utf-8", errors="replace") if text is not None else b""


def _parameters(part: EmailMessage) -> dict[str, dict[str, str | None]]:
    result: dict[str, dict[str, str | None]] = {}
    for header in ("content-type", "content-disposition"):
        values = part.get_params(header=header, failobj=[]) or []
        result[header] = {
            scrub(name).casefold(): None if value is None else scrub(value)
            for name, value in values[1:]
        }
    return result


def _part_rows(
    root: EmailMessage,
) -> tuple[list[dict[str, object]], list[str], list[str]]:
    rows: list[dict[str, object]] = []
    plain: list[str] = []
    html: list[str] = []

    def visit(part: EmailMessage, path: str, parent: str | None) -> None:
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        is_attachment = bool(
            disposition == "attachment"
            or filename
            or (
                not part.is_multipart()
                and part.get_content_type() not in {"text/plain", "text/html"}
            )
        )
        payload = _decoded_payload(part)
        # Le texte d'une part n'est pas réservé au maintype « text » : un SVG
        # (image/svg+xml) ou un fragment XML est du texte balisé, et c'est
        # précisément là que se cache le markup actif d'une pièce jointe
        # déguisée en image. On expose donc aussi son contenu textuel.
        ctype_full = part.get_content_type().casefold()
        is_textual = part.get_content_maintype() == "text" or ctype_full in {
            "image/svg+xml",
            "application/xml",
            "application/xhtml+xml",
        }
        text = _decode_text(part) if is_textual else None
        if text is not None and not is_attachment and part.get_content_maintype() == "text":
            (html if part.get_content_type() == "text/html" else plain).append(text)
        rows.append(
            {
                "path": path,
                "parent_path": parent,
                "ordinal": len(rows),
                "is_multipart": part.is_multipart(),
                "is_attachment": is_attachment,
                "content_type": part.get_content_type().casefold(),
                "maintype": part.get_content_maintype().casefold(),
                "subtype": part.get_content_subtype().casefold(),
                "charset": part.get_content_charset(),
                "content_transfer_encoding": part.get("Content-Transfer-Encoding"),
                "content_disposition": disposition,
                "filename": filename,
                "content_id": part.get("Content-ID"),
                "content_description": part.get("Content-Description"),
                "content_language": part.get("Content-Language"),
                "content_location": part.get("Content-Location"),
                "decoded_size_bytes": len(payload),
                "decoded_sha256": _sha256(payload) if payload else None,
                "text_content": text,
                "parameters": _parameters(part),
                "defects": [type(defect).__name__ for defect in part.defects],
            }
        )
        if part.is_multipart():
            children = list(part.iter_parts())
            for index, child in enumerate(children):
                visit(child, f"{path}.{index}", path)

    visit(root, "0", None)
    return rows, plain, html


def _header_rows(message: EmailMessage) -> list[dict[str, object]]:
    raw_items = list(message.raw_items())
    decoded_items = list(message.items())
    rows: list[dict[str, object]] = []
    for ordinal, (name, value) in enumerate(raw_items):
        normalized = name.casefold()
        decoded = scrub(
            decoded_items[ordinal][1] if ordinal < len(decoded_items) else value
        )
        rows.append(
            {
                "ordinal": ordinal,
                "name_original": name,
                "name_normalized": normalized,
                "value_raw": scrub(value),
                "value_decoded": decoded,
                "value_sha256": _sha256(value.encode("utf-8", errors="surrogatepass")),
                "value_length": len(value),
                "is_trace": normalized in _TRACE_HEADERS,
                "is_security": normalized.startswith(_SECURITY_PREFIXES),
            }
        )
    return rows


def _date(message: EmailMessage) -> tuple[str | None, datetime | None, str | None]:
    raw = message.get("Date")
    if raw is None:
        return None, None, None
    try:
        parsed = parsedate_to_datetime(str(raw))
        if parsed is None:
            raise ValueError("date vide")
        return str(raw), parsed.replace(tzinfo=parsed.tzinfo or UTC), None
    except Exception as exc:  # noqa: BLE001 - la valeur brute est conservee
        return str(raw), None, str(exc)[:500]


def _content_facts(text: str, html: str) -> dict[str, object]:
    tag_counts = Counter(tag.casefold() for tag in _TAG_RE.findall(html))
    characters = len(text) + len(html)
    frequencies = Counter((text + html).encode("utf-8", errors="replace"))
    entropy = 0.0
    if characters:
        total = sum(frequencies.values())
        entropy = -sum(
            (count / total) * math.log2(count / total) for count in frequencies.values()
        )
    return {
        "text_characters": len(text),
        "html_characters": len(html),
        "word_count": len(_WORD_RE.findall(text)),
        "line_count": text.count("\n") + (1 if text else 0),
        "non_ascii_characters": sum(ord(char) > 127 for char in text + html),
        "content_entropy": round(entropy, 6),
        "html_tags": dict(tag_counts),
        "html_link_count": tag_counts.get("a", 0),
        "html_image_count": tag_counts.get("img", 0),
        "html_form_count": tag_counts.get("form", 0),
        "html_script_count": tag_counts.get("script", 0),
    }


def parse_message(raw: bytes) -> ParsedMessage:
    parsed: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    headers = _header_rows(parsed)
    parts, plain_parts, html_parts = _part_rows(parsed)
    body_text = "\n".join(plain_parts) or None
    body_html = "\n".join(html_parts) or None
    date_raw, header_date, date_error = _date(parsed)
    names = Counter(row["name_normalized"] for row in headers)
    defects = [
        type(defect).__name__ for part in parsed.walk() for defect in part.defects
    ]
    facts = {
        "header_count": len(headers),
        "distinct_header_count": len(names),
        "duplicate_headers": {
            name: count for name, count in names.items() if count > 1
        },
        "mime_part_count": len(parts),
        "attachment_count": sum(bool(row["is_attachment"]) for row in parts),
        "content_types": dict(Counter(str(row["content_type"]) for row in parts)),
        "charsets": dict(Counter(str(row["charset"] or "<none>") for row in parts)),
        "content": _content_facts(body_text or "", body_html or ""),
    }
    return ParsedMessage(
        message={
            "message_id": parsed.get("Message-ID"),
            "subject": scrub(parsed.get("Subject") or "") or None,
            "from_header": scrub(parsed.get("From") or "") or None,
            "to_header": parsed.get("To"),
            "cc_header": parsed.get("Cc"),
            "reply_to_header": parsed.get("Reply-To"),
            "return_path_header": parsed.get("Return-Path"),
            "header_date_raw": date_raw,
            "header_date": header_date,
            "header_date_parse_error": date_error,
            "mime_version": parsed.get("MIME-Version"),
            "root_content_type": parsed.get_content_type().casefold(),
            "root_charset": parsed.get_content_charset(),
            "root_transfer_encoding": parsed.get("Content-Transfer-Encoding"),
            "body_text": body_text,
            "body_html": body_html,
            "parser_version": PARSER_VERSION,
            "parser_defects": defects,
        },
        headers=headers,
        parts=parts,
        facts=facts,
    )
