from __future__ import annotations

import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from urllib.parse import urlsplit, urlunsplit

from sentimail_v3.observation.parser import ParsedMessage

_URL_RE = re.compile(r"(?i)\b(?:https?://|ftp://)[^\s<>\"']+")
_IP_CANDIDATE_RE = re.compile(r"(?<![\w.])(?:[0-9a-fA-F:.]{3,})(?![\w.])")
_DOMAIN_RE = re.compile(
    r"(?i)(?<![\w@])(?:[a-z0-9_\u0080-\uffff](?:[a-z0-9_\-\u0080-\uffff]{0,61}"
    r"[a-z0-9_\u0080-\uffff])?\.)+[a-z\u0080-\uffff]{2,63}(?![\w])"
)
_ADDRESS_HEADERS = {
    "from": "from",
    "to": "to",
    "cc": "cc",
    "bcc": "bcc",
    "reply-to": "reply_to",
    "sender": "sender",
    "return-path": "return_path",
    "resent-from": "resent_from",
    "resent-to": "resent_to",
    "resent-cc": "resent_cc",
    "disposition-notification-to": "disposition_notification_to",
    "errors-to": "errors_to",
    "bounces-to": "bounces_to",
}


def _domain(value: str) -> str | None:
    candidate = value.strip().strip(".[]<>()\"'").casefold()
    if not candidate or "." not in candidate:
        return None
    try:
        return candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _entity(
    entity_type: str,
    role: str,
    value_raw: str,
    value_normalized: str,
    attributes: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "entity_type": entity_type,
        "role": role,
        "value_raw": value_raw,
        "value_normalized": value_normalized,
        "attributes": attributes or {},
    }


def _address_entities(role: str, values: list[str]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for display_name, address in getaddresses(values):
        if "@" not in address:
            continue
        local, raw_domain = address.rsplit("@", 1)
        domain = _domain(raw_domain)
        if not local or domain is None:
            continue
        normalized = f"{local}@{domain}"
        result.append(
            _entity(
                "address",
                role,
                address,
                normalized,
                {"display_name": display_name, "local_part": local, "domain": domain},
            )
        )
        result.append(_entity("domain", f"address:{role}", raw_domain, domain))
    return result


def _url_entities(source: str, value: str) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for match in _URL_RE.finditer(value):
        raw = match.group(0).rstrip(".,;:!?)]}")
        try:
            parsed = urlsplit(raw)
            host = parsed.hostname
            port = parsed.port
        except ValueError:
            continue
        if not host:
            continue
        normalized_host = _domain(host) or host.casefold()
        normalized = urlunsplit(
            (
                parsed.scheme.casefold(),
                parsed.netloc.casefold(),
                parsed.path,
                parsed.query,
                parsed.fragment,
            )
        )
        result.append(
            _entity(
                "url",
                source,
                raw,
                normalized,
                {
                    "scheme": parsed.scheme.casefold(),
                    "host": normalized_host,
                    "port": port,
                    "path": parsed.path,
                    "query": parsed.query,
                    "fragment": parsed.fragment,
                    "username_present": parsed.username is not None,
                    "password_present": parsed.password is not None,
                },
            )
        )
        try:
            ipaddress.ip_address(host)
        except ValueError:
            domain = _domain(host)
            if domain:
                result.append(_entity("domain", f"url:{source}", host, domain))
        else:
            result.append(_ip_entity(f"url:{source}", host))
    return result


def _ip_entity(role: str, value: str) -> dict[str, object]:
    parsed = ipaddress.ip_address(value.strip("[]"))
    return _entity(
        "ip",
        role,
        value,
        parsed.compressed,
        {
            "version": parsed.version,
            "is_private": parsed.is_private,
            "is_global": parsed.is_global,
            "is_loopback": parsed.is_loopback,
            "is_multicast": parsed.is_multicast,
            "is_reserved": parsed.is_reserved,
        },
    )


def _observed_entities(source: str, value: str) -> list[dict[str, object]]:
    result = _url_entities(source, value)
    for match in _IP_CANDIDATE_RE.finditer(value):
        candidate = match.group(0).strip(".:")
        try:
            result.append(_ip_entity(source, candidate))
        except ValueError:
            continue
    for match in _DOMAIN_RE.finditer(value):
        raw = match.group(0)
        domain = _domain(raw)
        if domain:
            result.append(_entity("domain", source, raw, domain, {"heuristic": True}))
    return result


def extract_entities(
    raw: bytes,
    parsed: ParsedMessage,
    envelope_from: str,
    recipients: list[str],
) -> list[dict[str, object]]:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    result = _address_entities("envelope_from", [parseaddr(envelope_from)[1]])
    result.extend(_address_entities("envelope_to", recipients))

    for header_name, role in _ADDRESS_HEADERS.items():
        result.extend(
            _address_entities(role, [str(v) for v in message.get_all(header_name, [])])
        )
    for header in parsed.headers:
        source = f"header:{header['name_normalized']}"
        result.extend(_observed_entities(source, str(header["value_decoded"])))
    for part in parsed.parts:
        text = part.get("text_content")
        if text:
            result.extend(_observed_entities(f"mime:{part['path']}", str(text)))
        digest = part.get("decoded_sha256")
        if digest:
            result.append(
                _entity("hash", f"mime:{part['path']}:sha256", str(digest), str(digest))
            )
    message_id = parsed.message.get("message_id")
    if message_id:
        normalized = str(message_id).strip().strip("<>").casefold()
        result.append(_entity("message_id", "message_id", str(message_id), normalized))

    for ordinal, entity in enumerate(result):
        entity["ordinal"] = ordinal
    return result
