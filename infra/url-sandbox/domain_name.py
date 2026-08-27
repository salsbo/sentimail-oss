"""Frontiere organisationnelle PSL locale du sandbox URL.

La snapshot Public Suffix List est fournie par ``tldextract``. Aucun cache ni
telechargement n'est autorise a l'execution et la section PRIVATE est incluse,
afin que deux tenants d'un hebergeur comme ``github.io`` restent distincts.
"""

from __future__ import annotations

import ipaddress

import tldextract

_EXTRACT = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    fallback_to_snapshot=True,
    include_psl_private_domains=True,
)


def normalize_hostname(host: str) -> str:
    """Canonise un hostname en A-label IDNA minuscule, ou une IP compacte."""
    value = host.strip().rstrip(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not value:
        return ""
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        pass
    try:
        normalized = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""
    labels = normalized.split(".")
    if any(not label or len(label) > 63 for label in labels) or len(normalized) > 253:
        return ""
    return normalized


def registrable_domain(host: str) -> str:
    """Retourne l'eTLD+1 selon la PSL ICANN + PRIVATE embarquee."""
    normalized = normalize_hostname(host)
    if not normalized:
        return ""
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        result = _EXTRACT(normalized)
        if result.top_domain_under_public_suffix:
            return result.top_domain_under_public_suffix
        labels = normalized.split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else normalized
    return normalized
