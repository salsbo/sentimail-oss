from __future__ import annotations

import re
from email.utils import getaddresses
from typing import ClassVar
from urllib.parse import urlsplit

import tldextract

from sentimail_v3.observation.dossier.hook import EvidenceHook
from sentimail_v3.observation.dossier.models import Clue, InvestigationContext

_extract = tldextract.TLDExtract(suffix_list_urls=())


def _domain(values: list[str]) -> str | None:
    addresses = [address for _, address in getaddresses(values) if "@" in address]
    return addresses[0].rsplit("@", 1)[1].casefold() if len(addresses) == 1 else None


def _registered(domain: str | None) -> str | None:
    if not domain:
        return None
    result = _extract(domain)
    return ".".join(part for part in (result.domain, result.suffix) if part) or None


# RFC 2369 admet une adresse nue ou entre chevrons, plusieurs séparées par une
# virgule : on prend chaque URI https, avec ou sans chevrons.
_UNSUBSCRIBE_URL = re.compile(r"<(https://[^>\s]+)>|(https://[^\s,>]+)")


def _unsubscribe_urls(values: list[str]) -> list[str]:
    urls: list[str] = []
    for value in values:
        for bracketed, bare in _UNSUBSCRIBE_URL.findall(value):
            urls.append(bracketed or bare)
    return urls


def _url_apex(url: str) -> str | None:
    return _registered(urlsplit(url).hostname)


class HeadersHook(EvidenceHook):
    name: ClassVar[str] = "headers"
    version: ClassVar[str] = "1.0.0"

    async def observe(
        self, context: InvestigationContext
    ) -> tuple[list[Clue], dict[str, object]]:
        grouped: dict[str, list[str]] = {}
        for header in context.parsed.headers:
            grouped.setdefault(str(header["name_normalized"]), []).append(
                str(header["value_decoded"])
            )
        clues: list[Clue] = []
        # Un message ordinaire nomme celui à qui il s'adresse. Quand l'adresse
        # protégée n'apparaît ni en To ni en Cc, elle a été mise en copie
        # cachée : c'est le mode d'envoi d'une diffusion de masse à des
        # adresses collectées. Une lettre d'information qui s'annonce comme
        # telle fait la même chose sans rien dissimuler, et n'est donc pas
        # concernée : c'est la conjonction avec l'absence de déclaration qui
        # rend le fait défavorable.
        addressed = {
            address.casefold()
            for _, address in getaddresses(
                grouped.get("to", []) + grouped.get("cc", [])
            )
            if "@" in address
        }
        declared_bulk = any(
            name in grouped for name in ("list-unsubscribe", "list-id", "list-post")
        )
        hidden = [
            recipient
            for recipient in context.recipients
            if recipient.casefold() not in addressed
        ]
        if hidden and addressed and not declared_bulk:
            clues.append(
                Clue(
                    "HEADERS-003",
                    "HEADERS_RECIPIENT_NOT_ADDRESSED",
                    "adverse",
                    40,
                    0.9,
                    "Le message ne vous nomme ni en destinataire ni en copie : "
                    "il a été envoyé en copie cachée.",
                    {
                        "addressed_count": len(addressed),
                        "hidden_recipient_count": len(hidden),
                        "declared_bulk": declared_bulk,
                    },
                    {"source": "headers:to,cc+smtp-envelope"},
                )
            )
        from_values = grouped.get("from", [])
        if len(from_values) > 1:
            clues.append(
                Clue(
                    "HEADER-001",
                    "HEADERS_MULTIPLE_FROM",
                    "adverse",
                    70,
                    1.0,
                    f"Le message contient {len(from_values)} champs From.",
                    {"count": len(from_values)},
                    {"source": "header:from"},
                )
            )

        from_domain = _registered(_domain(from_values))
        reply_domain = _registered(_domain(grouped.get("reply-to", [])))
        if from_domain and reply_domain and from_domain != reply_domain:
            clues.append(
                Clue(
                    "HEADER-002",
                    "HEADERS_REPLY_TO_DIFFERENT_DOMAIN",
                    "adverse",
                    15,
                    0.8,
                    "Le Reply-To utilise un domaine enregistrable différent du From.",
                    {"from_domain": from_domain, "reply_to_domain": reply_domain},
                    {"source": "headers:from,reply-to"},
                )
            )
        # Désinscription conforme RFC 8058 : une adresse https alignée sur le
        # domaine expéditeur, avec l'en-tête one-click. Purement observationnel,
        # sans jamais visiter l'URL - mais l'alignement syntaxique seul ne
        # prouve RIEN sur qui a réellement envoyé le message : un From usurpé
        # peut porter les deux en-têtes tout aussi facilement qu'un From
        # authentique. Ce hook n'a pas accès à l'authentification (elle vit
        # dans un autre hook) : il consigne donc un FAIT neutre, structurel.
        # C'est deep_analysis._signals, qui connaît l'alignement DMARC, qui
        # peut seul en tirer une corrélation favorable (voir CORR-013).
        unsubscribe_urls = _unsubscribe_urls(grouped.get("list-unsubscribe", []))
        one_click = any(
            "list-unsubscribe=one-click" in value.strip().casefold()
            for value in grouped.get("list-unsubscribe-post", [])
        )
        unsubscribe_apex = _url_apex(unsubscribe_urls[0]) if unsubscribe_urls else None
        rfc8058_structure_aligned = bool(
            unsubscribe_apex and from_domain and unsubscribe_apex == from_domain
        )
        if unsubscribe_urls and one_click and rfc8058_structure_aligned:
            clues.append(
                Clue(
                    "HEADERS-004",
                    "HEADERS_RFC8058_STRUCTURE",
                    "neutral",
                    0,
                    0.9,
                    "Le message présente un mécanisme de désinscription en un "
                    "clic (RFC 8058) dont l’adresse est alignée, syntaxiquement, "
                    "sur le domaine affiché : cet alignement seul ne prouve pas "
                    "qui a envoyé le message.",
                    {
                        "unsubscribe_apex": unsubscribe_apex,
                        "from_domain": from_domain,
                        "one_click_header": one_click,
                    },
                    {"source": "headers:list-unsubscribe,list-unsubscribe-post"},
                )
            )
        return clues, {
            "from_count": len(from_values),
            "from_registered_domain": from_domain,
            "reply_to_registered_domain": reply_domain,
            "unsubscribe_apex": unsubscribe_apex,
            "unsubscribe_one_click": one_click,
            "rfc8058_structure_aligned": rfc8058_structure_aligned,
        }
