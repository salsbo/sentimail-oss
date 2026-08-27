from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import ClassVar
from urllib.parse import urlsplit

import tldextract

from sentimail_v3.observation.dossier.hook import EvidenceHook
from sentimail_v3.observation.dossier.models import Clue, InvestigationContext

_extract = tldextract.TLDExtract(suffix_list_urls=())
_URL = re.compile(r"https?://[^\s<>'\"\)]+", re.IGNORECASE)
_VISIBLE_DOMAIN = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", re.IGNORECASE)
_RISKY_TLDS = {"zip", "mov", "top", "click", "loan", "work", "win", "bid", "stream", "support"}
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly"}


def _apex(host: str) -> str:
    value = _extract(host.casefold().rstrip("."))
    return ".".join(part for part in (value.domain, value.suffix) if part)


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() == "a":
            self._href = next((value for name, value in attrs if name.casefold() == "href"), None)
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "a" and self._href is not None:
            self.links.append((self._href, " ".join(self._text).strip()))
            self._href = None
            self._text = []


class UrlHook(EvidenceHook):
    name: ClassVar[str] = "urls"
    version: ClassVar[str] = "1.0.0"

    async def observe(
        self, context: InvestigationContext
    ) -> tuple[list[Clue], dict[str, object]]:
        text = str(context.parsed.message.get("body_text") or "")
        html = str(context.parsed.message.get("body_html") or "")
        parser = _Links()
        try:
            parser.feed(html[:1_000_000])
        except Exception:  # noqa: BLE001 - HTML malforme, analyse fail-soft
            parser.links = []
        # Le HTML brut contient aussi des namespaces, DTD, images, pixels et CSS.
        # Ce ne sont pas des destinations activables par l'utilisateur et ils ne
        # doivent ni épuiser le budget ni créer de faux apex étrangers.
        raw_urls = [
            match.group(0).rstrip(".,;:!?") for match in _URL.finditer(text)
        ]
        raw_urls.extend(href for href, _ in parser.links if href.casefold().startswith(("http://", "https://")))
        urls = list(dict.fromkeys(raw_urls))
        from_address = parseaddr(str(context.parsed.message.get("from_header") or ""))[1]
        from_apex = _apex(from_address.rsplit("@", 1)[-1]) if "@" in from_address else ""
        clues: list[Clue] = []
        hosts: list[str] = []
        apexes: set[str] = set()
        risky_count = 0

        for raw in urls[:100]:
            try:
                parsed = urlsplit(raw)
                host = (parsed.hostname or "").casefold().rstrip(".")
                port = parsed.port
            except ValueError:
                continue
            if not host:
                continue
            hosts.append(host)
            apex = _apex(host)
            if apex:
                apexes.add(apex)
            reasons: list[str] = []
            try:
                ipaddress.ip_address(host)
                reasons.append("IP nue comme destination")
            except ValueError:
                pass
            if port not in {None, 80, 443}:
                reasons.append(f"port inhabituel {port}")
            if parsed.username is not None:
                reasons.append("userinfo avant le vrai hôte")
            if host.split(".")[-1] in _RISKY_TLDS:
                reasons.append("extension fréquemment détournée")
            if host.startswith("xn--") or ".xn--" in host:
                reasons.append("nom internationalisé pouvant imiter une marque")
            if len(host.split(".")) >= 6:
                reasons.append("empilement inhabituel de sous-domaines")
            if apex in _SHORTENERS:
                reasons.append("raccourcisseur masquant la destination")
            if reasons:
                risky_count += 1
                clues.append(
                    Clue(
                        "URL-001",
                        "URL_STATIC_RISK",
                        "adverse",
                        min(75, 20 + len(reasons) * 15),
                        0.86,
                        f"Une URL présente des caractéristiques risquées : {', '.join(reasons)}.",
                        # Les motifs sont écrits, pas seulement comptés : un
                        # raccourcisseur appartenant à l'expéditeur ne masque
                        # rien, et le distinguer demande de savoir lequel des
                        # motifs a joué.
                        {
                            "host": host,
                            "apex": apex,
                            "reasons": list(reasons),
                            "reason_count": len(reasons),
                        },
                        {"source": "url-static"},
                    )
                )

        deceptive = 0
        displayed_mismatches: list[dict[str, str]] = []
        for href, visible in parser.links[:100]:
            try:
                parsed_href = urlsplit(href)
                href_host = parsed_href.hostname or ""
            except ValueError:
                continue
            if parsed_href.scheme.casefold() not in {"http", "https"} or not href_host:
                continue
            visible_match = _VISIBLE_DOMAIN.search(visible)
            if visible_match and _apex(visible_match.group(0)) != _apex(href_host):
                deceptive += 1
                displayed_mismatches.append(
                    {
                        "displayed_apex": _apex(visible_match.group(0)),
                        "link_apex": _apex(href_host),
                    }
                )
        if deceptive:
            clues.append(
                Clue(
                    "URL-002",
                    "URL_DECEPTIVE_LINK_TEXT",
                    "neutral",
                    0,
                    0.98,
                    "Le domaine affiché diffère du lien intermédiaire ; la destination finale doit être vérifiée.",
                    {
                        "count": deceptive,
                        "pairs": displayed_mismatches[:10],
                    },
                    {"source": "html:a[href]"},
                )
            )
        foreign_apexes = sorted(apex for apex in apexes if from_apex and apex != from_apex)
        if foreign_apexes:
            clues.append(
                Clue(
                    "URL-003",
                    "URL_CROSS_APEX",
                    "neutral",
                    0,
                    0.8,
                    "Le message contient des liens vers des apex distincts de l’expéditeur.",
                    {"from_apex": from_apex, "foreign_apex_count": len(foreign_apexes)},
                    {"source": "from+urls"},
                )
            )
        if len(urls) > 100:
            clues.append(
                Clue(
                    "URL-004",
                    "URL_ANALYSIS_BUDGET_EXCEEDED",
                    "adverse",
                    50,
                    1.0,
                    "Le nombre d’URL dépasse le budget d’analyse statique.",
                    {"total": len(urls), "analyzed": 100},
                    {"source": "analysis-budget"},
                )
            )
        # Les apex des seuls liens cliquables. Une image hébergée sur un CDN
        # n'est pas une destination : personne ne clique dessus, et la compter
        # ferait refuser la voie rapide à tout courrier transactionnel dont le
        # logo vit ailleurs.
        actionable_apexes = sorted(
            {
                apex
                for apex in (
                    _apex(urlsplit(href).hostname or "")
                    for href, _ in parser.links
                    if href.casefold().startswith(("http://", "https://"))
                )
                if apex
            }
        )
        return clues, {
            "actionable_apexes": actionable_apexes,
            "url_count": len(urls),
            "analyzed_count": min(100, len(urls)),
            "host_count": len(set(hosts)),
            "apexes": sorted(apexes)[:50],
            "from_apex": from_apex,
            "risky_url_count": risky_count,
            "deceptive_link_count": deceptive,
            "complete": len(urls) <= 100,
        }
