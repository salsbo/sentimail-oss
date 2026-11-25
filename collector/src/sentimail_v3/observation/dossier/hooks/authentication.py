from __future__ import annotations

import re
from email.utils import parseaddr
from typing import ClassVar

import tldextract

from sentimail_v3.code.shared_esp import shared_esp_marker, shared_esp_provider
from sentimail_v3.observation.dossier.hook import EvidenceHook
from sentimail_v3.observation.dossier.models import Clue, InvestigationContext

_RESULT = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
    re.IGNORECASE,
)
# Le domaine qui a réellement signé, tel que le relais de confiance le rapporte.
_SIGNING_DOMAIN = re.compile(
    r"\bdkim\s*=\s*pass[^;]*?\bheader\.d\s*=\s*([A-Za-z0-9.-]+)", re.IGNORECASE
)
_extract = tldextract.TLDExtract(suffix_list_urls=())


def _apex(domain: str) -> str:
    value = _extract(domain.casefold().rstrip("."))
    return ".".join(part for part in (value.domain, value.suffix) if part)


class AuthenticationHook(EvidenceHook):
    name: ClassVar[str] = "authentication"
    version: ClassVar[str] = "1.0.0"

    async def observe(
        self, context: InvestigationContext
    ) -> tuple[list[Clue], dict[str, object]]:
        trusted: list[str] = []
        for header in context.parsed.headers:
            if header["name_normalized"] != "authentication-results":
                continue
            value = str(header["value_decoded"])
            authserv_id = value.partition(";")[0].strip().casefold().rstrip(".")
            if authserv_id == "rspamd.sentimail":
                trusted.append(value)

        results: dict[str, str] = {}
        # Le relais de confiance ajoute son résultat en tête. Un message externe
        # peut contenir un faux en-tête plus bas : il ne doit jamais l'écraser.
        for value in trusted[:1]:
            for match in _RESULT.finditer(value):
                results.setdefault(match.group(1).casefold(), match.group(2).casefold())

        # Une signature valide ne dit rien tant qu'on ignore QUI a signé. Toute
        # plateforme d'envoi signe pour son propre domaine : le message part
        # alors avec un dkim=pass parfaitement authentique, qui n'engage que
        # l'hébergeur. Lu comme un gage d'authenticité, il devient l'argument
        # le plus commode d'un usurpateur. On compare donc le domaine
        # signataire à celui que le message affiche.
        signing_domain = ""
        for value in trusted[:1]:
            match = _SIGNING_DOMAIN.search(value)
            if match:
                signing_domain = match.group(1)
        from_apex = ""
        display_name = ""
        for header in context.parsed.headers:
            if header["name_normalized"] == "from":
                display_name, address = parseaddr(str(header["value_decoded"]))
                from_apex = _apex(address.rsplit("@", 1)[-1]) if "@" in address else ""
                break
        signing_apex = _apex(signing_domain) if signing_domain else ""
        dkim_alignment = "unknown"
        if signing_apex and from_apex:
            dkim_alignment = "aligned" if signing_apex == from_apex else "unaligned"

        clues: list[Clue] = []
        # DMARC établi vaut alignement démontré, par SPF ou par DKIM : le
        # signataire tiers devient alors le fonctionnement normal d'un envoi
        # délégué, et non un défaut. Sans DMARC, la question reste entière.
        if (
            results.get("dkim") == "pass"
            and dkim_alignment != "aligned"
            and results.get("dmarc") != "pass"
        ):
            code, direction, strength, statement = (
                ("AUTH_DKIM_UNALIGNED", "adverse", 45,
                 "La signature du message appartient à un autre domaine que celui affiché.")
                if dkim_alignment == "unaligned"
                else ("AUTH_DKIM_PASS", "neutral", 0,
                      "Le message porte une signature valide, dont le domaine "
                      "signataire n’a pas pu être comparé à l’expéditeur affiché.")
            )
            clues.append(
                Clue(
                    "AUTH-003",
                    code,
                    direction,  # type: ignore[arg-type]
                    strength,
                    0.95,
                    statement,
                    {
                        "method": "dkim",
                        "result": "pass",
                        "signing_domain": signing_domain,
                        "from_apex": from_apex,
                        "alignment": dkim_alignment,
                    },
                    {"source": "authentication-results:rspamd.sentimail"},
                )
            )
            results.pop("dkim")
        mapping = {
            ("dmarc", "pass"): ("AUTH-001", "AUTH_DMARC_PASS", "favorable", 60),
            ("dmarc", "fail"): ("AUTH-002", "AUTH_DMARC_FAIL", "adverse", 70),
            ("dkim", "pass"): ("AUTH-003", "AUTH_DKIM_PASS", "favorable", 25),
            ("dkim", "fail"): ("AUTH-004", "AUTH_DKIM_FAIL", "adverse", 20),
            ("spf", "pass"): ("AUTH-005", "AUTH_SPF_PASS", "favorable", 20),
            ("spf", "fail"): ("AUTH-006", "AUTH_SPF_FAIL", "adverse", 20),
            ("spf", "softfail"): ("AUTH-006", "AUTH_SPF_SOFTFAIL", "adverse", 15),
        }
        for method in ("dmarc", "dkim", "spf"):
            result = results.get(method)
            rule = mapping.get((method, result))
            if rule:
                article, code, direction, strength = rule
                facts: dict[str, object] = {
                    "method": method,
                    "result": result,
                    "from_apex": from_apex,
                    "claimed_organisation": display_name.strip()[:80],
                }
                if code == "AUTH_DKIM_PASS" and signing_domain:
                    facts["signing_domain"] = signing_domain
                clues.append(
                    Clue(
                        article,
                        code,
                        direction,  # type: ignore[arg-type]
                        strength,
                        0.95,
                        f"Le relais de confiance indique {method.upper()}={result}.",
                        # L'avis nomme le domaine qui a écrit et le nom
                        # affiché : « authentique » ne dit pas « légitime ».
                        facts,
                        {"source": "authentication-results:rspamd.sentimail"},
                    )
                )
            elif result in {"temperror", "permerror", "none", "neutral"}:
                clues.append(
                    Clue(
                        "AUTH-008",
                        f"AUTH_{method.upper()}_INCONCLUSIVE",
                        "adverse",
                        35 if result in {"temperror", "permerror"} else 10,
                        0.95,
                        f"Le résultat {method.upper()}={result} ne permet pas d’établir l’authenticité.",
                        # L'avis nomme le domaine qu'il n'a pas pu vérifier :
                        # « le domaine affiché » ne dit rien à qui lit.
                        {
                            "method": method,
                            "result": result,
                            "from_apex": from_apex,
                            "claimed_organisation": display_name.strip()[:80],
                        },
                        {"source": "authentication-results:rspamd.sentimail"},
                    )
                )
        if not results:
            clues.append(
                Clue(
                    "AUTH-007",
                    "AUTH_NO_TRUSTED_RESULTS",
                    "neutral",
                    0,
                    1.0,
                    "Aucun résultat d’authentification provenant du relais de confiance.",
                    provenance={"source": "authentication-results"},
                )
            )
        # Une infrastructure d'envoi mutualisée : l'authentification engage la
        # plateforme, pas la marque affichée. Neutre en soi - la plupart des
        # envois honnêtes passent par là - mais elle retire à un dkim/dmarc
        # pass son crédit de légitimité de marque, et devient un signal par
        # corrélation avec une marque imitée ou un domaine jeune.
        provider = (
            shared_esp_provider(context.envelope_from.rsplit("@", 1)[-1])
            if "@" in context.envelope_from
            else None
        ) or shared_esp_provider(signing_domain)
        provider_source = "envelope+dkim"
        if provider is None:
            blob = "\n".join(
                f"{header['name_normalized']}:{header['value_decoded']}"
                for header in context.parsed.headers
            )
            provider = shared_esp_marker(blob)
            provider_source = "headers"
        if provider is not None:
            clues.append(
                Clue(
                    "AUTH-009",
                    "AUTH_SHARED_ESP_INFRASTRUCTURE",
                    "neutral",
                    0,
                    0.9,
                    "Le message transite par une plateforme d’envoi mutualisée : "
                    "son authentification engage la plateforme, non la marque affichée.",
                    {
                        "provider": provider,
                        "from_apex": from_apex,
                        "signing_domain": signing_domain,
                        "detected_by": provider_source,
                    },
                    {"source": "envelope+authentication+headers"},
                )
            )
        return clues, {
            "trusted_header_count": len(trusted),
            "results": results,
            "shared_esp_provider": provider,
        }
