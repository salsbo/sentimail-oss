from __future__ import annotations

import re

_RISK_TERMS = re.compile(
    r"\b(?:urgent|imm[ée]diat|derni[eè]re chance|expire|suspendu|bloqu[ée]|"
    r"mot de passe|password|identifiant|login|2fa|mfa|otp|code de s[ée]curit[ée]|"
    r"iban|rib|virement|paiement|carte bancaire|sepa|clique[rz]?|t[ée]l[ée]charge[rz]?|"
    r"confirme[rz]?|v[ée]rifie[rz]?|scanne[rz]?|secret|confidentiel|ne dites [àa] personne|"
    r"prise en main [àa] distance|anydesk|teamviewer|carte cadeau|gift card|crypto|bitcoin)\b",
    re.IGNORECASE,
)
_SEGMENT = re.compile(r"[^\n.!?]{0,180}(?:[.!?]|$)")


def risky_text_excerpts(subject: str, body_text: str, limit: int = 8) -> list[str]:
    """Extraits exacts issus du texte, sélectionnés sans décision du LLM."""
    source = f"{subject.strip()}\n{body_text}"[:100_000]
    excerpts: list[str] = []
    seen: set[str] = set()
    for match in _SEGMENT.finditer(source):
        segment = " ".join(match.group(0).split()).strip()
        if not segment or not _RISK_TERMS.search(segment):
            continue
        normalized = segment.casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        excerpts.append(segment[:360])
        if len(excerpts) >= limit:
            break
    return excerpts
