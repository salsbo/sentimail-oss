from __future__ import annotations

import re
import unicodedata

_RISK_TERMS = re.compile(
    r"\b(?:urgent|imm[ée]diat|derni[eè]re chance|expire|suspendu|bloqu[ée]|"
    r"mot de passe|password|identifiant|login|2fa|mfa|otp|code de s[ée]curit[ée]|"
    r"iban|rib|virement|paiement|carte bancaire|sepa|clique[rz]?|t[ée]l[ée]charge[rz]?|"
    r"confirme[rz]?|v[ée]rifie[rz]?|scanne[rz]?|secret|confidentiel|ne dites [àa] personne|"
    r"prise en main [àa] distance|anydesk|teamviewer|carte cadeau|gift card|crypto|bitcoin)\b",
    re.IGNORECASE,
)
# Une phrase finit sur un point suivi d'un blanc, ou sur un saut de ligne. Un
# point collé à la suite - une adresse IP, un domaine, « e-mail.fr » - ne coupe
# plus : « l'adresse IP 82. » laissait l'extrait en plan au milieu du nombre.
_SENTENCE_BREAK = re.compile(r"(?:\r?\n)+|(?<=[.!?])\s+")
_AUTO_LINK = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>()]+|"
    r"(?<![\w.+-])[\w.+-]+@(?:[\w-]+\.)+[\w-]{2,}|"
    r"(?<![@\w-])(?:[\w-]+\.)+[a-z]{2,}(?::\d{1,5})?(?:/[^\s<>()]*)?"
)
# Une URL complète, avec les crochets que la version texte d'un courrier met
# autour. Dans un extrait elle ne sert pas à reconnaître le message : coupée à
# son « ? » et hachée par la neutralisation, elle n'était qu'un déchet visible.
_URL = re.compile(r"(?i)\[?\s*(?:https?://|www\.)[^\s<>\]]+\s*\]?")
# Caractères de remplissage qui ne sont pas des blancs pour ``str.split`` :
# les préentêtes les alignent par dizaines (« &zwnj;&nbsp; ») pour masquer la
# suite du texte dans l'aperçu des clients de messagerie.
_FILLERS = {"\u034f", "\u115f", "\u1160", "\u2800", "\u3164", "\uffa0"}
LINK_PLACEHOLDER = "[lien]"


def _readable(text: str) -> str:
    """Le texte sans remplissage invisible ni URL, prêt à découper."""
    visible = "".join(
        char
        for char in text
        if char not in _FILLERS and unicodedata.category(char) != "Cf"
    )
    return _URL.sub(f" {LINK_PLACEHOLDER} ", visible)


def _sentences(text: str) -> list[str]:
    return [
        segment
        for segment in (" ".join(raw.split()) for raw in _SENTENCE_BREAK.split(text))
        if segment
    ]


def risky_text_excerpts(subject: str, body_text: str, limit: int = 8) -> list[str]:
    """Extraits exacts issus du texte, sélectionnés sans décision du LLM."""
    source = _readable(f"{subject.strip()}\n{body_text}"[:100_000])
    excerpts: list[str] = []
    seen: set[str] = set()
    for segment in _sentences(source):
        if not _RISK_TERMS.search(segment):
            continue
        normalized = segment.casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        excerpts.append(segment[:360])
        if len(excerpts) >= limit:
            break
    return excerpts


def message_text_excerpts(body_text: str, limit: int = 3) -> list[str]:
    """Quelques passages utiles, même quand aucun mot de risque n'est écrit.

    Les phrases qui portent une demande sensible restent prioritaires. Un doute
    peut toutefois venir de l'identité ou du contexte de l'envoi, sans aucun mot
    alarmant dans le corps : les premiers passages substantiels complètent alors
    la sélection. L'avis ne reproduit jamais plus de trois courts extraits.
    """
    if limit <= 0:
        return []
    source = str(body_text or "")[:100_000]
    excerpts = [
        value[:280].rstrip()
        for value in risky_text_excerpts("", source, limit=limit)
    ]
    seen = {value.casefold() for value in excerpts}
    for segment in _sentences(_readable(source)):
        # Un passage fait de liens et de ponctuation n'apprend rien : on compte
        # les lettres qui restent une fois les marqueurs de lien retirés.
        lettres = sum(
            char.isalpha() for char in segment.replace(LINK_PLACEHOLDER, "")
        )
        if lettres < 20:
            continue
        segment = segment[:280].rstrip()
        normalized = segment.casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        excerpts.append(segment)
        if len(excerpts) >= limit:
            break
    return excerpts[:limit]


def neutralize_excerpt_links(value: str) -> str:
    """Garde le texte lisible sans laisser le client créer un lien actif."""

    def neutralize(match: re.Match[str]) -> str:
        token = match.group(0)
        return (
            token.replace("://", ":\u200b//")
            .replace("@", "@\u200b")
            .replace(".", ".\u200b")
        )

    return _AUTO_LINK.sub(neutralize, str(value or ""))
