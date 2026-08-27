"""Empreinte de gabarit d'un message, pour reconnaître une campagne.

Le signal robuste face aux comptes d'envoi jetables n'est pas le texte mais la
STRUCTURE : suite des balises HTML, leurs classes, et les apex des liens. La
personnalisation (prénom injecté, lien unique par destinataire) ne touche que
le contenu, pas le squelette. On en tire une empreinte MinHash - une signature
compacte dont l'égalité position par position estime la similarité de Jaccard
des ensembles de départ - calculable et comparable en local pur, sans
dépendance externe.

Le sujet reçoit un traitement séparé : masquage des nombres et jetons pour
isoler le gabarit « {accroche} » de la personnalisation (« Doc 6EM2A8TM8 »).
"""

from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser

import tldextract

_NUM_PERM = 64
_MIN_TAGS = 15
_SHINGLE = 3
_MASK32 = 0xFFFFFFFF
# Constantes impaires distinctes par position : une famille de fonctions de
# hachage h_i(x) = (a_i * x + b_i) mod 2^32 suffit pour un MinHash de filtre.
_A = [(i * 2 + 1) * 2654435761 & _MASK32 for i in range(_NUM_PERM)]
_B = [(i * 40503 + 12345) & _MASK32 for i in range(_NUM_PERM)]

_extract = tldextract.TLDExtract(suffix_list_urls=())
_SKIP = {"head", "style", "script", "template", "title", "meta", "link"}


def _apex(url: str) -> str:
    host = re.sub(r"^https?://", "", url.strip().casefold()).split("/", 1)[0]
    value = _extract(host)
    return ".".join(part for part in (value.domain, value.suffix) if part)


class _SkeletonParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tokens: list[str] = []
        self._depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        if tag in _SKIP:
            self._depth += 1
            return
        if self._depth:
            return
        cls = ""
        href_apex = ""
        for name, value in attrs:
            if name == "class" and value:
                # Première classe seulement : les suffixes générés (col-1,
                # col-2) ne doivent pas éclater le squelette.
                cls = value.split()[0] if value.split() else ""
            elif name in ("href", "src") and value and value.startswith("http"):
                href_apex = _apex(value)
        token = tag
        if cls:
            token += "." + cls
        if href_apex:
            token += "@" + href_apex
        self.tokens.append(token)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in _SKIP and self._depth:
            self._depth -= 1


def _skeleton_tokens(html: str) -> list[str]:
    parser = _SkeletonParser()
    try:
        parser.feed((html or "")[:400_000])
        parser.close()
    except Exception:  # noqa: BLE001 - squelette partiel plutôt que rien
        pass
    return parser.tokens


def _shingles(tokens: list[str]) -> set[int]:
    grams: set[int] = set()
    for i in range(len(tokens) - _SHINGLE + 1):
        gram = "\x1f".join(tokens[i : i + _SHINGLE])
        grams.add(int.from_bytes(hashlib.blake2b(gram.encode(), digest_size=4).digest(), "big"))
    return grams


def dom_minhash(html: str) -> list[int] | None:
    """Signature MinHash du squelette DOM, ou None si trop pauvre pour discriminer."""
    tokens = _skeleton_tokens(html)
    if len(tokens) < _MIN_TAGS:
        return None
    grams = _shingles(tokens)
    if not grams:
        return None
    signature = []
    for a, b in zip(_A, _B):
        signature.append(min(((a * gram + b) & _MASK32) for gram in grams))
    return signature


def jaccard(left: list[int] | None, right: list[int] | None) -> float:
    """Similarité de Jaccard estimée par l'accord position par position."""
    if not left or not right or len(left) != len(right):
        return 0.0
    return sum(1 for x, y in zip(left, right) if x == y) / len(left)


# Tout jeton contenant un chiffre est une référence/un montant/un code : c'est
# la personnalisation à masquer. Le reste - les mots - porte le gabarit.
_ALNUM_WITH_DIGIT = re.compile(r"\b\w*\d\w*\b", re.UNICODE)


def subject_template(subject: str) -> str:
    """Le sujet réduit à son gabarit : nombres et jetons codés masqués."""
    masked = _ALNUM_WITH_DIGIT.sub("#", subject or "")
    return " ".join(masked.casefold().split())


def band_keys(signature: list[int], bands: int = 16) -> list[str]:
    """Les clés LSH par bandes : deux signatures proches partagent au moins une."""
    rows = max(1, len(signature) // bands)
    keys: list[str] = []
    for band in range(bands):
        chunk = signature[band * rows : (band + 1) * rows]
        if not chunk:
            continue
        digest = hashlib.blake2b(
            "|".join(str(x) for x in chunk).encode(), digest_size=8
        ).hexdigest()
        keys.append(f"{band}:{digest}")
    return keys
