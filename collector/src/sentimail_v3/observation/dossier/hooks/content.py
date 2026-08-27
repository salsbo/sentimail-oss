from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from typing import ClassVar

from sentimail_v3.observation.dossier.hook import EvidenceHook
from sentimail_v3.observation.dossier.hooks.nature import is_unsolicited_style
from sentimail_v3.observation.dossier.hooks.hidden_text import split_visible_hidden
from sentimail_v3.observation.dossier.hooks.visible_text import visible_html_text
from sentimail_v3.observation.dossier.models import Clue, InvestigationContext

_URGENCY = re.compile(
    r"\b(urgent|imm[ée]diat|derni[eè]re chance|dans les \d+ (?:minutes|heures)|"
    r"expire|expirera|expires?|suspendu|bloqu[ée]|sans d[ée]lai|action requise)\b",
    re.IGNORECASE,
)
_INTRINSIC_EXPIRATION = re.compile(
    r"\b(expire|expirera|expires?|valable (?:pendant|\d)|valid for|"
    r"usage unique|one[- ]time|lien s[ée]curis[ée]|secure link|"
    r"code de v[ée]rification|verification code|otp)\b",
    re.IGNORECASE,
)
_COERCION = re.compile(
    r"\b(derni[eè]re chance|sinon|faute de quoi|sous peine|sera (?:suspendu|bloqu[ée])|"
    r"compte (?:suspendu|bloqu[ée])|p[ée]nalit[ée]|sanction|imm[ée]diatement)\b",
    re.IGNORECASE,
)
_ONE_TIME_PURPOSE = re.compile(
    r"\b(lien s[ée]curis[ée]|secure link|magic link|usage unique|one[- ]time|otp|"
    r"code de v[ée]rification|verification code|code de connexion|sign[- ]in link)\b",
    re.IGNORECASE,
)
_ACCOUNT_SECURITY = re.compile(
    r"\b(r[ée]initialis(?:er|ation)|reset (?:your )?password|v[ée]rifier (?:votre|ton) compte|"
    r"verify (?:your )?account|connexion|login|sign[ -]?in|2fa|mfa)\b",
    re.IGNORECASE,
)
_FINANCIAL_TRANSFER = re.compile(
    r"\b(iban|rib|virement|wire transfer|sepa|bitcoin|btc|ethereum|eth|usdt|"
    r"crypto(?:monnaie|currency)?|wallet address|adresse (?:de )?portefeuille)\b",
    re.IGNORECASE,
)
# Le chantage ne demande pas, il menace : aucune formule de politesse à
# repérer, aucune urgence au sens habituel. Sans motif propre, un tel message
# passait pour dépourvu de pression, et se voyait même créditer de ne rien
# demander de sensible.
#
# Deux registres, parce que les mots du chantage n'ont pas tous le même poids.
# Certains ne se disent qu'en menaçant : « sextorsion », « rançon », « je vais
# publier », « verse-moi 500 ». D'autres appartiennent aussi au vocabulaire
# ordinaire - une confirmation d'examen surveillé demande une webcam, un avis
# de sécurité parle de comptes piratés. Pris isolément, ces mots-là ont fait
# porter une accusation de chantage à des messages qui n'en étaient pas ; il
# en faut deux pour que le faisceau tienne. Un vrai chantage les accumule
# toujours : il pirate, il filme, il réclame et il menace de diffuser.
_EXTORTION_EXPLICITE = re.compile(
    r"\b(sextorsion|ransom|ran[çc]on|"
    r"compromising (?:video|photo)|vid[ée]o compromettante|"
    r"recorded (?:you|your)|enregistr[ée] (?:votre|ta) (?:webcam|cam[ée]ra)|"
    r"(?:send|pay|transfer)\s+me\s+(?:\$|€|\d+)|"
    r"(?:verse[rz]?|paye[rz]?)[-\s]moi|"
    r"(?:i|je) (?:will|vais) (?:publish|send|share|diffuser|envoyer|publier))\b",
    re.IGNORECASE,
)

_EXTORTION_INDICE = re.compile(
    r"\b(hacked|pirat[ée]|compromis|stolen|vol[ée]es?|"
    r"webcam|humiliat|"
    r"(?:send|pay|transfer|verse[rz]?|payez)\s+(?:\$|€|\d+)|"
    r"regain access|r[ée]cup[ée]rer l.acc[eè]s)\b",
    re.IGNORECASE,
)


def _extorsion(sample: str) -> bool:
    """Ce texte menace-t-il pour obtenir quelque chose ?

    Un mot explicite suffit ; les mots ambigus doivent être au moins deux, et
    deux mots *différents* - un texte qui répète « webcam » ne menace pas
    davantage qu'un texte qui le dit une fois.
    """
    if _EXTORTION_EXPLICITE.search(sample):
        return True
    indices = {
        trouve.group(0).casefold() for trouve in _EXTORTION_INDICE.finditer(sample)
    }
    return len(indices) >= 2
_PAYMENT = re.compile(
    r"\b(paiement|payment|facture|invoice|remboursement|refund|"
    r"carte bancaire|credit card|d[ée]bit)\b",
    re.IGNORECASE,
)
_DELIVERY = re.compile(r"\b(colis|livraison|delivery|shipment|tracking)\b", re.IGNORECASE)
_REQUEST_VERB = re.compile(
    r"\b(saisissez|renseignez|entrez|indiquez|communiquez|envoyez|confirmez|"
    r"fournissez|partagez|v[ée]rifie[rz]?|provide|enter|submit|send|confirm|share|verify)\b",
    re.IGNORECASE,
)
_DISCLOSURE_VERB = re.compile(
    r"\b(communiquez|envoyez|fournissez|partagez|r[ée]pondez|"
    r"provide|send|share|reply)\b",
    re.IGNORECASE,
)
_ACTION_PATTERNS = {
    "open_link": re.compile(
        r"\b(clique[rz]?|ouvrez|ouvrir|open|follow (?:the )?link)\b",
        re.IGNORECASE,
    ),
    "download": re.compile(r"\b(t[ée]l[ée]charge[rz]?|download)\b", re.IGNORECASE),
    "reply": re.compile(r"\b(r[ée]pondez|reply)\b", re.IGNORECASE),
    "call": re.compile(r"\b(appelez|call)\b", re.IGNORECASE),
    "scan": re.compile(r"\b(scanne[rz]?|scan)\b", re.IGNORECASE),
    "authenticate": re.compile(
        r"\b(connectez-vous|connexion|login|sign[ -]?in|authentif)\b",
        re.IGNORECASE,
    ),
    "transfer_money": _FINANCIAL_TRANSFER,
    "pay": _PAYMENT,
}
_SENSITIVE_PATTERNS = {
    "password": re.compile(r"\b(mot de passe|password|passwd|passcode)\b", re.IGNORECASE),
    "one_time_code": re.compile(
        r"\b(otp|2fa|mfa|code (?:de )?(?:s[ée]curit[ée]|v[ée]rification|connexion)|"
        r"verification code|security code)\b",
        re.IGNORECASE,
    ),
    "bank_account": _FINANCIAL_TRANSFER,
    "payment_card": re.compile(
        r"\b(carte bancaire|num[ée]ro de carte|cvv|cvc|credit card|card number)\b",
        re.IGNORECASE,
    ),
    "identity": re.compile(
        r"\b(pi[eè]ce d.identit[ée]|passeport|passport|social security|"
        r"num[ée]ro de s[ée]curit[ée] sociale)\b",
        re.IGNORECASE,
    ),
}
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/])")
_URL = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_HIDDEN_HTML = re.compile(
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\D|$)|"
    r"font-size\s*:\s*0(?:px|pt|em|rem|\D))",
    re.IGNORECASE,
)
_ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}

# D\u00e9coupage en mots pour comparer vocabulaire visible et vocabulaire cach\u00e9
# (CONTENT-013) : \w+ Unicode, insensible \u00e0 la casse.
_WORD_RE = re.compile(r"\w+", re.UNICODE)


def _word_set(sample: str) -> set[str]:
    return {mot.casefold() for mot in _WORD_RE.findall(sample)}

# Un message qui s'adresse \u00e0 un syst\u00e8me d'analyse, jamais au lecteur : c'est
# une injection de prompt. Les motifs sont ceux des campagnes r\u00e9elles - en
# anglais comme en fran\u00e7ais - et n'ont aucune raison d'exister dans du courrier
# honn\u00eate.
_PROMPT_INJECTION = re.compile(
    r"(?:ignore|disregard|forget|oublie[rz]?|ignore[rz]?)\s+"
    r"(?:all\s+|the\s+|any\s+|previous\s+|toute[s]?\s+|les\s+|pr[ée]c[ée]dent)"
    r"[^.\n]{0,40}(?:instruction|consigne|prompt|context|r[èe]gle)"
    r"|(?:classif(?:y|ie[rz]?)|mark|classe[rz]?|marque[rz]?|traite[rz]?|"
    r"consider[e]?[rz]?|r[ée]pond[srez]*)\s+[^.\n]{0,40}"
    r"(?:as\s+|comme\s+|en\s+)?(?:benign|safe|legitimate|not\s+spam|ham|"
    r"l[ée]gitime|non[ -]spam|sans\s+risque|inoffensi)"
    r"|LLM[_ ]?IGNORE|</?(?:system|assistant|user)>|"
    r"(?:^|\n)\s*(?:system|assistant|user)\s*:\s|"
    r"you\s+are\s+(?:a|an|now)\s+|tu\s+es\s+(?:un|une|maintenant)\s+|"
    r"as\s+an?\s+ai\b|en\s+tant\s+qu[e']\s+(?:ia|intelligence)",
    re.IGNORECASE,
)


def _message_purpose(sample: str) -> str:
    if _FINANCIAL_TRANSFER.search(sample):
        return "financial_transfer"
    if _PAYMENT.search(sample):
        return "payment"
    if _ONE_TIME_PURPOSE.search(sample):
        return "one_time_authentication"
    if _ACCOUNT_SECURITY.search(sample):
        return "account_security"
    if _DELIVERY.search(sample):
        return "parcel_delivery"
    return "unknown"


def _sensitive_context(sample: str) -> tuple[list[str], list[str]]:
    """Distingue une donnée citée d'une donnée effectivement demandée."""
    mentioned: list[str] = []
    requested: list[str] = []
    for category, pattern in _SENSITIVE_PATTERNS.items():
        matches = list(pattern.finditer(sample))
        if not matches:
            continue
        mentioned.append(category)
        if any(
            _REQUEST_VERB.search(sample[max(0, match.start() - 100): match.end() + 100])
            for match in matches
        ):
            requested.append(category)
    return mentioned, requested


def _splits_a_word(sample: str, index: int) -> bool:
    """Vrai quand l'invisible s'insère entre deux caractères pleins.

    C'est la seule position où un caractère de largeur nulle change la lecture
    d'un mot : « p‌a‌y‌p‌a‌l » se lit comme « paypal » mais ne se cherche plus,
    et « paypal‌.com » casse un domaine. Partout ailleurs il ne cache rien.
    """
    before = sample[index - 1] if index > 0 else " "
    after = sample[index + 1] if index + 1 < len(sample) else " "
    return _is_solid(before) and _is_solid(after)


def _is_solid(char: str) -> bool:
    return not char.isspace() and char not in _ZERO_WIDTH and char != "\xa0"


def _obfuscation_markers(sample: str) -> list[dict[str, object]]:
    """Retourne des pièces montrables, sans confondre un jeton d'URL avec du texte."""
    markers: list[dict[str, object]] = []
    url_spans = [match.span() for match in _URL.finditer(sample)]
    for index, char in enumerate(sample):
        if char in _ZERO_WIDTH:
            # Tout emailing commercial intercale des invisibles après le texte
            # d'aperçu, pour empêcher la boîte de réception de déborder sur le
            # corps. Sur les 68 messages qui portaient cet indice, 5 636
            # invisibles pour 31 coupant réellement un mot : le reste pesait
            # une charge adverse sur du courrier ordinaire. Le fait demeure
            # compté, il cesse seulement d'accuser.
            markers.append(
                {
                    "type": "zero_width"
                    if _splits_a_word(sample, index)
                    else "zero_width_padding",
                    "codepoint": f"U+{ord(char):04X}",
                    "offset": index,
                }
            )
        elif unicodedata.bidirectional(char) in {"RLE", "LRE", "RLO", "LRO", "PDF"}:
            markers.append(
                {"type": "bidi_control", "codepoint": f"U+{ord(char):04X}", "offset": index}
            )
    for match in _BASE64.finditer(sample):
        if any(start <= match.start() < end for start, end in url_spans):
            continue
        token = match.group(0)
        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) < 24:
            continue
        printable = sum(byte in b"\t\n\r" or 32 <= byte <= 126 for byte in decoded)
        markers.append(
            {
                "type": "base64_like_text",
                "length": len(token),
                "preview": token[:16] + "…" + token[-8:],
                "decoded_kind": "mostly_text" if printable / len(decoded) >= 0.85 else "binary",
            }
        )
    return markers[:20]


# Les écritures dont les lettres imitent les lettres latines. Un mot qui
# mélange l'une d'elles au latin n'existe dans aucune langue : c'est un
# déguisement de mot, fait pour passer les filtres sans changer la lecture.
_LOOKALIKE_SCRIPTS = ("CYRILLIC", "GREEK")
_WORD = re.compile(r"[^\W\d_]+", re.UNICODE)


def _letter_script(char: str) -> str:
    name = unicodedata.name(char, "")
    for script in ("LATIN", *_LOOKALIKE_SCRIPTS):
        if name.startswith(script):
            return script
    return ""


def _mixed_script_words(sample: str) -> list[dict[str, object]]:
    """Les mots qui mélangent l'alphabet latin et un alphabet sosie.

    Un texte entièrement russe ou grec est une langue, jamais relevé ici : le
    mélange ne se constate qu'à l'intérieur d'un même mot, là où « prіority »
    (і cyrillique) devient indiscernable de « priority » à l'œil.
    """
    releves: list[dict[str, object]] = []
    for match in _WORD.finditer(sample):
        word = match.group(0)
        if len(word) < 3:
            continue
        scripts = {script for char in word if (script := _letter_script(char))}
        if "LATIN" in scripts and scripts.intersection(_LOOKALIKE_SCRIPTS):
            releves.append(
                {
                    "word": word[:40],
                    "scripts": sorted(scripts),
                    "offset": match.start(),
                }
            )
            if len(releves) >= 20:
                break
    return releves


class ContentHook(EvidenceHook):
    name: ClassVar[str] = "content"
    version: ClassVar[str] = "2.0.0"

    async def observe(
        self, context: InvestigationContext
    ) -> tuple[list[Clue], dict[str, object]]:
        message = context.parsed.message
        subject = str(message.get("subject") or "")
        text = str(message.get("body_text") or "")
        html = str(message.get("body_html") or "")
        visible_html = visible_html_text(html)
        # Un BOM au début d'un champ est un artefact d'encodage, pas une
        # injection zero-width au milieu du texte.
        subject_visible = subject.removeprefix("\ufeff")
        sample = f"{subject_visible}\n{text}\n{visible_html[:100_000]}"
        urgency = len(_URGENCY.findall(sample))
        purpose = _message_purpose(sample)
        mentioned_sensitive, requested_sensitive = _sensitive_context(sample)
        action_types = sorted(
            name for name, pattern in _ACTION_PATTERNS.items() if pattern.search(sample)
        )
        actions = len(action_types)
        intrinsic_expiration = bool(
            urgency
            and purpose == "one_time_authentication"
            and _INTRINSIC_EXPIRATION.search(sample)
        )
        extortion = _extorsion(sample)
        # Une menace suffit : elle n'a pas besoin du vocabulaire de l'urgence
        # pour contraindre, et c'est précisément ce qui la rendait invisible.
        coercive_pressure = bool(urgency and _COERCION.search(sample)) or extortion
        expected_one_time_input = bool(
            purpose == "one_time_authentication"
            and requested_sensitive
            and set(requested_sensitive) <= {"one_time_code"}
            and not _DISCLOSURE_VERB.search(sample)
            and not coercive_pressure
        )
        urgency_kind = (
            "intrinsic_expiration"
            if intrinsic_expiration
            else "coercive_pressure"
            if coercive_pressure
            else "generic_temporal_pressure"
            if urgency
            else "none"
        )
        obfuscation_markers = _obfuscation_markers(sample)
        zero_width = sum(
            marker["type"] == "zero_width" for marker in obfuscation_markers
        )
        bidi = sum(
            marker["type"] == "bidi_control" for marker in obfuscation_markers
        )
        base64_tokens = sum(
            marker["type"] == "base64_like_text" for marker in obfuscation_markers
        )
        hidden_html = len(_HIDDEN_HTML.findall(html))
        letters = [char for char in subject if char.isalpha()]
        uppercase_ratio = (
            sum(char.isupper() for char in letters) / len(letters) if letters else 0.0
        )
        clues: list[Clue] = []
        content_facts = context.parsed.facts.get("content", {})
        html_forms = (
            int(content_facts.get("html_form_count", 0))
            if isinstance(content_facts, dict)
            else 0
        )
        html_scripts = (
            int(content_facts.get("html_script_count", 0))
            if isinstance(content_facts, dict)
            else 0
        )

        if urgency and urgency_kind != "intrinsic_expiration":
            clues.append(
                Clue(
                    "CONTENT-001",
                    "CONTENT_URGENCY",
                    "adverse",
                    min(45, (22 if coercive_pressure else 8) + urgency * 5),
                    0.75,
                    (
                        f"Le texte exerce une pression {urgency_kind} dans un contexte "
                        f"{purpose}; ce contexte doit expliquer pourquoi l’action ne peut pas attendre."
                    ),
                    {"matches": urgency, "urgency_kind": urgency_kind, "purpose": purpose},
                    {"source": "subject+body"},
                )
            )
        elif intrinsic_expiration:
            clues.append(
                Clue(
                    "CONTENT-008",
                    "CONTENT_EXPECTED_ONE_TIME_EXPIRATION",
                    "neutral",
                    0,
                    0.9,
                    "La limite de temps est intrinsèque à un lien ou code d’authentification à usage unique; elle n’est pas, seule, une pression frauduleuse.",
                    {"urgency_kind": urgency_kind, "purpose": purpose},
                    {"source": "content-context"},
                )
            )
        if requested_sensitive and not expected_one_time_input:
            categories = ", ".join(requested_sensitive)
            clues.append(
                Clue(
                    "CONTENT-002",
                    "CONTENT_SENSITIVE_REQUEST",
                    "adverse",
                    min(45, 18 + len(requested_sensitive) * 8),
                    0.82,
                    f"Le texte demande explicitement une donnée sensible de catégorie : {categories}.",
                    {"categories": requested_sensitive, "purpose": purpose},
                    {"source": "visible-subject+body"},
                )
            )
        elif expected_one_time_input:
            clues.append(
                Clue(
                    "CONTENT-010",
                    "CONTENT_EXPECTED_ONE_TIME_CODE_INPUT",
                    "neutral",
                    0,
                    0.9,
                    "Le message demande d’utiliser un code à usage unique dans un parcours d’authentification, sans demander de le transmettre à un tiers.",
                    {
                        "categories": requested_sensitive,
                        "purpose": purpose,
                        "disclosure_requested": False,
                    },
                    {"source": "content-context"},
                )
            )
        if (
            urgency_kind in {"coercive_pressure", "generic_temporal_pressure"}
            and actions
            and (
                (requested_sensitive and not expected_one_time_input)
                or purpose == "financial_transfer"
            )
        ):
            clues.append(
                Clue(
                    "CONTENT-003",
                    "CONTENT_SOCIAL_ENGINEERING_COMBINATION",
                    "adverse",
                    75 if coercive_pressure else 50,
                    0.9,
                    (
                        f"Le contexte {purpose} combine une pression {urgency_kind}, "
                        f"les actions {', '.join(action_types)} et une demande sensible "
                        f"{', '.join(requested_sensitive) or 'financière'}."
                    ),
                    {
                        "urgency_kind": urgency_kind,
                        "purpose": purpose,
                        "action_types": action_types,
                        "sensitive_categories": requested_sensitive,
                    },
                    {"source": "content-context-correlation"},
                )
            )
        # Le nom affiché entre dans le champ du déguisement : « Аmazon » avec
        # un А cyrillique se lit comme la marque, et n'apparaît nulle part
        # ailleurs que dans l'en-tête From.
        mixed_words = _mixed_script_words(
            f"{message.get('from_header') or ''}\n{sample}"
        )
        if mixed_words:
            clues.append(
                Clue(
                    "CONTENT-012",
                    "CONTENT_MIXED_SCRIPT",
                    "adverse",
                    min(80, 55 + 5 * len(mixed_words)),
                    0.9,
                    "Des mots mélangent l’alphabet latin et un alphabet sosie "
                    "(lettres qui imitent des lettres latines) : "
                    + ", ".join(str(releve["word"]) for releve in mixed_words[:5])
                    + ".",
                    {"words": mixed_words},
                    {"source": "unicode:from+subject+body"},
                )
            )
        # Texte masqué par CSS inline : séparé du visible, il ne fausse plus la
        # lecture, et son volume trahit le « salting ». Un preheader légitime
        # est court et unique ; on ne compte que le masquage substantiel, et
        # significatif par rapport au texte réellement lu.
        texte_visible, texte_cache = split_visible_hidden(html)
        # Injection de prompt : le message s'adresse au filtre, souvent dans du
        # texte masqué. On scanne l'ensemble - sujet, visible, caché - et on
        # pèse plus lourd quand le motif est caché.
        injection_zone = f"{subject_visible}\n{text}\n{texte_visible}\n{texte_cache}"
        injection = _PROMPT_INJECTION.search(injection_zone)
        if injection:
            cache = bool(_PROMPT_INJECTION.search(texte_cache))
            clues.append(
                Clue(
                    "CONTENT-014",
                    "CONTENT_PROMPT_INJECTION_ATTEMPT",
                    "adverse",
                    80 if cache else 65,
                    0.9,
                    "Le message contient une instruction adressée à un système "
                    "d’analyse automatique" + (" (masquée)" if cache else "")
                    + " : tentative de manipulation du filtre.",
                    {"match": injection.group(0)[:80], "hidden": cache},
                    {"source": "subject+visible+hidden"},
                )
            )
        hidden_chars = len(texte_cache.strip())
        visible_chars = len(visible_html.strip()) or 1
        # Un gabarit responsive (variante mobile/desktop, repli mso) cache
        # légitimement de grands blocs qui DUPLIQUENT le texte visible : ce
        # n'est pas du salting. Le salting introduit du vocabulaire absent du
        # visible. On ne mesure donc que la part inédite du texte caché,
        # mot par mot (\w+, casefold), contre le même seuil.
        vocabulaire_visible = _word_set(f"{texte_visible}\n{text}")
        mots_caches_inedits = [
            mot for mot in _WORD_RE.findall(texte_cache) if mot.casefold() not in vocabulaire_visible
        ]
        novel_chars = sum(len(mot) for mot in mots_caches_inedits)
        if novel_chars >= 200 and novel_chars / visible_chars >= 0.2:
            clues.append(
                Clue(
                    "CONTENT-013",
                    "CONTENT_HIDDEN_TEXT_SALTING",
                    "adverse",
                    min(70, 30 + novel_chars // 100),
                    0.85,
                    "Le message contient un volume important de texte masqué par "
                    "CSS, invisible au lecteur, et absent du texte visible : "
                    "dilution des filtres ou instructions cachées.",
                    {
                        "hidden_chars": hidden_chars,
                        "visible_chars": visible_chars,
                        "novel_chars": novel_chars,
                        "ratio": round(novel_chars / visible_chars, 3),
                    },
                    {"source": "html:inline-style"},
                )
            )
        material_obfuscation = bidi > 0 or zero_width >= 2 or base64_tokens > 0
        if material_obfuscation:
            clues.append(
                Clue(
                    "CONTENT-004",
                    "CONTENT_OBFUSCATION",
                    "adverse",
                    min(80, 24 + bidi * 20 + zero_width * 8 + base64_tokens * 12),
                    0.82,
                    "Le texte visible présente des marqueurs matériels d’offuscation : "
                    + ", ".join(
                        (
                            str(marker.get("codepoint"))
                            if marker["type"] != "base64_like_text"
                            else str(marker.get("preview"))
                        )
                        for marker in obfuscation_markers[:5]
                    )
                    + ".",
                    {
                        "zero_width": zero_width,
                        "bidi_controls": bidi,
                        "base64_like_tokens": base64_tokens,
                        "hidden_html_patterns": hidden_html,
                        "markers": obfuscation_markers,
                    },
                    {"source": "unicode+html"},
                )
            )
        # Un envoi de masse n'a aucune raison d'exercer une pression : son
        # absence ne dit donc rien de sa légitimité et ne peut pas le créditer.
        # Le cadre d'envoi est décrit par le hook nature ; seule la question
        # « ce message est-il coercitif ? » se juge ici.
        if extortion:
            clues.append(
                Clue(
                    "CONTENT-011",
                    "CONTENT_EXTORTION",
                    "adverse",
                    65,
                    0.85,
                    "Le message menace de divulguer des données ou réclame un "
                    "versement pour s’en abstenir.",
                    {
                        "purpose": purpose,
                        "payment_channel": bool(
                            _FINANCIAL_TRANSFER.search(sample)
                        ),
                    },
                )
            )
        if (
            urgency_kind not in {"coercive_pressure", "generic_temporal_pressure"}
            and not requested_sensitive
            and purpose != "financial_transfer"
            and not is_unsolicited_style(context.parsed)
        ):
            clues.append(
                Clue(
                    "CONTENT-007",
                    "CONTENT_NO_SENSITIVE_PRESSURE",
                    # Ne rien trouver n'établit rien. Ce constat décrit une
                    # lecture, il ne crédite pas le message : les motifs
                    # connus sont toujours en retard d'une formulation.
                    "neutral",
                    0,
                    0.8,
                    "Aucune pression ni demande sensible n’a été repérée par les motifs connus.",
                    {
                        "urgency_matches": urgency,
                        "urgency_kind": urgency_kind,
                        "sensitive_categories_mentioned": mentioned_sensitive,
                        "sensitive_categories_requested": requested_sensitive,
                        "action_types": action_types,
                    },
                    {"source": "visible-subject+body"},
                )
            )
        if purpose == "one_time_authentication" and not requested_sensitive:
            clues.append(
                Clue(
                    "CONTENT-009",
                    "CONTENT_ONE_TIME_CREDENTIAL_PROVIDED_NOT_REQUESTED",
                    "favorable",
                    18,
                    0.85,
                    "Le message fournit un lien ou code à usage unique sans demander au destinataire de révéler un secret.",
                    {
                        "purpose": purpose,
                        "sensitive_categories_mentioned": mentioned_sensitive,
                        "sensitive_categories_requested": requested_sensitive,
                    },
                    {"source": "content-context"},
                )
            )
        if len(letters) >= 12 and uppercase_ratio >= 0.75:
            clues.append(
                Clue(
                    "CONTENT-005",
                    "CONTENT_SUBJECT_MOSTLY_UPPERCASE",
                    "adverse",
                    12,
                    0.7,
                    "L’objet est majoritairement écrit en majuscules.",
                    {"uppercase_ratio": round(uppercase_ratio, 3)},
                    {"source": "header:subject"},
                )
            )
        if html_forms or html_scripts:
            clues.append(
                Clue(
                    "CONTENT-006",
                    "CONTENT_ACTIVE_HTML",
                    "adverse",
                    min(85, 50 + html_forms * 10 + html_scripts * 15),
                    0.95,
                    "Le corps HTML contient un formulaire ou un script actif.",
                    {"forms": html_forms, "scripts": html_scripts},
                    {"source": "html-structure"},
                )
            )
        return clues, {
            "urgency_matches": urgency,
            "action_matches": actions,
            "content_context": {
                "purpose": purpose,
                "urgency_kind": urgency_kind,
                "action_types": action_types,
                "sensitive_categories_mentioned": mentioned_sensitive,
                "sensitive_categories_requested": requested_sensitive,
                "coercive_pressure": coercive_pressure,
                "intrinsic_expiration": intrinsic_expiration,
                "expected_one_time_input": expected_one_time_input,
            },
            "zero_width_count": zero_width,
            "bidi_control_count": bidi,
            "base64_like_token_count": base64_tokens,
            "hidden_html_patterns": hidden_html,
            "hidden_html_is_template_fact_only": True,
            "visible_html_characters": len(visible_html),
            "subject_uppercase_ratio": round(uppercase_ratio, 6),
            "html_form_count": html_forms,
            "html_script_count": html_scripts,
        }
