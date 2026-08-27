"""Nature de l'envoi : dans quel cadre ce message arrive-t-il ?

Le reste du Code cherche la tromperie : usurpation, coercition, collecte de
secrets. Un envoi commercial de masse n'emprunte aucun de ces chemins, et son
absence de pression finissait donc par le créditer d'un indice favorable.

Ce hook décrit le cadre d'envoi à partir de faits d'en-têtes normalisés, puis le
registre du discours. Il ne décide rien : un envoi de masse reste parfaitement
légitime quand le destinataire l'a demandé. C'est la conjonction avec l'absence
d'historique, établie plus tard, qui fait le caractère non sollicité.
"""

from __future__ import annotations

import re
from typing import ClassVar

from sentimail_v3.observation.dossier.hook import EvidenceHook
from sentimail_v3.observation.dossier.hooks.visible_text import visible_html_text
from sentimail_v3.observation.dossier.models import Clue, InvestigationContext
from sentimail_v3.observation.parser import ParsedMessage

_BULK_HEADERS = (
    "list-unsubscribe",
    "list-unsubscribe-post",
    "list-id",
    "list-help",
    "list-post",
    "feedback-id",
    "x-csa-complaints",
    "x-report-abuse",
)
_BULK_PRECEDENCE = {"bulk", "list", "junk"}
_AUTOMATED_HEADER = "auto-submitted"

# Registres de discours propres aux envois non sollicités. Ils décrivent une
# rhétorique, jamais un produit ou un secteur : aucune marque, aucun expéditeur.
_UNVERIFIABLE_CLAIM = re.compile(
    r"\b(miracle|miraculeu\w+|r[ée]volutionnaire|breakthrough|"
    r"secret (?:que|des|de la)|secret that|what doctors|ce que les m[ée]decins|"
    r"suppress\w*|cach\w+ (?:par|aux)|big pharma|cartels?|"
    r"guaranteed|garanti\w*|sans (?:effort|r[ée]gime)|effortless|"
    r"changes everything|change tout|"
    # Rhétorique de cure : un verbe spectaculaire, une promesse chiffrée en
    # jours, ou le « truc simple », récurrents dans le démarchage santé.
    r"revers\w+|invers\w+|restore[sd]?|restaure\w*|flush\w* out|"
    r"dissolv\w+|melts?|[ée]limin\w+|fatal weakness|"
    r"in \d+ days?|en \d+ jours?|\d+[- ]?day|"
    r"simple (?:\w+ )?(?:trick|routine|ritual|recipe|method|hack)|"
    r"one weird (?:trick|tip))\b",
    re.IGNORECASE,
)
_HEALTH_PROMISE = re.compile(
    r"\b(perte de poids|weight loss|br[ûu]le[rz]? (?:les )?graisses|fat burn\w*|"
    r"anti[- ]?[âa]ge|anti[- ]?aging|rem[eè]de naturel|natural (?:solution|remedy|formula)|"
    r"compl[ée]ment alimentaire|supplement|libido|puissance sexuelle|"
    r"m[ée]moire|brain (?:health|power)|cardiovascular|glyc[ée]mie|blood sugar|"
    # Organes, fonctions et affections que le démarchage santé cible sans preuve.
    r"cognitiv\w+|cognition|neural|neuro\w*|inflammation|"
    r"blood flow|circulation (?:sanguine)?|m[ée]tabolis\w+|"
    r"detox\w*|cleanse|immunit\w+|immune|parasite|glucose|"
    r"arthrit\w+|joint pain|gut health|intestin\w*)\b",
    re.IGNORECASE,
)
_WEALTH_PROMISE = re.compile(
    r"\b(revenus? passifs?|passive income|gagnez? \d|earn \$?\d|"
    r"devenir riche|get rich|investissement garanti|guaranteed returns?|"
    r"crypto (?:gains?|profits?)|trading (?:signals?|bot))\b",
    re.IGNORECASE,
)


def sending_mode(parsed: ParsedMessage) -> dict[str, object]:
    """Cadre d'envoi déduit des seuls en-têtes normalisés du message."""
    grouped: dict[str, list[str]] = {}
    for header in parsed.headers:
        grouped.setdefault(str(header["name_normalized"]), []).append(
            str(header["value_decoded"])
        )
    present = [name for name in _BULK_HEADERS if name in grouped]
    precedence = " ".join(grouped.get("precedence", [])).strip().casefold()
    bulk_precedence = precedence in _BULK_PRECEDENCE
    automated = any(
        value.strip().casefold().startswith(("auto-generated", "auto-replied"))
        for value in grouped.get(_AUTOMATED_HEADER, [])
    )
    bulk = bool(present) or bulk_precedence
    return {
        "mode": "bulk" if bulk else "automated" if automated else "conversational",
        "bulk_headers_present": present,
        "precedence": precedence or None,
        "automated": automated,
        "unsubscribe_offered": "list-unsubscribe" in grouped,
    }


def is_bulk_mailing(parsed: ParsedMessage) -> bool:
    return sending_mode(parsed)["mode"] == "bulk"


def _claim_registers(sample: str) -> list[str]:
    registers: list[str] = []
    if _HEALTH_PROMISE.search(sample):
        registers.append("health")
    if _WEALTH_PROMISE.search(sample):
        registers.append("wealth")
    return registers


def _visible_sample(parsed: ParsedMessage) -> str:
    message = parsed.message
    return "\n".join(
        (
            str(message.get("subject") or ""),
            str(message.get("body_text") or "")[:100_000],
            visible_html_text(str(message.get("body_html") or ""))[:100_000],
        )
    )


# Les mots-outils sont ce qu'une langue répète sans y penser : ils survivent à
# la traduction automatique et au vocabulaire du sujet, là où les mots pleins
# varient d'un message à l'autre. Constater la langue ne juge rien - c'est le
# rapport à la langue habituelle du destinataire qui, lui, parlera.
_LANGUAGE_MARKERS: dict[str, frozenset[str]] = {
    "fr": frozenset(
        "le la les de des du et est vous nous votre notre pour dans avec sur "
        "que qui ne pas plus cette ces son ses par au aux une un être avoir".split()
    ),
    "en": frozenset(
        "the of and to in is you your we our for with that this it not are "
        "have has will can from they their been would there".split()
    ),
    "es": frozenset(
        "el la los las de del y es usted su nuestro para con que no mas esta "
        "estos por un una ser tener como".split()
    ),
    "de": frozenset(
        "der die das und ist sie ihre unser fur mit dass nicht mehr diese "
        "von zu ein eine sein haben werden".split()
    ),
    "it": frozenset(
        "il lo la le di del e sono voi nostro per con che non piu questa "
        "questi da un una essere avere come".split()
    ),
}
_WORD = re.compile(r"[a-zà-öø-ÿ]+", re.IGNORECASE)


def detect_language(sample: str) -> str | None:
    """La langue dominante du texte visible, ou None si l'échantillon est court."""
    words = [word.casefold() for word in _WORD.findall(sample)]
    if len(words) < 12:
        return None
    scores = {
        language: sum(1 for word in words if word in markers)
        for language, markers in _LANGUAGE_MARKERS.items()
    }
    best = max(scores, key=lambda language: scores[language])
    if scores[best] < 3:
        return None
    runner_up = max(
        (score for language, score in scores.items() if language != best), default=0
    )
    return best if scores[best] > runner_up else None


def promotional_claims(parsed: ParsedMessage) -> dict[str, object]:
    """Promesses invérifiables : une rhétorique, jamais un produit ni un secteur."""
    sample = _visible_sample(parsed)
    return {
        "claim_matches": len(_UNVERIFIABLE_CLAIM.findall(sample)),
        "registers": _claim_registers(sample),
    }


def is_unsolicited_style(parsed: ParsedMessage) -> bool:
    """Diffusion déclarée, ou sollicitation qui en emprunte la rhétorique.

    Les envois de masse honnêtes se déclarent par leurs en-têtes. Une
    sollicitation qui ne se déclare pas mais promet l'invérifiable relève du
    même registre : dans les deux cas, l'absence de pression ne prouve rien.
    """
    if is_bulk_mailing(parsed):
        return True
    claims = promotional_claims(parsed)
    return bool(claims["claim_matches"] and claims["registers"])


class NatureHook(EvidenceHook):
    name: ClassVar[str] = "nature"
    version: ClassVar[str] = "1.0.0"

    async def observe(
        self, context: InvestigationContext
    ) -> tuple[list[Clue], dict[str, object]]:
        parsed = context.parsed
        mode = sending_mode(parsed)
        promotional = promotional_claims(parsed)
        claims = int(promotional["claim_matches"])
        registers = list(promotional["registers"])
        clues: list[Clue] = []
        language = detect_language(_visible_sample(parsed))
        if language:
            # Constater la langue n'accuse personne : c'est son écart avec la
            # langue habituelle du destinataire qui informe, et cet écart ne
            # s'apprécie qu'avec l'historique. L'indice existe pour que le fait
            # soit étiqueté, jugé et appris comme les autres.
            clues.append(
                Clue(
                    "NATURE-005",
                    "NATURE_MESSAGE_LANGUAGE",
                    "neutral",
                    0,
                    0.8,
                    f"Le message est rédigé en {language}.",
                    {"language": language},
                    {"source": "visible-subject+body"},
                )
            )
        if mode["mode"] == "bulk":
            clues.append(
                Clue(
                    "NATURE-001",
                    "NATURE_BULK_MAILING",
                    "neutral",
                    0,
                    1.0,
                    "Le message est un envoi de masse identifié par ses en-têtes.",
                    {
                        "bulk_headers_present": mode["bulk_headers_present"],
                        "precedence": mode["precedence"],
                        "unsubscribe_offered": mode["unsubscribe_offered"],
                    },
                    {"source": "headers:list-*,precedence,feedback-id"},
                )
            )
        if claims and registers:
            clues.append(
                Clue(
                    "NATURE-003",
                    "NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS",
                    "adverse",
                    25,
                    0.7,
                    "L’envoi promeut des promesses invérifiables dans un registre "
                    + " et ".join(registers)
                    + ".",
                    {
                        "claim_matches": claims,
                        "registers": registers,
                        "sending_mode": mode["mode"],
                    },
                    {"source": "visible-subject+body"},
                )
            )
            # Les diffusions honnêtes se déclarent et offrent une sortie. Une
            # sollicitation qui promet l'invérifiable sans jamais permettre de
            # s'en défaire n'a pas de destinataire consentant.
            if not mode["unsubscribe_offered"]:
                clues.append(
                    Clue(
                        "NATURE-004",
                        "NATURE_SOLICITATION_WITHOUT_OPT_OUT",
                        "adverse",
                        20,
                        0.75,
                        "La sollicitation n’offre aucun moyen normalisé de se "
                        "désinscrire.",
                        {
                            "sending_mode": mode["mode"],
                            "bulk_headers_present": mode["bulk_headers_present"],
                            "registers": registers,
                        },
                        {"source": "headers:list-unsubscribe"},
                    )
                )
        return clues, {
            "sending_mode": mode["mode"],
            "bulk_headers_present": mode["bulk_headers_present"],
            "precedence": mode["precedence"],
            "unsubscribe_offered": mode["unsubscribe_offered"],
            "automated": mode["automated"],
            "claim_matches": claims,
            "claim_registers": registers,
            "language": detect_language(_visible_sample(parsed)),
        }
