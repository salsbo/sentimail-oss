from __future__ import annotations

import re
from typing import ClassVar

from sentimail_v3.observation.dossier.hook import EvidenceHook
from sentimail_v3.observation.dossier.models import Clue, InvestigationContext

_SCORE = re.compile(r"\[\s*(-?\d+(?:\.\d+)?)\s*/\s*(\d+(?:\.\d+)?)\s*\]")
_SYMBOL = re.compile(r"\b([A-Z][A-Z0-9_]{2,})\((-?\d+(?:\.\d+)?)\)")
_MATERIAL = {
    "CLAM_VIRUS",
    "MALWARE",
}
_MATERIAL_FRAGMENTS = (
    "MALWARE",
    "VIRUS",
)
_REPUTATION_FRAGMENTS = (
    "SURBL",
    "SPAMHAUS",
    "RBL",
    "DBL",
)
_WEAK_TRANSACTIONAL_ARTIFACTS = {"FORGED_SENDER"}
# Des déguisements que Rspamd relève et que personne ne lisait : un objet ou
# un expéditeur encodés en base64 sans raison (« C I C » l'était, pour passer
# les filtres de mots). C'est un procédé, pas un accident d'encodage - et sans
# indice, il n'entrait ni au jugement ni à l'apprentissage (M-490357,
# 6 septembre 2026).
#
# ZERO_FONT n'en fait plus partie (13 septembre 2026). Le texte en taille zéro
# est le texte d'aperçu des gabarits d'envoi : sur 147 messages marqués, la
# quasi-totalité étaient authentifiés et ordinaires, et un code Dashlane
# restait retenu pour cette seule charge. Le texte caché qui trompe se mesure
# par CONTENT_HIDDEN_TEXT_SALTING, sur son contenu, pas sur sa présence.
_OBFUSCATION = {"SUBJ_EXCESS_BASE64", "FROM_EXCESS_BASE64"}


class RspamdHook(EvidenceHook):
    name: ClassVar[str] = "rspamd"
    version: ClassVar[str] = "1.3.0"

    async def observe(
        self, context: InvestigationContext
    ) -> tuple[list[Clue], dict[str, object]]:
        values = [
            str(row["value_decoded"])
            for row in context.parsed.headers
            if row["name_normalized"] == "x-spamd-result"
        ]
        if not values:
            return [
                Clue(
                    "RSPAMD-001",
                    "RSPAMD_RESULT_MISSING",
                    "adverse",
                    45,
                    1.0,
                    "Le résultat du premier filtre Rspamd est absent.",
                    provenance={"source": "header:x-spamd-result"},
                )
            ], {"present": False}
        value = values[0]
        score_match = _SCORE.search(value)
        score = float(score_match.group(1)) if score_match else None
        maximum = float(score_match.group(2)) if score_match else None
        symbols = {name: float(raw) for name, raw in _SYMBOL.findall(value)}
        material = sorted(
            name
            for name, points in symbols.items()
            if name in _MATERIAL
            or (
                points >= 1.0
                and any(fragment in name for fragment in _MATERIAL_FRAGMENTS)
            )
        )
        reputation = sorted(
            name
            for name, points in symbols.items()
            if points >= 1.0
            and any(fragment in name for fragment in _REPUTATION_FRAGMENTS)
        )
        phishing_heuristics = sorted(
            name for name, points in symbols.items() if points > 0 and "PHISH" in name
        )
        obfuscation = sorted(
            name for name, points in symbols.items() if points > 0 and name in _OBFUSCATION
        )
        clues: list[Clue] = []
        if obfuscation:
            clues.append(
                Clue(
                    "RSPAMD-009",
                    "RSPAMD_OBFUSCATION_SYMBOL",
                    "adverse",
                    35,
                    0.9,
                    "Rspamd relève un déguisement : "
                    + ", ".join(obfuscation)
                    + ".",
                    {
                        "symbols": obfuscation,
                        "symbol_scores": {name: symbols[name] for name in obfuscation},
                    },
                    {"source": "header:x-spamd-result"},
                )
            )
        if material:
            clues.append(
                Clue(
                    "RSPAMD-002",
                    "RSPAMD_MATERIAL_SYMBOL",
                    "adverse",
                    100,
                    0.98,
                    "Rspamd signale un résultat matériel de malware ou de virus.",
                    {
                        "symbols": material,
                        "symbol_scores": {name: symbols[name] for name in material},
                    },
                    {"source": "header:x-spamd-result"},
                )
            )
        if reputation:
            clues.append(
                Clue(
                    "RSPAMD-006",
                    "RSPAMD_REPUTATION_LIST",
                    "adverse",
                    55,
                    0.85,
                    "Rspamd relève une réputation externe défavorable qui doit être corroborée.",
                    {
                        "symbols": reputation,
                        "symbol_scores": {name: symbols[name] for name in reputation},
                    },
                    {"source": "header:x-spamd-result"},
                )
            )
        else:
            clues.append(
                Clue(
                    "RSPAMD-008",
                    "RSPAMD_NO_REPUTATION_HIT",
                    "favorable",
                    5,
                    0.7,
                    "Rspamd n’observe aucun signal de liste de réputation défavorable dans ce message.",
                    {
                        "score": score,
                        "checked_symbol_count": len(symbols),
                        "reputation_symbols": [],
                    },
                    {"source": "header:x-spamd-result"},
                )
            )
        if phishing_heuristics:
            clues.append(
                Clue(
                    "RSPAMD-007",
                    "RSPAMD_PHISHING_HEURISTIC",
                    "neutral",
                    0,
                    0.95,
                    "Rspamd émet une hypothèse de phishing à vérifier par les destinations finales.",
                    {
                        "symbols": phishing_heuristics,
                        "symbol_scores": {
                            name: symbols[name] for name in phishing_heuristics
                        },
                    },
                    {"source": "header:x-spamd-result"},
                )
            )
        if score is not None and score >= 6:
            clues.append(
                Clue(
                    "RSPAMD-003",
                    "RSPAMD_HIGH_SCORE",
                    "neutral",
                    0,
                    1.0,
                    "Le score agrégé Rspamd est élevé mais ne constitue pas une preuve indépendante de ses symboles.",
                    {
                        "score": score,
                        "maximum": maximum,
                        "positive_symbols": {
                            name: points
                            for name, points in sorted(
                                symbols.items(), key=lambda item: item[1], reverse=True
                            )[:12]
                            if points > 0
                        },
                    },
                    {"source": "header:x-spamd-result"},
                )
            )
        elif score is not None and score < 2:
            clues.append(
                Clue(
                    "RSPAMD-004",
                    "RSPAMD_LOW_SCORE",
                    "favorable",
                    15,
                    0.85,
                    "Rspamd observe un score faible.",
                    {"score": score, "maximum": maximum},
                    {"source": "header:x-spamd-result"},
                )
            )
        weak_artifacts = sorted(_WEAK_TRANSACTIONAL_ARTIFACTS.intersection(symbols))
        if weak_artifacts:
            clues.append(
                Clue(
                    "RSPAMD-005",
                    "RSPAMD_TRANSACTIONAL_ENVELOPE_VARIATION",
                    "neutral",
                    0,
                    0.95,
                    "Rspamd observe une différence d’adresse visible/rebond, courante en envoi transactionnel.",
                    {
                        "symbols": weak_artifacts,
                        "symbol_scores": {
                            name: symbols[name] for name in weak_artifacts
                        },
                    },
                    {"source": "header:x-spamd-result"},
                )
            )
        return clues, {
            "present": True,
            "score": score,
            "maximum": maximum,
            "symbol_count": len(symbols),
            "material_symbols": material,
            "reputation_symbols": reputation,
            "phishing_heuristics": phishing_heuristics,
            "weak_transactional_artifacts": weak_artifacts,
            "symbols": dict(sorted(symbols.items())[:80]),
        }
