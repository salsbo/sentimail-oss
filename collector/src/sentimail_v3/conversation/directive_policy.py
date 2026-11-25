from __future__ import annotations

import re
import unicodedata
from typing import Any

_ACTIONABLE = {"release_original", "suppress_future", "cancel_suppression"}

# Noyée dans un long texte, une lettre ou une phrase vient plus souvent d'une
# citation mal détourée que d'une intention. Au-delà, le texte part au modèle.
CHOICE_CONTEXT_LIMIT = 400


def short_enough(text: str) -> bool:
    """Le texte tient dans la limite, blancs réduits."""
    return len(" ".join(text.split())) <= CHOICE_CONTEXT_LIMIT


def _normalized(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    return "".join(char for char in decomposed if not unicodedata.combining(char))


# Une lettre seule sur sa ligne, c'est un choix de bouton. Elle n'AUTORISE
# rien : l'autorisation vient du jeton S3-ACTION porté par la réponse et du
# filtre d'expéditeur. Elle dit seulement ce que l'utilisateur a voulu, sans
# qu'un modèle ait à le deviner.
_LONE_LETTER = re.compile(r"^[ \t]*([ABab])[ \t]*$", re.MULTILINE)
_LETTER_ACTION = {"A": "release_original", "B": "suppress_future"}
_LETTER_CLASSIFICATION = {"A": "legitimate", "B": "spam"}


def _lone_letter(text: str) -> str | None:
    """« A » ou « B » isolé sur sa ligne, tel que les boutons l'écrivent."""
    trouvees = {match.group(1).upper() for match in _LONE_LETTER.finditer(text or "")}
    # Deux lettres différentes ne disent plus rien : on préfère ne rien décider.
    if len(trouvees) != 1:
        return None
    # Même garde que pour les boutons : une lettre au milieu d'un long texte
    # ne décide pas. Sans elle, le texte libre confié au modèle retrouvait ici
    # la lettre que la lecture des choix venait d'écarter.
    reste = _LONE_LETTER.sub("", text or "")
    return trouvees.pop() if short_enough(reste) else None


def _explicit_action(text: str) -> str | None:
    lettre = _lone_letter(text)
    if lettre is not None:
        return _LETTER_ACTION[lettre]
    if re.search(
        r"\b(ne\s+(?:le\s+)?(?:livre|delivre|libere)\s+pas|"
        r"n[' ]?(?:envoie|envoi|expedie)\s+pas|"
        r"ne\s+plus\s+(?:le\s+)?(?:livre|delivre|libere)|"
        r"bloque\s+(?:les\s+)?(?:prochains|futurs)|supprime\s+a\s+l'avenir)\b",
        text,
    ):
        return "suppress_future"
    if re.search(r"\b(annule|retire|enleve)\b.{0,30}\b(blocage|suppression)\b", text):
        return "cancel_suppression"
    if re.search(
        r"\b(tu\s+peux\s+(?:me\s+)?(?:le\s+)?(?:livrer|delivrer|liberer)|"
        r"livre\s*(?:-\s*le)?|delivre\s*(?:-\s*le)?|"
        r"libere\s*(?:-\s*)?(?:le|l.email|ce\s+message)?|"
        r"autorise\s+ce\s+message)\b",
        text,
    ):
        return "release_original"
    if re.search(
        r"\b((?:va|vas)\s+y(?:\s+(?:envoie|envoi|expedie|transmets?))?|"
        r"(?:envoie|envoi|expedie|transmets?)\s*(?:-\s*)?(?:le|la|lui|moi)?|"
        r"(?:fais|fait|laisse)\s+(?:le\s+)?passer)\b",
        text,
    ):
        return "release_original"
    return None


def _explicit_classification(text: str) -> str | None:
    lettre = _lone_letter(text)
    if lettre is not None:
        return _LETTER_CLASSIFICATION[lettre]
    if re.search(
        r"\b(pas\s+(?:du\s+)?spam|legitime|fiable|je\s+le\s+connais|"
        r"c.est\s+moi|je\s+suis\s+a\s+l.origine)\b",
        text,
    ):
        return "legitimate"
    if re.search(
        r"\b(phishing|hameconnage|dangereux|malveillant|ce\s+n.est\s+pas\s+moi|"
        r"je\s+ne\s+suis\s+pas\s+a\s+l.origine)\b",
        text,
    ):
        return "dangerous"
    if re.search(
        r"\b(c[' ]?est\s+(?:du\s+)?spam|courrier\s+indesirable|"
        r"message\s+indesirable|non\s+sollicite)\b",
        text,
    ):
        return "spam"
    if re.search(r"\b(suspect|bizarre|douteux)\b", text):
        return "suspect"
    return None


def explicit_directive(user_text: str) -> tuple[str | None, str | None]:
    """Lit localement l'action et la qualification dites par l'utilisateur.

    Cette lecture ne donne aucun droit d'exécution à elle seule : le jeton de
    réponse SMTP et le rattachement au dossier restent les autorités. Elle est
    publique afin que les réponses préremplies, rédigées en toutes lettres,
    empruntent exactement la même voie déterministe que les anciennes lettres
    A/B, sans dépendre d'un fournisseur LLM.
    """
    text = _normalized(user_text)
    return _explicit_action(text), _explicit_classification(text)


def evaluate_directive(user_text: str, llm_result: dict[str, Any]) -> dict[str, object]:
    """Bloque toute action LLM absente ou contraire au texte explicite."""
    explicit_action, explicit_classification = explicit_directive(user_text)
    llm_action = str(llm_result.get("requested_action") or "none")
    llm_classification = llm_result.get("classification")
    conflicts: list[str] = []

    if llm_action in _ACTIONABLE:
        if explicit_action is None:
            conflicts.append("action_not_explicitly_requested")
        elif llm_action != explicit_action:
            conflicts.append("action_contradicts_user_text")

    if explicit_classification == "legitimate" and llm_classification in {
        "spam",
        "dangerous",
        "suspect",
    }:
        conflicts.append("classification_contradicts_user_text")
    if explicit_classification in {"spam", "dangerous"} and llm_classification == "legitimate":
        conflicts.append("classification_contradicts_user_text")

    return {
        "status": "blocked_conflict" if conflicts else "allow_non_binding",
        "explicit_action": explicit_action,
        "explicit_classification": explicit_classification,
        "llm_action": llm_action,
        "llm_classification": llm_classification,
        "conflicts": conflicts,
    }


def apply_directive_gate(
    user_text: str, llm_result: dict[str, Any]
) -> dict[str, object]:
    gate = evaluate_directive(user_text, llm_result)
    llm_raw = llm_result.get("raw_response")
    llm_result["policy_gate"] = gate
    llm_result["raw_response"] = {"llm": llm_raw, "policy_gate": gate}
    if gate["status"] == "blocked_conflict":
        llm_result["requested_action"] = "none"
        llm_result["classification"] = None
        llm_result["confidence"] = min(float(llm_result.get("confidence") or 0), 0.49)
        llm_result["clarification_question"] = (
            "J’ai détecté une contradiction entre tes mots et mon interprétation. "
            "Peux-tu reformuler explicitement le verdict et l’action souhaitée ?"
        )
        reasons = list(llm_result.get("reasons") or [])
        reasons.extend(str(value) for value in gate["conflicts"])
        llm_result["reasons"] = reasons[:12]
        return gate

    explicit_action = gate["explicit_action"]
    explicit_classification = gate["explicit_classification"]
    overrides: list[str] = []
    if explicit_action and llm_result.get("requested_action") != explicit_action:
        llm_result["requested_action"] = explicit_action
        llm_result["intent"] = explicit_action
        overrides.append("requested_action")
    if explicit_classification and llm_result.get("classification") in {
        None,
        "undetermined",
    }:
        llm_result["classification"] = explicit_classification
        overrides.append("classification")
    if overrides:
        gate["status"] = "allow_explicit_user_override"
        gate["overrides"] = overrides
        llm_result["clarification_question"] = None
        reasons = list(llm_result.get("reasons") or [])
        reasons.append("explicit_user_text_overrides_llm_omission")
        llm_result["reasons"] = reasons[:12]
        llm_result["raw_response"] = {
            "llm": llm_raw,
            "policy_gate": gate,
        }
    return gate
