"""Lit, valide et traduit la réponse du juge avant toute acceptation."""

from __future__ import annotations

import json
import re

from sentimail_v3.code.attack_techniques import recognized as recognized_techniques
from sentimail_v3.code.attack_techniques import summary as techniques_summary
from sentimail_v3.postgres_values import pg_text

CLASSIFICATIONS = {"legitimate", "spam", "suspect", "dangerous", "undetermined"}


FILED_AS_JUNK = {"spam": "spam", "dangerous": "malicious"}


_EVIDENCE_CODE_REF = re.compile(r"\b[A-Z][A-Z0-9]*(?:[-_.][A-Z0-9_]+)+\b")


def _parse_verdict(content: str, dossier: dict[str, object]) -> dict[str, object]:
    start, end = content.find("{"), content.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("verdict response has no JSON object")
    try:
        value = json.loads(content[start : end + 1])
    except json.JSONDecodeError:
        # Un modèle peut faire suivre l'objet d'une note ou d'un second objet
        # (« Extra data ») : le premier objet complet fait foi. Une réponse
        # réellement coupée ou illisible échoue ici comme avant.
        value, _ = json.JSONDecoder().raw_decode(content[start:])
    if not isinstance(value, dict):
        raise TypeError("verdict response is not an object")
    def section(*names: str) -> dict[str, object]:
        """Une section de la réponse, sous son nom actuel ou son nom d'origine.

        Le vocabulaire judiciaire a été remplacé par défavorable/favorable/verdict
        final ; un modèle qui répond encore avec l'ancien schéma reste compris.
        """
        for name in names:
            candidate = value.get(name)
            if isinstance(candidate, dict):
                return candidate
        return {}

    final_verdict = section("final_verdict", "judge") or value
    unfavorable = section("unfavorable", "prosecutor")
    favorable = section("favorable", "defence")
    classification = final_verdict.get("classification")
    if classification not in CLASSIFICATIONS:
        classification = "undetermined"
    try:
        confidence = max(0.0, min(1.0, float(final_verdict.get("confidence", 0))))
    except (TypeError, ValueError):
        confidence = 0.0
    delivery_decision = final_verdict.get("delivery_decision")
    if delivery_decision not in {"deliver", "junk", "ask_user"}:
        raise ValueError("verdict has no valid final delivery decision")
    known = {
        str(clue["clue_code"])
        for clue in dossier.get("clues", [])
        if isinstance(clue, dict) and clue.get("clue_code")
    }
    directions = {
        str(clue["clue_code"]): str(clue.get("direction") or "")
        for clue in dossier.get("clues", [])
        if isinstance(clue, dict) and clue.get("clue_code")
    }
    # Profil de spam matériel : un expéditeur forgé (DMARC en échec), jamais vu
    # (aucune relation préalable) et qui fait un démarchage non sollicité n'a
    # rien d'un doute - c'est du spam certain. L'arbitre, par prudence, le gare
    # en « suspect » (retenu, l'utilisateur doit trancher) ; on remonte ce
    # profil-là en spam/junk. On n'agit QUE sur un « suspect » déjà posé, jamais
    # sur un « legitimate » : aucun faux positif possible sur du courrier propre.
    # Un mail légitime ne réunit pas forge + première observation + démarchage :
    # soit il s'authentifie, soit on le connaît, soit il ne démarche pas.
    _rules = dossier.get("judgment_rules")
    _rules = _rules if isinstance(_rules, dict) else {}
    if (
        # L'arbitre gare ce profil en revue de deux façons : « ask_user », ou
        # « junk » mais à une confiance sous le seuil - que la validation
        # rétrograde alors en revue. Les deux doivent être condamnés.
        delivery_decision in {"ask_user", "junk"}
        and classification in {"suspect", "spam", "dangerous"}
        # Flag calculé sur les indices complets (cf _build_dossier), pas sur la
        # liste tronquée pour le LLM : un gros dossier ne doit pas faire perdre
        # le profil au ras du budget de contexte.
        and dossier.get("material_spam_profile")
        # Une analyse incomplète reste un doute légitime : on ne condamne pas
        # sur un dossier partiel, la validation junk l'interdirait de toute façon.
        and _rules.get("deep_execution_complete")
        and _rules.get("static_investigation_complete")
    ):
        # L'arbitre gare ce profil en revue - soit « suspect », soit « spam »
        # mais en demandant confirmation. Le profil matériel tranche : on classe
        # spam et on file en indésirables. Jamais sur un « legitimate » (livré) :
        # aucun faux positif possible sur du courrier propre.
        if classification == "suspect":
            classification = "spam"
        delivery_decision = "junk"
        # La certitude vient du profil matériel, pas de l'auto-évaluation prudente
        # du modèle : on porte la confiance au seuil de condamnation, sinon la
        # validation (junk exige >= seuil) rejouerait le verdict à l'infini.
        confidence = max(confidence, float(_rules.get("confidence_required") or 0.9))
    # Profil d'usurpation matériel : une organisation dont les domaines
    # officiels sont connus, un message qui n'en vient pas, pas
    # d'authentification, jamais vu, et une demande d'agir. Même remontée que
    # le spam, et jamais sur un « legitimate ». L'analyse profonde n'est pas
    # exigée complète : c'est l'attaquant qui tient le lien, et faire échouer
    # le bac à sable lui suffisait pour rester en doute (M-490357). Un verdict
    # dangerous, lui, l'exige toujours ; à défaut le message est classé
    # indésirable, ce que le Code autorise sur une analyse partielle.
    if (
        delivery_decision in {"ask_user", "junk"}
        and classification in {"suspect", "spam", "dangerous"}
        and dossier.get("material_impersonation_profile")
        and _rules.get("static_investigation_complete")
    ):
        if classification == "suspect":
            classification = (
                "dangerous" if _rules.get("deep_execution_complete") else "spam"
            )
        elif classification == "dangerous" and not _rules.get("deep_execution_complete"):
            classification = "spam"
        delivery_decision = "junk"
        confidence = max(confidence, float(_rules.get("confidence_required") or 0.9))

    def role_codes(
        section: dict[str, object], legacy_name: str, direction: str
    ) -> list[str]:
        raw = section.get("clue_codes")
        if not isinstance(raw, list):
            raw = value.get(legacy_name)
        if not isinstance(raw, list):
            return []
        return [
            str(code)
            for code in raw[:30]
            if str(code) in known
            and (directions.get(str(code)) or direction) == direction
        ]

    def role_arguments(section: dict[str, object], legacy_name: str) -> list[str]:
        raw = section.get("arguments")
        if not isinstance(raw, list):
            raw = value.get(legacy_name)
        if not isinstance(raw, list):
            return []
        return [str(item)[:1000] for item in raw[:12] if isinstance(item, str)]

    unfavorable_codes = role_codes(unfavorable, "supporting_clue_codes", "adverse")
    favorable_codes = role_codes(favorable, "contradicting_clue_codes", "favorable")
    doubt_reasons = final_verdict.get("doubt_reasons")
    if not isinstance(doubt_reasons, list):
        doubt_reasons = value.get("uncertainties")
    if not isinstance(doubt_reasons, list):
        doubt_reasons = []
    available_references = {
        str(clue.get(field) or "")
        for clue in dossier.get("clues", [])
        if isinstance(clue, dict)
        for field in ("clue_code", "article_code")
        if clue.get(field)
    }
    # Le dossier expose l'index du Code applicable et le texte des articles
    # qu'un indice a déclenchés. Citer un article qu'on a sous les yeux - pour
    # dire qu'il s'applique, ou justement qu'il ne s'applique pas - n'est pas
    # inventer une preuve. Ce qui reste interdit, et contrôlé ailleurs, c'est
    # de s'appuyer sur un indice absent du dossier.
    for section in ("code_articles", "code_index"):
        available_references |= {
            str(article.get("article_code") or "")
            for article in dossier.get(section, [])
            if isinstance(article, dict) and article.get("article_code")
        }
    # Les techniques du registre sont nommables dans une motivation : les citer
    # n'est pas fabriquer une preuve.
    available_references |= {
        str(entry.get("technique_code") or "")
        for entry in dossier.get("attack_technique_registry", [])
        if isinstance(entry, dict) and entry.get("technique_code")
    }
    # Une règle calculée sur les indices complets peut nommer un indice que
    # la vue tronquée n'a plus : le citer n'est pas inventer une preuve. Les
    # rôles à charge et à décharge, eux, restent filtrés sur la vue.
    for family in _rules.get("family_coverage") or []:
        if not isinstance(family, dict):
            continue
        for side in ("adverse", "favorable"):
            tally = family.get(side)
            if isinstance(tally, dict):
                available_references |= {
                    str(code) for code in tally.get("clue_codes") or [] if code
                }
    for item in _rules.get("material_danger_evidence") or []:
        if isinstance(item, dict):
            available_references |= {
                str(item.get(field) or "")
                for field in ("clue_code", "article_code")
                if item.get(field)
            }
    # Une norme cite ses propres identifiants (« RFC5322.From »,
    # « DKIM-Signature »). Recopiés dans une motivation, ils ressemblent à des
    # références de preuve et feraient rejeter un verdict par ailleurs correct.
    knowledge = dossier.get("reference_knowledge")
    quoted_in_knowledge = set()
    if isinstance(knowledge, dict):
        for passage in knowledge.get("passages") or []:
            if isinstance(passage, dict):
                quoted_in_knowledge |= set(
                    _EVIDENCE_CODE_REF.findall(str(passage.get("text") or ""))
                    + _EVIDENCE_CODE_REF.findall(str(passage.get("section") or ""))
                )
    available_prefixes = {
        reference.split("-", 1)[0].split("_", 1)[0].split(".", 1)[0]
        for reference in available_references
    }
    trial_texts = [
        str(final_verdict.get("rationale") or ""),
        *role_arguments(unfavorable, "unfavorable_case"),
        *role_arguments(favorable, "favorable_case"),
        *(str(item) for item in doubt_reasons if isinstance(item, str)),
    ]
    invented_references = sorted(
        {
            reference
            for text in trial_texts
            for reference in _EVIDENCE_CODE_REF.findall(text)
            if reference.split("-", 1)[0].split("_", 1)[0].split(".", 1)[0]
            in available_prefixes
            and reference not in available_references
            and reference not in quoted_in_knowledge
        }
    )
    if invented_references:
        raise ValueError(
            "verdict cites unavailable evidence: " + ",".join(invented_references[:8])
        )

    attack_section = (
        value.get("attack") if isinstance(value.get("attack"), dict) else {}
    )
    known_techniques = {
        str(entry.get("technique_code")): entry
        for entry in dossier.get("attack_technique_registry") or []
        if isinstance(entry, dict) and entry.get("technique_code")
    }
    attack_entries = recognized_techniques(
        attack_section.get("techniques"), known_techniques
    )
    attack = techniques_summary(attack_entries) if attack_entries else {}
    if attack:
        brand = attack_section.get("impersonated_brand")
        attack["impersonated_brand"] = (
            str(brand)[:120] if isinstance(brand, str) and brand.strip() else None
        )
        attack["targeted"] = bool(attack_section.get("targeted"))

    result = {
        "classification": classification,
        "confidence": confidence,
        "attack": attack,
        "delivery_decision": delivery_decision,
        "rationale": pg_text(str(final_verdict.get("rationale") or "Verdict non motivé.")[:8000]),
        "supporting_clue_codes": unfavorable_codes,
        "contradicting_clue_codes": favorable_codes,
        "uncertainties": [
            str(item)[:1000] for item in doubt_reasons[:12] if isinstance(item, str)
        ],
        "requested_additional_evidence": [],
        "unfavorable_case": role_arguments(unfavorable, "unfavorable_case"),
        "favorable_case": role_arguments(favorable, "favorable_case"),
        "contested_points": [],
        "missing_harm_elements": [],
        "specialist_assessments": {},
        "verdict_doubt": bool(final_verdict.get("doubt"))
        or classification != "legitimate",
        "raw_response": value,
    }
    _validate_final_judgment(result, dossier)
    return result


class JudgmentContradiction(ValueError):
    """Jugement rejeté avant d'être contraignant, avec le motif du rejet.

    Une contradiction structurelle porte sur un fait immuable du dossier :
    analyse incomplète, preuve matérielle, retenue authentifiée. Rejouer le
    modèle ne changerait rien, puisque le fait, lui, ne change pas.
    """

    STRUCTURAL = frozenset(
        {
            "deep_execution_incomplete",
            "static_investigation_incomplete",
            "material_danger_unresolved",
            "authenticated_hold_ignored",
            "identity_destination_conflict_unresolved",
            "ask_without_real_doubt",
        }
    )

    def __init__(
        self, contradictions: list[str], judgment: dict[str, object] | None = None
    ) -> None:
        super().__init__(
            "internally inconsistent final judgment: " + ",".join(contradictions)
        )
        self.contradictions = contradictions
        self.judgment = judgment

    @property
    def structural(self) -> bool:
        return bool(set(self.contradictions) & self.STRUCTURAL)


def waiting_judgment(contradiction: JudgmentContradiction) -> dict[str, object]:
    """Conséquence d'un jugement rejeté pour un fait immuable du dossier.

    Le fait qui interdit la livraison ne changera pas d'un rejeu à l'autre :
    rejouer le modèle dépenserait des appels pour aboutir au même ordre. L'avis
    de l'utilisateur est donc demandé tout de suite. Ce n'est pas un veto
    postérieur : le jugement a été rejeté avant de devenir contraignant, et
    l'attente est la seule issue qu'il restait.
    """
    judgment = dict(contradiction.judgment or {})
    judgment["delivery_decision"] = "ask_user"
    judgment["verdict_doubt"] = True
    if judgment.get("classification") == "legitimate":
        judgment["classification"] = "undetermined"
    judgment["uncertainties"] = [
        *(str(value) for value in judgment.get("uncertainties") or []),
        *contradiction.contradictions,
    ][:12]
    judgment["structural_contradiction"] = list(contradiction.contradictions)
    # La motivation d'origine concluait à la livraison : la laisser telle
    # quelle donnait un avis qui se contredit, rassurant sur le fond et
    # inquiet sur la forme. On dit ce qui a réellement empêché de conclure.
    judgment["rationale"] = (
        "L'identité de l'expéditeur reste non établie et la destination du "
        "bouton contredit l'opération annoncée. Je te demande ton avis avant "
        "de donner suite."
        if "identity_destination_conflict_unresolved" in contradiction.contradictions else
        "Mon analyse n’a pas pu être menée à son terme, je préfère te "
        "demander plutôt que de décider à ta place. Ce que j’avais retenu "
        "jusque-là : " + str(judgment.get("rationale") or "").strip()
    )[:8000]
    return judgment


def _without_real_doubt(rules: object, classification: object) -> bool:
    """Le destinataire ne veut que les vrais doutes, et il n'y en a pas."""
    return bool(
        isinstance(rules, dict)
        and rules.get("ask_only_on_real_doubt")
        and not rules.get("real_doubt")
        and classification != "dangerous"
    )


def delivery_without_question(contradiction: JudgmentContradiction) -> dict[str, object]:
    """Conséquence d'un jugement rejeté chez qui ne veut que les vrais doutes.

    Le pendant de waiting_judgment : le jugement a été rejeté avant de devenir
    contraignant, et la livraison est la seule issue qu'il restait. Le
    destinataire a choisi qu'un message laissé passer vaille mieux qu'une
    question de trop ; classification et confiance restent celles du juge.
    """
    judgment = dict(contradiction.judgment or {})
    judgment["delivery_decision"] = "deliver"
    judgment["uncertainties"] = [
        *(str(value) for value in judgment.get("uncertainties") or []),
        *contradiction.contradictions,
    ][:12]
    judgment["structural_contradiction"] = list(contradiction.contradictions)
    judgment["rationale"] = (
        "Aucun danger établi ni faisceau défavorable, et le destinataire a "
        "choisi de n'être interrogé que sur un vrai doute : je livre. Ce que "
        "j'avais retenu : " + str(judgment.get("rationale") or "").strip()
    )[:8000]
    return judgment


def _parse_final_response(
    content: str, dossier: dict[str, object]
) -> tuple[dict[str, object], list[str]]:
    """Transforme seulement les contradictions immuables en attente humaine.

    Chez qui ne veut que les vrais doutes, et quand il n'y en a pas, tout
    jugement rejeté devient une livraison : l'attente lui est fermée.
    """
    try:
        return _parse_verdict(content, dossier), []
    except JudgmentContradiction as contradiction:
        if contradiction.judgment is not None and _without_real_doubt(
            dossier.get("judgment_rules"), contradiction.judgment.get("classification")
        ):
            return delivery_without_question(contradiction), contradiction.contradictions
        if not contradiction.structural or contradiction.judgment is None:
            raise
        return waiting_judgment(contradiction), contradiction.contradictions


def _validate_final_judgment(
    result: dict[str, object], dossier: dict[str, object]
) -> None:
    """Valide la cohérence interne du jugement sans lui substituer une décision.

    Une réponse incohérente est rejetée et rejouée comme jugement invalide. Elle
    n'est jamais transformée après coup par une politique de livraison distincte.
    """
    rules = dossier.get("judgment_rules")
    binding = isinstance(rules, dict) and (
        rules.get("verdict_is_final") or rules.get("judge_is_final")
    )
    if not binding:
        raise ValueError("final judgment rules are missing")
    decision = result.get("delivery_decision")
    classification = result.get("classification")
    confidence = float(result.get("confidence") or 0)
    threshold = float(rules.get("confidence_required") or 1)
    if rules.get("identity_destination_conflict") and decision == "deliver":
        raise JudgmentContradiction(["identity_destination_conflict_unresolved"], result)
    without_real_doubt = _without_real_doubt(rules, classification)
    if without_real_doubt and decision == "ask_user":
        raise JudgmentContradiction(["ask_without_real_doubt"], result)
    if decision == "deliver" and without_real_doubt:
        # Rien de ce qui fait barrière n'est présent : livrer est permis quel
        # que soit le verdict, c'est le choix du destinataire.
        return
    if decision == "deliver":
        contradictions: list[str] = []
        if classification != "legitimate":
            contradictions.append("delivery_requires_legitimate")
        if bool(result.get("verdict_doubt", result.get("judge_doubt"))):
            contradictions.append("delivery_forbids_verdict_doubt")
        if confidence < threshold:
            contradictions.append("confidence_below_judicial_threshold")
        decisive = rules.get("incomplete_analysis_is_decisive", True)
        if decisive and not rules.get("deep_execution_complete"):
            contradictions.append("deep_execution_incomplete")
        if decisive and not rules.get("static_investigation_complete"):
            contradictions.append("static_investigation_incomplete")
        if rules.get("material_danger_evidence"):
            contradictions.append("material_danger_unresolved")
        if rules.get("authenticated_sender_policy") == "hold":
            contradictions.append("authenticated_hold_ignored")
        if contradictions:
            raise JudgmentContradiction(contradictions, result)
    elif decision == "junk":
        contradictions = []
        # Classer sans demander suppose d'être sûr : le doute a sa propre
        # issue, et c'est l'utilisateur.
        if classification not in {"spam", "dangerous"}:
            contradictions.append("junk_requires_spam_or_dangerous")
        if confidence < threshold:
            contradictions.append("confidence_below_judicial_threshold")
        # Le bac à sable n'aboutit pas toujours, et beaucoup de prospection
        # manifeste en fait échouer l'inspection. Exiger une analyse profonde
        # complète pour classer revenait à redemander un avis sur chaque envoi
        # de masse : la question perdait son sens à force d'être posée. Le pire
        # qu'un classement erroné coûte ici est un message récupérable dans les
        # indésirables. Un verdict dangereux garde cette exigence lorsqu'une
        # pièce jointe reste sans inspection : un lien mort ou lent ne bloque
        # plus le classement en indésirables.
        if classification == "dangerous" and not rules.get(
            "attachment_analysis_complete", rules.get("deep_execution_complete")
        ):
            contradictions.append("deep_execution_incomplete")
        # Sans même les vérifications de base, il n'y a rien sur quoi trancher.
        if not rules.get("static_investigation_complete"):
            contradictions.append("static_investigation_incomplete")
        if contradictions:
            raise JudgmentContradiction(contradictions, result)
    elif classification == "legitimate":
        raise JudgmentContradiction(["legitimate_must_be_delivered"], result)


def _judgment_execution(result: dict[str, object]) -> dict[str, object]:
    """Traduit littéralement le jugement final en ordre, sans réévaluation."""
    decision = str(result["delivery_decision"])
    classification = str(result["classification"])
    return {
        "version": "verdict-final-v3-policy-suppression",
        "verdict_is_final": True,
        "delivery_decision": decision,
        # Un message classé en indésirables est livré : il part vers la boîte,
        # simplement pas dans la réception.
        "original_delivery_allowed": decision in {"deliver", "junk"},
        "policy_suppressed": decision == "suppress",
        "filed_as_junk": FILED_AS_JUNK.get(classification) if decision == "junk" else None,
        "classification": classification,
        "confidence": result["confidence"],
    }


def _authenticated_suppression(
    dossier: dict[str, object],
) -> dict[str, object] | None:
    """Exécute la préférence B avant tout nouvel arbitrage du modèle.

    Une règle authentifiée n'est pas une preuve de danger et n'entraîne donc
    aucune conclusion de sécurité. Elle exprime en revanche une préférence de
    boîte contraignante : ce correspondant ne doit plus produire de courrier,
    y compris un nouvel avis MAIA.
    """
    rules = dossier.get("judgment_rules")
    if not isinstance(rules, dict) or rules.get("authenticated_sender_policy") != "hold":
        return None
    return {
        "classification": "undetermined",
        "confidence": 1.0,
        "attack": {},
        "delivery_decision": "suppress",
        "rationale": (
            "L’utilisateur a authentifié une règle B pour cet expéditeur ; "
            "le message est supprimé sans nouvelle notification."
        ),
        "supporting_clue_codes": [],
        "contradicting_clue_codes": [],
        "uncertainties": [],
        "requested_additional_evidence": [],
        "unfavorable_case": [],
        "favorable_case": [],
        "contested_points": [],
        "missing_harm_elements": [],
        "specialist_assessments": {},
        "verdict_doubt": False,
        "raw_response": {"source": "authenticated_sender_policy"},
    }
