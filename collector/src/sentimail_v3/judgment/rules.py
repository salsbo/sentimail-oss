"""Établit les barrières du jugement sur les faits complets, avant le modèle."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from sentimail_v3.code.families import converging_families, family_coverage
from sentimail_v3.code.reference import nommer_dossier
from sentimail_v3.config import Settings
from sentimail_v3.judgment.dossier_view import _bounded, _json
from sentimail_v3.judgment.model_routing import JUDGMENT_RULES_VERSION

logger = logging.getLogger("sentimail-v3-verdict")

_MATERIAL_SPAM_SOLICITATION = {
    "NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS",
    "NATURE_SOLICITATION_WITHOUT_OPT_OUT",
    # Un envoi de masse déclaré par ses en-têtes, d'un expéditeur jamais vu :
    # c'est le démarchage lui-même. Il manquait au profil, et huit réclames
    # forgées ont été posées en question le 3 septembre 2026.
    "NATURE_UNSOLICITED_BULK_FIRST_CONTACT",
}


_IMPERSONATION_ACTIONS = {
    "ACTION_CLICK_LINK",
    "ACTION_CREDENTIAL_ENTRY",
    "ACTION_MFA_CODE_DISCLOSURE",
    "ACTION_PERSONAL_DATA",
    "ACTION_IDENTITY_DOCUMENT",
    "ACTION_PAYMENT_TRANSFER",
    "ACTION_BANK_DETAILS_CHANGE",
    "ACTION_GIFT_CARD_PURCHASE",
    "ACTION_QR_CODE_SCAN",
    "ACTION_PHONE_CALLBACK",
}


_MECHANICAL_REFUTATION = "domaine_officiel_avec_mot_en_plus"


def _clue_facts(clue: dict[str, object]) -> dict[str, object]:
    facts = clue.get("facts")
    if isinstance(facts, str):
        try:
            facts = json.loads(facts)
        except ValueError:
            return {}
    if not isinstance(facts, dict):
        return {}
    nested = facts.get("facts")
    return dict(nested) if isinstance(nested, dict) else dict(facts)


def _material_impersonation_profile(clues: list[dict[str, object]]) -> bool:
    """Identité démentie sur un fait, non authentifiée, jamais vue, et qui
    demande d'agir : le profil d'usurpation matériel.

    Le juge posait ce profil en question (« aucune preuve matérielle de
    dommage »), alors que l'usurpation est établie sur pièces : la recherche a
    rendu les domaines officiels de l'organisation, et le message vient d'un
    domaine qui en accole le nom. La convergence CORRELATION_BRAND_SPOOFING
    porte déjà le défaut d'authentification.
    """
    codes = {
        str(clue.get("clue_code") or "") for clue in clues if isinstance(clue, dict)
    }
    refute_sur_fait = any(
        isinstance(clue, dict)
        and clue.get("clue_code") == "IDENTITY_CLAIMED_ORGANISATION_REFUTED"
        and clue.get("direction") == "adverse"
        and _clue_facts(clue).get("constat") == _MECHANICAL_REFUTATION
        for clue in clues
    )
    return (
        refute_sur_fait
        and "CORRELATION_BRAND_SPOOFING" in codes
        and "HISTORY_FIRST_OBSERVATION" in codes
        and bool(codes & _IMPERSONATION_ACTIONS)
    )


def _material_spam_profile(clue_codes: set[str]) -> bool:
    """Forge + première observation + démarchage non sollicité : le profil de
    spam matériel. Calculé sur les indices COMPLETS avant tout ajustement à la
    taille du contexte LLM - le dossier envoyé au modèle peut être tronqué, pas
    la certitude qui condamne."""
    return (
        "AUTH_DMARC_FAIL" in clue_codes
        and "HISTORY_FIRST_OBSERVATION" in clue_codes
        and bool(clue_codes & _MATERIAL_SPAM_SOLICITATION)
    )


def _log(event: str, **fields: object) -> None:
    fields = nommer_dossier(dict(fields))
    level = logging.ERROR if event.endswith(".error") else logging.INFO
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": logging.getLevelName(level).lower(),
        "event": event,
        **fields,
    }
    logger.log(level, _json(payload))


def _learning_adjustments(labels: object) -> tuple[int, int, float]:
    if not isinstance(labels, dict):
        return 0, 0, 0.0
    confirmations = int(labels.get("legitimate", 0))
    adverse = sum(int(labels.get(name, 0)) for name in ("spam", "suspect", "dangerous"))
    learned_reduction = 0.0 if adverse else min(0.08, confirmations * 0.004)
    return confirmations, adverse, learned_reduction


def _material_danger_evidence(
    dossier: dict[str, object],
) -> list[dict[str, object]]:
    """Retourne les preuves matérielles que le Code impose d'examiner.

    Les scores, heuristiques et corrélations restent dans le procès soumis au
    LLM. Ils ne deviennent jamais implicitement une barrière de livraison par
    accumulation. Le caractère matériel est une propriété explicite et
    auditable de l'article actif du Code Sentinel, transmise avant le verdict.
    """
    articles = dossier.get("code_articles")
    material_articles: dict[str, str] = {}
    for article in articles if isinstance(articles, list) else []:
        if not isinstance(article, dict):
            continue
        parameters = article.get("parameters")
        # asyncpg rend une colonne jsonb en texte faute de codec. Lu tel quel,
        # aucun article n'a jamais fait barrière : la liste est restée vide sur
        # les 2 747 jugements du mois précédant le 16 septembre 2026, extorsion
        # et pièces jointes exécutables comprises.
        if isinstance(parameters, str):
            try:
                parameters = json.loads(parameters)
            except ValueError:
                # La panne du 16 septembre 2026 était silencieuse : un article
                # illisible perd sa barrière, et cela doit au moins se voir.
                _log(
                    "verdict.material_parameters_unreadable",
                    article_code=str(article.get("article_code") or ""),
                )
                continue
        if not isinstance(parameters, dict):
            continue
        if parameters.get("delivery_barrier") != "material_danger":
            continue
        code = str(article.get("article_code") or "")
        if code:
            material_articles[code] = str(
                parameters.get("material_kind") or "unspecified"
            )

    evidence: list[dict[str, object]] = []
    clues = dossier.get("clues")
    for clue in clues if isinstance(clues, list) else []:
        if not isinstance(clue, dict) or clue.get("direction") != "adverse":
            continue
        article_code = str(clue.get("article_code") or "")
        if article_code not in material_articles:
            continue
        evidence.append(
            {
                "article_code": article_code,
                "clue_code": str(clue.get("clue_code") or ""),
                "material_kind": material_articles[article_code],
                "strength": int(clue.get("strength") or 0),
            }
        )
    return evidence


_ATTACHMENT_INCOMPLETE_CLUES = frozenset(
    {"ATTACHMENT_ANALYSIS_BLOCKED", "ATTACHMENT_SANDBOX_INCOMPLETE"}
)


def _attachment_analysis_complete(
    dossier: dict[str, object], deep: dict[str, object]
) -> bool:
    """Vrai seulement si chaque pièce jointe a été entièrement inspectée.

    Le drapeau de l'analyse profonde fait foi ; un dossier plus ancien, qui ne
    l'a pas, se relit sur ses analyses de pièces jointes. Sans l'un ni
    l'autre, rien ne dit qu'un fichier a échappé à l'inspection.

    L'indice ATT-019 est neutre, de force 0 : c'est le premier que la
    troncature écarterait. Il n'est lu ici de façon fiable que parce que les
    règles se calculent sur les indices complets (voir _prepare_for_judgment).
    """
    flag = deep.get("attachments_complete")
    if isinstance(flag, bool):
        complete = flag
    else:
        analyses = deep.get("attachment_analyses")
        complete = (
            not any(
                isinstance(analysis, dict) and analysis.get("analysis_incomplete")
                for analysis in analyses
            )
            if isinstance(analyses, list)
            else True
        )
    clues = dossier.get("clues")
    blocked = any(
        isinstance(clue, dict)
        and clue.get("clue_code") in _ATTACHMENT_INCOMPLETE_CLUES
        for clue in (clues if isinstance(clues, list) else [])
    )
    return complete and not blocked


def _judgment_rules(
    dossier: dict[str, object],
    deep: dict[str, object],
    settings: Settings,
) -> dict[str, object]:
    clues = dossier.get("clues") or []
    history = deep.get("history") if isinstance(deep.get("history"), dict) else {}
    labels = history.get("ground_truth_labels") if isinstance(history, dict) else {}
    confirmations, adverse_confirmations, learned_reduction = _learning_adjustments(labels)
    allow_identity_authenticated = any(
        isinstance(clue, dict) and clue.get("clue_code") == "AUTH_DMARC_PASS"
        for clue in clues
    )
    authenticated_allow_reduction = (
        max(0.0, settings.auto_delivery_confidence - 0.82)
        if isinstance(history, dict)
        and history.get("persistent_allow")
        and allow_identity_authenticated
        else 0.0
    )
    # La confiance de l'utilisateur porte sur une identité habituelle, jamais
    # sur un acte ou un montage observé sur CE message. Un compte de confiance
    # détourné est le chemin le plus court du hameçonnage : une convergence
    # défavorable suspend donc la réduction de seuil et la posture
    # d'expéditeur de confiance. Seul le préfixe CORRELATION_ compte :
    # TPLT_KNOWN_CAMPAIGN est une mémoire de ressemblance, pas un faisceau de
    # faits. Mesure du 29 septembre 2026 sur 60 jours : les deux livraisons
    # d'expéditeurs autorisés qui portaient CORRELATION_FINANCIAL_FRAUD
    # avaient une confiance de 0,90, égale au seuil plein. Le seuil seul ne
    # les aurait pas retenues ; c'est la posture trusted_sender qui les
    # portait.
    adverse_correlations = sorted(
        {
            str(clue.get("clue_code"))
            for clue in clues
            if isinstance(clue, dict)
            and clue.get("direction") == "adverse"
            and str(clue.get("clue_code") or "").startswith("CORRELATION_")
        }
    )
    # Les confirmations humaines portent sur l'adresse exacte. Sans DMARC sur
    # ce message, rien ne dit qu'elle n'est pas usurpée : une adresse
    # confirmée vingt fois et forgée sans alignement obtenait 0,82.
    learned_applied = learned_reduction if allow_identity_authenticated else 0.0
    reduction_applied = (
        0.0 if adverse_correlations else max(learned_applied, authenticated_allow_reduction)
    )
    confidence_required = max(
        0.82, settings.auto_delivery_confidence - reduction_applied
    )
    message = dossier.get("message") if isinstance(dossier.get("message"), dict) else {}
    material_evidence = _material_danger_evidence(dossier)
    coverage = deep.get("url_coverage")
    sender_policy = "none"
    if isinstance(history, dict) and history.get("persistent_hold"):
        sender_policy = "hold"
    elif isinstance(history, dict) and history.get("persistent_allow"):
        sender_policy = "allow"
    # Un correspondant que l'utilisateur a lui-meme autorise, et dont
    # l'identite est authentifiee, ne doit plus le deranger pour du bruit :
    # premiere observation, registre promotionnel, couverture d'analyse
    # limitee, score antispam eleve. Mais une adresse de confiance peut etre
    # compromise, et c'est meme le chemin le plus efficace du hameconnage :
    # une preuve materielle continue donc de lui valoir une question, et une
    # convergence defavorable lui retire la posture de confiance.
    trusted_sender = (
        sender_policy == "allow"
        and allow_identity_authenticated
        and not adverse_correlations
    )
    # Une vérification de lien inachevée ne dérange pas un expéditeur
    # authentifié sans charge : beaucoup de liens légitimes (reçus, suivis de
    # commande) refusent le bac à sable. Un fichier jamais ouvert, si.
    # L'authentification prouve qui écrit, pas ce que contient le fichier.
    # Mesure du 29 septembre 2026 : sur 32 jours, 7 messages ont été livrés
    # sans que leur pièce jointe soit inspectée, tous parce que le parseur et
    # le bac à sable ne définissaient pas la pièce jointe de la même façon
    # (définition désormais unique, parser.is_attachment_part).
    # L'incomplétude redevient aussi décisive dès qu'il y a une raison de se
    # méfier : authentification en défaut, indice défavorable réel, preuve
    # matérielle.
    attachment_analysis_complete = _attachment_analysis_complete(dossier, deep)
    strong_adverse = any(
        isinstance(clue, dict)
        and clue.get("direction") == "adverse"
        and int(clue.get("strength") or 0) >= 20
        for clue in clues
    )
    incomplete_analysis_is_decisive = bool(
        not allow_identity_authenticated
        or strong_adverse
        or material_evidence
        or not attachment_analysis_complete
    )
    # Le choix du destinataire de n'être interrogé que sur un vrai doute. Un
    # vrai doute est ce qui fait déjà barrière ailleurs, jamais une simple
    # incertitude du juge : analyse inachevée, promotion, activité mal lue ou
    # premier contact sans faisceau n'en sont pas. La pièce jointe que rien
    # n'a pu ouvrir en reste un : c'est le seul inconnu qui peut exécuter.
    ask_only_on_real_doubt = bool(
        isinstance(history, dict) and history.get("ask_only_on_real_doubt")
    )
    real_doubt = bool(
        material_evidence
        or adverse_correlations
        or sender_policy == "hold"
        or not attachment_analysis_complete
    )
    return {
        "version": JUDGMENT_RULES_VERSION,
        "verdict_is_final": True,
        "confidence_required": round(confidence_required, 3),
        # Grille de lecture, jamais une note : ce que chaque famille a vu, y
        # compris quand elle n'a rien vu. Aucun total n'est calculé ici, et il
        # ne faut pas en fabriquer un - l'accumulation d'indices faibles ne
        # devient pas une preuve parce qu'on l'a additionnée.
        "family_coverage": family_coverage(clues),
        "converging_families": converging_families(clues),
        "trusted_sender": trusted_sender,
        "trusted_sender_noise_is_not_a_reason_to_ask": trusted_sender,
        "incomplete_analysis_is_decisive": incomplete_analysis_is_decisive,
        "deep_execution_complete": bool(deep.get("complete"))
        and attachment_analysis_complete,
        "attachment_analysis_complete": attachment_analysis_complete,
        "static_investigation_complete": message.get("investigation_status")
        == "complete",
        "url_coverage": _bounded(coverage) if isinstance(coverage, dict) else {},
        "authenticated_sender_policy": sender_policy,
        "adverse_points_observed": int(message.get("adverse_points") or 0),
        "material_danger_evidence": material_evidence,
        "identity_destination_conflict": any(
            isinstance(clue, dict)
            and clue.get("clue_code") == "CORRELATION_UNVERIFIED_IDENTITY_DESTINATION"
            and clue.get("direction") == "adverse"
            for clue in clues
        ),
        "legitimate_confirmations": confirmations,
        "adverse_confirmations": adverse_confirmations,
        # Ce que la confiance aurait donné, gardé pour l'audit ; ce qui s'est
        # réellement appliqué est threshold_reduction_applied.
        "learned_reduction": round(learned_reduction, 3),
        "authenticated_allow_reduction": round(authenticated_allow_reduction, 3),
        "threshold_reduction_applied": round(reduction_applied, 3),
        "reduction_suspended_by": adverse_correlations[:8],
        "allow_identity_authenticated": allow_identity_authenticated,
        "ask_only_on_real_doubt": ask_only_on_real_doubt,
        "real_doubt": real_doubt,
        "binding_rules": [
            "trusted_sender_still_yields_to_material_danger",
            "deliver_only_legitimate_without_doubt",
            "legitimate_confidence_must_reach_threshold",
            "actual_analysis_failure_requires_undetermined",
            "material_danger_requires_human_review",
            "authenticated_hold_requires_human_review",
            "coverage_limit_is_context_not_an_automatic_veto",
            "unanalyzed_attachment_is_always_decisive",
            "adverse_correlation_suspends_sender_trust",
            "unverified_identity_with_destination_conflict_requires_review",
            "participant_asked_only_on_real_doubt",
        ],
    }
