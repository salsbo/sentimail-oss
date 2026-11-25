"""Évaluation parallèle (shadow) via l'API Google Gemini Decisions.

Collecte des métriques calibrées sur chaque courrier jugé, sans jamais influer
sur la décision exécutoire ni retarder la livraison. Tout échec reste silencieux
pour le pipeline principal et journalisé dans `decisions_api_shadow`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import asyncpg
import httpx

from sentimail_v3.config import Settings, load_settings
from sentimail_v3.judgment.dossier_view import _json
from sentimail_v3.judgment.events import _log
from sentimail_v3.llm_accounting import observed_call

MAX_INPUT_CHARS = 24_000
MAX_BODY_CHARS = 12_000
MAX_CLUES = 40
MAX_URLS = 25
MAX_ATTACHMENTS = 15
NEUTRAL_USER_AGENT = "Mozilla/5.0 (compatible)"

SHADOW_QUESTIONS: dict[str, dict[str, Any]] = {
    "classification": {
        "type": "choice",
        "instructions": (
            "Classe la sécurité globale de ce courrier électronique à partir de "
            "l'expéditeur, du texte visible, de l'authentification et des indices."
        ),
        "criteria": {
            "legitimate": "Courrier légitime, attendu ou correspondance normale sans tromperie.",
            "spam": "Sollicitation commerciale non demandée, prospection de masse ou indésirable.",
            "dangerous": "Hameçonnage, usurpation d'identité, arnaque financière ou menace malveillante.",
        },
    },
    "delivery_decision": {
        "type": "choice",
        "instructions": (
            "Choisis l'action de livraison appropriée pour protéger la boîte de réception."
        ),
        "criteria": {
            "deliver": "Livrer normalement en boîte de réception.",
            "junk": "Classer directement dans les indésirables.",
            "ask_user": "Retenir le message et demander confirmation à l'utilisateur en cas de doute.",
        },
    },
    "is_obvious_scam": {
        "type": "noul",
        "instructions": (
            "Le message est-il une arnaque manifeste, une fraude évidente ou une "
            "tentative de tromperie grossière ?"
        ),
    },
    "is_brand_impersonation": {
        "type": "noul",
        "instructions": (
            "Le message usurpe-t-il l'identité d'une marque, d'une banque, d'un "
            "service connu ou d'une administration ?"
        ),
    },
    "requests_sensitive_action": {
        "type": "noul",
        "instructions": (
            "Le message demande-t-il une action sensible : connexion, saisie "
            "d'identifiants, paiement, virement, code, rappel téléphonique urgent "
            "ou ouverture d'une pièce jointe risquée ?"
        ),
    },
    "risk_score": {
        "type": "score",
        "instructions": (
            "Évalue le niveau de risque global du courrier sur une échelle ordonnée de 1 à 5."
        ),
        "criteria": [
            "1: Légitime, aucun indice de risque",
            "2: Faible risque ou courrier commercial bénin",
            "3: Doute significatif nécessitant vérification",
            "4: Indésirable ou tentative suspecte probable",
            "5: Menace avérée, hameçonnage ou fraude critique",
        ],
    },
}


def resolve_gemini_api_key(settings: Settings) -> str:
    """Résout la clé API Gemini par ordre de priorité sans jamais la journaliser."""
    candidates: list[Path] = []
    key_file = getattr(settings, "gemini_api_key_file", None)
    if key_file:
        candidates.append(Path(key_file))
    secrets_dir = getattr(settings, "provider_secrets_dir", "")
    if secrets_dir:
        candidates.append(Path(secrets_dir) / "gemini_api_key")
    for path in candidates:
        try:
            if path.is_file():
                value = path.read_text(encoding="utf-8").strip()
                if value:
                    return value
        except OSError:
            continue
    return os.environ.get("GEMINI_API_KEY", "").strip()


def build_shadow_input(dossier: dict[str, Any], *, max_chars: int = MAX_INPUT_CHARS) -> str:
    """Construit une représentation textuelle bornée du dossier (sans EML brut ni HTML)."""
    message = dossier.get("message")
    message = message if isinstance(message, dict) else {}

    sections: list[str] = []

    header_lines: list[str] = []
    for label, key in (
        ("From", "from_header"),
        ("Envelope-From", "envelope_from"),
        ("Reply-To", "reply_to_header"),
        ("Return-Path", "return_path_header"),
        ("Subject", "subject"),
    ):
        val = message.get(key)
        if val:
            header_lines.append(f"{label}: {str(val).strip()[:400]}")
    if header_lines:
        sections.append("=== EN-TÊTES ===\n" + "\n".join(header_lines))

    # Résumé d'authentification à partir des en-têtes sélectionnés
    selected_headers = dossier.get("selected_headers")
    auth_lines: list[str] = []
    if isinstance(selected_headers, list):
        for hdr in selected_headers:
            if not isinstance(hdr, dict):
                continue
            name = str(hdr.get("name_normalized") or "").lower()
            if name in {"authentication-results", "x-spamd-result", "x-spam-status"}:
                val = str(hdr.get("value") or "").strip()
                if val:
                    auth_lines.append(f"{name}: {val[:500]}")
                    if len(auth_lines) >= 6:
                        break
    if auth_lines:
        sections.append("=== AUTHENTIFICATION ===\n" + "\n".join(auth_lines))

    # Indices extraits par le pipeline statique et profond
    clues = dossier.get("clues")
    clue_lines: list[str] = []
    if isinstance(clues, list):
        for clue in clues[:MAX_CLUES]:
            if not isinstance(clue, dict):
                continue
            code = str(clue.get("clue_code") or "")
            direction = str(clue.get("direction") or "")
            strength = clue.get("strength")
            statement = str(clue.get("statement") or "").strip()[:240]
            if code or statement:
                clue_lines.append(f"- [{direction}/{strength}] {code}: {statement}")
    if clue_lines:
        sections.append("=== INDICES ===\n" + "\n".join(clue_lines))

    # URLs et domaines observés
    entities = dossier.get("entities")
    url_lines: list[str] = []
    if isinstance(entities, list):
        for ent in entities:
            if not isinstance(ent, dict):
                continue
            etype = str(ent.get("entity_type") or "").lower()
            if etype in {"url", "domain"}:
                val = str(ent.get("value_normalized") or "").strip()[:300]
                role = str(ent.get("role") or "")
                if val:
                    url_lines.append(f"- ({etype}/{role}) {val}")
                    if len(url_lines) >= MAX_URLS:
                        break
    if url_lines:
        sections.append("=== LIENS ET DOMAINES ===\n" + "\n".join(url_lines))

    # Métadonnées des pièces jointes (jamais le contenu)
    attachments = dossier.get("attachment_metadata")
    att_lines: list[str] = []
    if isinstance(attachments, list):
        for att in attachments[:MAX_ATTACHMENTS]:
            if not isinstance(att, dict):
                continue
            filename = str(att.get("filename") or "(sans nom)")[:160]
            ctype = str(att.get("content_type") or "")[:100]
            size = att.get("decoded_size_bytes")
            att_lines.append(f"- {filename} ({ctype}, {size} octets)")
    if att_lines:
        sections.append("=== PIÈCES JOINTES ===\n" + "\n".join(att_lines))

    # Texte visible borné (jamais body_html ni raw_eml)
    body_text = message.get("body_text")
    if isinstance(body_text, str) and body_text.strip():
        sections.append("=== TEXTE VISIBLE ===\n" + body_text.strip()[:MAX_BODY_CHARS])

    combined = "\n\n".join(sections)
    if len(combined) > max_chars:
        combined = combined[:max_chars]
    return combined


def build_decisions_payload(model: str, input_text: str) -> dict[str, Any]:
    """Construit la charge utile JSON attendue par l'API Gemini Decisions."""
    return {
        "model": model,
        "input": input_text,
        "questions": SHADOW_QUESTIONS,
    }


def _to_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _parse_choice(answer: Any) -> tuple[str | None, float | None]:
    if not isinstance(answer, dict):
        return None, None
    probs = answer.get("probabilities")
    best_choice: str | None = None
    best_prob: float | None = None
    if isinstance(probs, dict) and probs:
        numeric_probs = [
            (str(k), _to_float(v)) for k, v in probs.items()
        ]
        valid = [(k, v) for k, v in numeric_probs if v is not None]
        if valid:
            best_choice, best_prob = max(valid, key=lambda item: item[1])
    raw_choice = answer.get("choice")
    choice = str(raw_choice) if isinstance(raw_choice, str) and raw_choice else best_choice
    confidence = _to_float(answer.get("confidence"))
    if confidence is None:
        if choice is not None and isinstance(probs, dict) and choice in probs:
            confidence = _to_float(probs.get(choice))
        else:
            confidence = best_prob
    return choice, confidence


def _parse_noul(answer: Any) -> float | None:
    if not isinstance(answer, dict):
        return _to_float(answer)
    for key in ("noul", "probability", "yes", "true", "score"):
        val = _to_float(answer.get(key))
        if val is not None:
            return val
    return None


def _parse_score(answer: Any) -> float | None:
    if not isinstance(answer, dict):
        return _to_float(answer)
    val = _to_float(answer.get("score"))
    if val is not None:
        return val
    probs = answer.get("probabilities")
    if isinstance(probs, dict) and probs:
        total = 0.0
        weighted = 0.0
        for k, v in probs.items():
            key_num = _to_float(k)
            prob_num = _to_float(v)
            if key_num is not None and prob_num is not None:
                weighted += key_num * prob_num
                total += prob_num
        if total > 0:
            return weighted / total
    return None


def compute_unsafe_divergence(
    predicted_decision: str | None,
    binding_classification: str,
    binding_decision: str,
) -> bool:
    """Vrai si l'API recommande `deliver` alors que le verdict exécutoire protège."""
    return predicted_decision == "deliver" and (
        binding_classification in {"spam", "dangerous"}
        or binding_decision in {"junk", "ask_user"}
    )


def parse_decisions_response(
    payload: dict[str, Any],
    *,
    binding_classification: str,
    binding_decision: str,
) -> dict[str, Any]:
    """Extrait les métriques calibrées et les indicateurs d'accord de la réponse API."""
    answers = payload.get("answers")
    answers = answers if isinstance(answers, dict) else {}

    usage = payload.get("usage")
    usage = usage if isinstance(usage, dict) else {}
    raw_tokens = usage.get("total_input_tokens", usage.get("input_tokens"))
    input_tokens = (
        int(raw_tokens)
        if isinstance(raw_tokens, int) and not isinstance(raw_tokens, bool) and raw_tokens >= 0
        else None
    )

    predicted_classification, classification_confidence = _parse_choice(
        answers.get("classification")
    )
    predicted_decision, decision_confidence = _parse_choice(
        answers.get("delivery_decision")
    )
    scam_probability = _parse_noul(answers.get("is_obvious_scam"))
    impersonation_probability = _parse_noul(answers.get("is_brand_impersonation"))
    sensitive_action_probability = _parse_noul(answers.get("requests_sensitive_action"))
    risk_score = _parse_score(answers.get("risk_score"))

    agrees_classification = (
        predicted_classification == binding_classification
        if predicted_classification is not None
        else None
    )
    agrees_decision = (
        predicted_decision == binding_decision
        if predicted_decision is not None
        else None
    )
    unsafe_divergence = compute_unsafe_divergence(
        predicted_decision, binding_classification, binding_decision
    )

    return {
        "input_tokens": input_tokens,
        "predicted_classification": predicted_classification,
        "predicted_decision": predicted_decision,
        "classification_confidence": classification_confidence,
        "decision_confidence": decision_confidence,
        "scam_probability": scam_probability,
        "impersonation_probability": impersonation_probability,
        "sensitive_action_probability": sensitive_action_probability,
        "risk_score": risk_score,
        "answers": answers,
        "agrees_classification": agrees_classification,
        "agrees_decision": agrees_decision,
        "unsafe_divergence": unsafe_divergence,
    }


async def _persist_shadow_row(
    pool: Any,
    *,
    message_id: str,
    verdict_run_id: str | None,
    model_name: str,
    status: str,
    error_type: str | None,
    latency_ms: float,
    input_tokens: int | None,
    binding_classification: str,
    binding_decision: str,
    binding_confidence: float | None,
    predicted_classification: str | None = None,
    predicted_decision: str | None = None,
    classification_confidence: float | None = None,
    decision_confidence: float | None = None,
    scam_probability: float | None = None,
    impersonation_probability: float | None = None,
    sensitive_action_probability: float | None = None,
    risk_score: float | None = None,
    answers: dict[str, Any] | None = None,
    agrees_classification: bool | None = None,
    agrees_decision: bool | None = None,
    unsafe_divergence: bool = False,
) -> None:
    await pool.execute(
        """
        INSERT INTO decisions_api_shadow (
            message_id, verdict_run_id, model_name, status, error_type,
            latency_ms, input_tokens,
            binding_classification, binding_decision, binding_confidence,
            predicted_classification, predicted_decision,
            classification_confidence, decision_confidence,
            scam_probability, impersonation_probability,
            sensitive_action_probability, risk_score,
            answers, agrees_classification, agrees_decision, unsafe_divergence
        ) VALUES (
            $1::uuid, $2::uuid, $3, $4, $5,
            $6, $7,
            $8, $9, $10,
            $11, $12,
            $13, $14,
            $15, $16,
            $17, $18,
            $19::jsonb, $20, $21, $22
        )
        """,
        message_id,
        verdict_run_id,
        model_name,
        status,
        error_type,
        latency_ms,
        input_tokens,
        binding_classification,
        binding_decision,
        binding_confidence,
        predicted_classification,
        predicted_decision,
        classification_confidence,
        decision_confidence,
        scam_probability,
        impersonation_probability,
        sensitive_action_probability,
        risk_score,
        _json(answers or {}),
        agrees_classification,
        agrees_decision,
        unsafe_divergence,
    )


async def evaluate_shadow(
    pool: Any,
    client: httpx.AsyncClient,
    settings: Settings,
    *,
    message_id: str,
    verdict_run_id: str | None,
    dossier: dict[str, Any],
    binding_result: dict[str, Any],
    binding_judgment: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Exécute l'évaluation shadow Gemini Decisions de manière strictement fail-soft."""
    if not getattr(settings, "gemini_decisions_enabled", False):
        return None
    api_key = resolve_gemini_api_key(settings)
    if not api_key:
        return None

    model_name = str(getattr(settings, "gemini_decisions_model", "gemini-decision-1"))
    decisions_url = str(
        getattr(
            settings,
            "gemini_decisions_url",
            "https://generativelanguage.googleapis.com/v1beta/decisions",
        )
    )
    timeout_seconds = float(getattr(settings, "gemini_decisions_timeout_seconds", 10.0))

    binding_classification = str(
        (binding_judgment or {}).get("classification")
        or binding_result.get("classification")
        or "undetermined"
    )
    binding_decision = str(
        (binding_judgment or {}).get("delivery_decision")
        or binding_result.get("delivery_decision")
        or "ask_user"
    )
    binding_confidence = _to_float(
        (binding_judgment or {}).get("confidence")
        if binding_judgment and "confidence" in binding_judgment
        else binding_result.get("confidence")
    )

    started = time.perf_counter()
    try:
        input_text = build_shadow_input(dossier)
        payload = build_decisions_payload(model_name, input_text)
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
            "User-Agent": NEUTRAL_USER_AGENT,
        }

        async def _invoke() -> tuple[str, dict[str, Any]]:
            response = await asyncio.wait_for(
                client.post(
                    decisions_url,
                    headers=headers,
                    json=payload,
                    timeout=timeout_seconds,
                ),
                timeout=timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("decisions_api response is not a JSON object")
            usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
            in_tokens = usage.get("total_input_tokens", usage.get("input_tokens"))
            return (
                json.dumps(data, ensure_ascii=False),
                {
                    "http_status": response.status_code,
                    "usage": {
                        "input_tokens": in_tokens,
                        "output_tokens": 0,
                    },
                    "parsed_body": data,
                },
            )

        _, metadata = await observed_call(
            pool,
            role="decisions_shadow",
            provider="gemini_decisions",
            model=model_name,
            invoke=_invoke,
        )
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        parsed = parse_decisions_response(
            metadata["parsed_body"],
            binding_classification=binding_classification,
            binding_decision=binding_decision,
        )
        await _persist_shadow_row(
            pool,
            message_id=message_id,
            verdict_run_id=verdict_run_id,
            model_name=model_name,
            status="ok",
            error_type=None,
            latency_ms=latency_ms,
            binding_classification=binding_classification,
            binding_decision=binding_decision,
            binding_confidence=binding_confidence,
            **parsed,
        )
        _log(
            "decisions_shadow.complete",
            message_id=message_id,
            verdict_run_id=verdict_run_id,
            model=model_name,
            latency_ms=latency_ms,
            input_tokens=parsed["input_tokens"],
            predicted_classification=parsed["predicted_classification"],
            predicted_decision=parsed["predicted_decision"],
            agrees_classification=parsed["agrees_classification"],
            agrees_decision=parsed["agrees_decision"],
            unsafe_divergence=parsed["unsafe_divergence"],
        )
        return {"status": "ok", "latency_ms": latency_ms, **parsed}
    except Exception as exc:  # noqa: BLE001 - évaluation shadow strictement fail-soft
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        error_type = type(exc).__name__
        try:
            await _persist_shadow_row(
                pool,
                message_id=message_id,
                verdict_run_id=verdict_run_id,
                model_name=model_name,
                status="error",
                error_type=error_type,
                latency_ms=latency_ms,
                input_tokens=None,
                binding_classification=binding_classification,
                binding_decision=binding_decision,
                binding_confidence=binding_confidence,
            )
        except Exception as persist_exc:  # noqa: BLE001 - ne jamais propager
            _log(
                "decisions_shadow.persist_failed",
                message_id=message_id,
                error=type(persist_exc).__name__,
            )
        _log(
            "decisions_shadow.failed",
            message_id=message_id,
            verdict_run_id=verdict_run_id,
            model=model_name,
            error_type=error_type,
            latency_ms=latency_ms,
        )
        return None


async def build_report(pool: Any, *, days: int = 7) -> dict[str, Any]:
    """Calcule le rapport de comparaison shadow sur les N derniers jours."""
    row = await pool.fetchrow(
        """
        WITH scoped AS (
            SELECT s.*, gt.label AS ground_truth_label
            FROM decisions_api_shadow s
            LEFT JOIN LATERAL (
                SELECT l.label
                FROM labels l
                WHERE l.message_id = s.message_id
                  AND l.is_ground_truth = true
                ORDER BY l.created_at DESC
                LIMIT 1
            ) gt ON true
            WHERE s.created_at >= now() - make_interval(days => $1)
        )
        SELECT
            COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE status = 'ok')::int AS ok,
            COUNT(*) FILTER (WHERE status = 'error')::int AS errors,
            percentile_cont(0.50) WITHIN GROUP (ORDER BY latency_ms)
                FILTER (WHERE status = 'ok') AS p50_latency_ms,
            percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms)
                FILTER (WHERE status = 'ok') AS p95_latency_ms,
            AVG(input_tokens) FILTER (WHERE status = 'ok' AND input_tokens IS NOT NULL)
                AS avg_input_tokens,
            AVG(CASE WHEN agrees_classification THEN 1.0 ELSE 0.0 END)
                FILTER (WHERE status = 'ok' AND agrees_classification IS NOT NULL)
                AS classification_agreement_rate,
            AVG(CASE WHEN agrees_decision THEN 1.0 ELSE 0.0 END)
                FILTER (WHERE status = 'ok' AND agrees_decision IS NOT NULL)
                AS decision_agreement_rate,
            COUNT(*) FILTER (
                WHERE status = 'ok'
                  AND binding_decision = 'ask_user'
                  AND predicted_decision = 'junk'
                  AND (
                      COALESCE(scam_probability, 0.0) >= 0.5
                      OR predicted_classification IN ('spam', 'dangerous')
                  )
            )::int AS ask_user_to_junk_on_scams,
            COUNT(*) FILTER (WHERE status = 'ok' AND unsafe_divergence)::int
                AS unsafe_divergences,
            COUNT(*) FILTER (
                WHERE status = 'ok'
                  AND ground_truth_label IS NOT NULL
                  AND predicted_classification = ground_truth_label
            )::int AS ground_truth_matches,
            COUNT(*) FILTER (
                WHERE status = 'ok'
                  AND ground_truth_label IS NOT NULL
            )::int AS ground_truth_total
        FROM scoped
        """,
        max(1, int(days)),
    )
    data = dict(row) if row is not None else {}

    def _round_opt(value: Any, digits: int = 4) -> float | None:
        num = _to_float(value)
        return round(num, digits) if num is not None else None

    return {
        "days": max(1, int(days)),
        "total": int(data.get("total") or 0),
        "ok": int(data.get("ok") or 0),
        "errors": int(data.get("errors") or 0),
        "p50_latency_ms": _round_opt(data.get("p50_latency_ms"), 2),
        "p95_latency_ms": _round_opt(data.get("p95_latency_ms"), 2),
        "avg_input_tokens": _round_opt(data.get("avg_input_tokens"), 1),
        "classification_agreement_rate": _round_opt(
            data.get("classification_agreement_rate"), 4
        ),
        "decision_agreement_rate": _round_opt(data.get("decision_agreement_rate"), 4),
        "ask_user_to_junk_on_scams": int(data.get("ask_user_to_junk_on_scams") or 0),
        "unsafe_divergences": int(data.get("unsafe_divergences") or 0),
        "ground_truth_matches": int(data.get("ground_truth_matches") or 0),
        "ground_truth_total": int(data.get("ground_truth_total") or 0),
    }


async def _run_report_cli(days: int) -> None:
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    try:
        report = await build_report(pool, days=days)
        print(json.dumps(report, ensure_ascii=False, indent=2))
    finally:
        await pool.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rapport d'évaluation parallèle Gemini Decisions API."
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Affiche le rapport JSON de comparaison sur la période demandée.",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Fenêtre d'observation en jours (défaut : 7).",
    )
    args = parser.parse_args(argv)
    if args.report:
        asyncio.run(_run_report_cli(days=args.days))
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
