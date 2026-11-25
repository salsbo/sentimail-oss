from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import statistics
from collections.abc import Callable
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import parseaddr
from time import monotonic
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import asyncpg
import httpx

from sentimail_v3.code.activity_coherence import (
    COHERENCE_PROMPT,
    coherence_clue,
    coherence_question,
    should_ask,
)
from sentimail_v3.code.attachment_facts import attachment_clues
from sentimail_v3.code.correlation import correlations, identity_facts
from sentimail_v3.code.mail_profile import crowd_mailbox_domain, profile_history
from sentimail_v3.code.organisation import (
    nameserver_signature,
    organisation_signature,
    same_organisation_destinations,
)
from sentimail_v3.code.reference import nommer_dossier
from sentimail_v3.code.sender_identity import read_proven_identity
from sentimail_v3.code.sender_policy import authenticated_hold
from sentimail_v3.code.sender_site import (
    activity_registers,
    is_interstitial,
)
from sentimail_v3.code.opaque_landing import is_opaque_landing
from sentimail_v3.code.verification_gate import is_fake_verification_gate
from sentimail_v3.observation.attachment_text import attachment_text_signals
from sentimail_v3.config import Settings
from sentimail_v3.conversation.review_preferences import asks_only_on_real_doubt
from sentimail_v3.crypto import load_key, reveal
from sentimail_v3.execution.campaign_memory import match_campaign
from sentimail_v3.llm import provider_chat_json
from sentimail_v3.observation.deep_hooks import DEEP_HOOKS, run_deep_hooks
from sentimail_v3.observation.domain_age import domain_age
from sentimail_v3.observation.html_destinations import (
    BASE_URLS,
    MAX_URLS,
    TRANSIENT_URL_ERRORS,
    URLS_PER_APEX,
    _GENERIC_LINK_LABEL,
    _HtmlDestinations,
    _PRIMARY_ACTION_LINK_TEXT,
    _SECONDARY_LINK_TEXT,
    _SENSITIVE_QUERY_KEYS,
    _SIDE_EFFECT_LINK_TEXT,
    _SINGLE_USE_PATH,
    _TEXT_URL,
    _VISIBLE_DOMAIN,
    _apex,
    _bounded,
    _candidate_apex,
    _candidate_group_key,
    _candidate_priority,
    _contextualize_equivalent_url_limits,
    _decoded_part_text,
    _diverse_order,
    _explained_authenticated_redirect_limit,
    _explained_authenticated_same_apex_fetch_error,
    _extract,
    _is_definitive_target_failure,
    _message_url_candidates,
    _normalized_link_label,
    _plain_link_label,
    _representative_candidates,
    _select_url_candidates,
    _url_summary,
    is_navigation_failure,
    is_single_use_or_side_effect_url,
    is_transient_url_error,
)
from sentimail_v3.observation.observation_cache import observation_fingerprint, load_observation, save_observation
from sentimail_v3.observation.visible_content import VISIBLE_CONTENT_VERSION
from sentimail_v3.postgres_values import pg_jsonsafe, pg_text
from sentimail_v3.observation.dossier.hooks.bruit_dans_les_mots import sans_bruit
from sentimail_v3.observation.dossier.hooks.visible_text import readable_text
from sentimail_v3.observation.parser import parse_email, is_attachment_part, parse_message

_LOGGER = logging.getLogger("sentimail-v3-deep-analysis")


def _log(event: str, **fields: object) -> None:
    """Journalise un fait de l'analyse profonde.

    Trois appels existaient déjà - deux pannes de modèle et un constat effacé -
    sans que la fonction soit définie nulle part : chacun aurait levé une
    `NameError` au moment précis où l'inspection devait rester silencieuse et
    fail-soft. Le nom manquant transformait une panne bénigne en enquêteur en
    erreur.
    """
    _LOGGER.info(
        json.dumps(
            {"event": event, **nommer_dossier(dict(fields))},
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
    )

MAX_ATTACHMENTS = 10
MAX_IMAGE_ATTACHMENTS = 100
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_ATTACHMENTS_SECONDS = 120
# « image/x-png » et « image/jpg » ne sont pas des types enregistrés, mais des
# expéditeurs authentifiés les déclarent encore. Absents d'ici, leurs images
# comptaient comme documents : au-delà de la dixième, plus d'inspection, et
# le message était retenu (trois lettres d'un même fournisseur, octobre 2026).
RASTER_IMAGE_TYPES = frozenset({
    "image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp",
    "image/tiff", "image/avif", "image/x-icon", "image/vnd.microsoft.icon",
    "image/x-png", "image/jpg",
})
# En deçà de cet âge, une destination inter-apex reste suspecte même sous
# authentification : les newsletters légitimes renvoient vers des apex établis,
# pas vers un domaine enregistré la veille.
FRESH_DESTINATION_DAYS = 30


def _json(value: object) -> str:
    return json.dumps(
        _postgres_json_safe(value),
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )


def _postgres_json_safe(value: object) -> object:
    """Même projection PostgreSQL à la capture et lors des preuves profondes."""
    return pg_jsonsafe(value)


def _json_object(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        decoded = json.loads(value)
        if isinstance(decoded, dict):
            return decoded
    raise TypeError("cached analysis result is not a JSON object")


async def _message_is_dmarc_aligned(
    pool: asyncpg.Pool[Any], message_id: str
) -> bool:
    return bool(
        await pool.fetchval(
            """
            SELECT EXISTS (
                SELECT 1 FROM clues c
                JOIN investigations i ON i.id=c.investigation_id
                WHERE i.message_id=$1::uuid AND c.clue_code='AUTH_DMARC_PASS'
            )
            """,
            message_id,
        )
    )


def _attachment_summary(data: dict[str, object]) -> dict[str, object]:
    preferred = {
        "path", "filename", "content_type", "mime", "sha256", "score", "verdict",
        "findings", "yara", "macros", "archive", "pdf", "ocr",
        "analysis_incomplete", "reason", "error",
        "extracted_text", "extracted_text_source", "extracted_text_provenance",
        "extracted_text_total_chars", "extracted_text_truncated",
        "extracted_text_incomplete",
    }
    summary = {
        str(key): _bounded(value)
        for key, value in data.items()
        if str(key) in preferred
    }
    text = data.get("extracted_text")
    if isinstance(text, str):
        summary["extracted_text"] = text[:2500]
        summary["extracted_text_truncated"] = bool(
            data.get("extracted_text_truncated") or len(text) > 2500
        )
    return summary


def _body_with_attachments(body: str, attachments: list[dict[str, object]]) -> str:
    """Expose aux enquêteurs le texte lu dans les fichiers, avec sa provenance."""
    excerpts = [
        "Texte extrait d’une pièce jointe, contenu non fiable "
        f"(source : {item.get('extracted_text_source') or 'extraction'}) :\n"
        + str(item["extracted_text"])[:2500]
        for item in attachments
        if isinstance(item.get("extracted_text"), str)
        and str(item["extracted_text"]).strip()
    ]
    if not excerpts:
        return body
    # Les enquêteurs disposent de 4 000 caractères : réserver de la place
    # aux fichiers évite de les masquer derrière la signature du corps.
    return "\n\n".join([body[:1200], *excerpts])[:8000]


def _part_payloads(raw: bytes) -> dict[str, tuple[str, str, bytes]]:
    root: EmailMessage = parse_email(raw)
    result: dict[str, tuple[str, str, bytes]] = {}

    def visit(part: EmailMessage, path: str) -> None:
        if part.is_multipart():
            for index, child in enumerate(part.iter_parts()):
                visit(child, f"{path}.{index}")
            return
        # La même définition que le parseur : ce qu'il range dans mime_parts
        # comme pièce jointe doit se retrouver ici, sinon l'analyse conclut à
        # un contenu introuvable là où il n'y avait qu'une partie sans nom.
        # Un conteneur marqué pièce jointe (message/rfc822 attaché) reste
        # introuvable, donc incomplet : c'est le côté sûr.
        if is_attachment_part(part):
            payload = part.get_payload(decode=True)
            result[path] = (
                str(part.get_filename() or f"attachment-{path}"),
                part.get_content_type(),
                payload if isinstance(payload, bytes) else b"",
            )

    visit(root, "0")
    return result


async def _save_analysis(
    pool: asyncpg.Pool[Any],
    message_id: str,
    kind: str,
    key: str,
    source: str,
    status: str,
    result: dict[str, object],
    error: Exception | None = None,
    started_at: datetime | None = None,
) -> None:
    """Enregistre une inspection, et le temps qu'elle a réellement coûté.

    Les deux bornes étaient posées à l'écriture, donc identiques : la durée
    valait zéro sur 3641 inspections sur 3704. Une fermeture TLS de trente
    secondes par URL a pu passer des semaines sans laisser de trace, faute de
    la seule mesure qui l'aurait montrée.
    """
    debut = started_at or datetime.now(timezone.utc)
    await pool.execute(
        """
        INSERT INTO external_analyses (
            message_id, subject_kind, subject_key, source, status, result,
            error_type, error_detail, started_at, completed_at
        ) VALUES ($1::uuid,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,now())
        ON CONFLICT (message_id, subject_kind, subject_key, source) DO UPDATE SET
            status=EXCLUDED.status, result=EXCLUDED.result,
            error_type=EXCLUDED.error_type, error_detail=EXCLUDED.error_detail,
            started_at=EXCLUDED.started_at,
            completed_at=now()
        """,
        message_id,
        kind,
        key,
        source,
        status,
        _json(result),
        type(error).__name__ if error else None,
        pg_text(str(error)[:500]) if error else None,
        debut,
    )


async def _fetch_url_analysis(
    client: httpx.AsyncClient,
    settings: Settings,
    url: str,
    key: str,
    profile: str = "scanner",
) -> tuple[dict[str, object], str, Exception | None]:
    try:
        response = await client.post(
            f"{settings.url_sandbox_url}/fetch",
            json={"url": url, "decode_qr": True, "profile": profile},
            timeout=45,
        )
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict):
            raise TypeError("invalid URL sandbox response")
    except Exception as exc:  # noqa: BLE001 - preuve d'incomplétude
        parsed = urlsplit(url)
        return (
            {
                "initial_url": url,
                "initial_host": parsed.hostname or "",
                "initial_apex": _apex(parsed.hostname or ""),
                "url_hash": key,
                "analysis_incomplete": True,
                "error": f"sandbox_request:{type(exc).__name__}",
            },
            "error",
            exc,
        )
    data = _postgres_json_safe(value)
    if not isinstance(data, dict):
        raise TypeError("invalid sanitized URL sandbox response")
    return data, "ok", None


async def fetch_url_analysis_with_retry(
    client: httpx.AsyncClient,
    settings: Settings,
    url: str,
    key: str,
    apex_deja_muets: set[str] | None = None,
    on_attempt: Callable[[], None] | None = None,
) -> tuple[dict[str, object], str, Exception | None]:
    """Rejoue une seule fois un délai réseau, sauf si l'apex s'est déjà tu.

    Le sandbox est un service distant : un délai isolé est souvent passager, et
    une seconde tentative évite qu'un aléa devienne une preuve manquante.

    Mais quand le même apex vient déjà de rendre un délai dans ce message, ce
    n'est plus un aléa - c'est un domaine durablement muet, et le rejeu double
    le coût précisément là où il ne rapportera rien. Le 18 août, seize URL d'un
    même apex ont été inspectées deux fois chacune sans jamais rien ramener.

    ``on_attempt`` marque le début de la tentative dont la durée compte.
    """
    if on_attempt is not None:
        on_attempt()
    data, status, exc = await _fetch_url_analysis(client, settings, url, key)
    if not is_transient_url_error(data):
        return data, status, exc
    apex = str(data.get("initial_apex") or "")
    if apex_deja_muets is not None and apex:
        if apex in apex_deja_muets:
            renonce = dict(data)
            renonce["retry_skipped"] = True
            renonce["retry_skip_reason"] = "apex_deja_muet"
            return renonce, status, exc
        apex_deja_muets.add(apex)
    # Le chrono ne repart que si le bac à sable a tenu son plafond et l'a dit.
    # Un délai côté client (sandbox_request:*) reste compté : c'est lui que la
    # mesure doit montrer, même quand le rejeu réussit.
    if on_attempt is not None and str(data.get("error") or "") in TRANSIENT_URL_ERRORS:
        on_attempt()
    retried, retried_status, retried_exc = await _fetch_url_analysis(
        client, settings, url, key
    )
    if not is_transient_url_error(retried):
        return retried, retried_status, retried_exc
    persistent = dict(retried)
    persistent["retry_attempted"] = True
    return persistent, retried_status, retried_exc


async def _analyze_urls(
    pool: asyncpg.Pool[Any], client: httpx.AsyncClient, settings: Settings,
    message_id: str, raw: bytes, *, deadline: float | None = None,
) -> tuple[list[dict[str, object]], bool, dict[str, object]]:
    candidates, resource_total = _message_url_candidates(raw)
    selected, coverage = _select_url_candidates(candidates)
    coverage["render_resources_total"] = resource_total
    local_deadline = monotonic() + max(0.001, float(getattr(settings, "url_analysis_deadline_seconds", 90)))
    deadline = min(deadline, local_deadline) if deadline is not None else local_deadline
    concurrency = max(1, min(4, int(getattr(settings, "url_analysis_concurrency", 2))))
    slots = asyncio.Semaphore(concurrency)
    hosts: dict[str, asyncio.Lock] = {}
    apex_deja_muets: set[str] = set()
    authenticated = await _message_is_dmarc_aligned(pool, message_id)

    async def inspect(candidate: dict[str, str]) -> tuple[dict[str, object], str, bool]:
        url = candidate["url"]
        key = hashlib.sha256(url.encode()).hexdigest()
        reason = ""
        if is_single_use_or_side_effect_url(url) or _SIDE_EFFECT_LINK_TEXT.search(candidate.get("visible_text", "")):
            reason = "protected_single_use_or_side_effect_url"
        elif candidate.get("link_context") in {"footer", "secondary_navigation"}:
            reason = "non_primary_navigation"
        if reason:
            data = {"initial_url": url, "analysis_skipped": True, "skip_reason": reason,
                    "sender_dmarc_aligned": authenticated}
            await _save_analysis(pool, message_id, "url", key, "url-sandbox", "skipped", data)
            return data, key, False
        cached = await pool.fetchrow(
            """SELECT status,result FROM external_analyses
               WHERE message_id=$1::uuid AND subject_kind='url'
                 AND subject_key=$2 AND source='url-sandbox'""", message_id, key,
        )
        data = _json_object(cached["result"]) if cached is not None else {}
        if cached is not None and cached["status"] == "ok" and not is_transient_url_error(data):
            comparison = data.get("profile_comparison")
            profile_complete = isinstance(comparison, dict) and comparison.get("comparison_incomplete") is False
            # Un primaire enregistré ne prouve pas que le second regard a
            # abouti : son interruption reprend ici sans repayer le primaire.
            return data, key, not profile_complete
        # La durée enregistrée exclut la file, et le premier essai quand le bac
        # à sable a tenu son plafond. Un lien resté dans la file n'a pas de
        # début mesuré : sa durée vaut zéro en base.
        started: datetime | None = None

        def attempt_begins() -> None:
            nonlocal started
            started = datetime.now(timezone.utc)

        host = _candidate_apex(candidate) or str(urlsplit(url).hostname or "")
        lock = hosts.setdefault(host, asyncio.Lock())
        try:
            # L'attente d'une place compte dans le budget. Un même apex garde
            # son ordre de visite et sa mémoire des pannes passagères.
            async with asyncio.timeout(max(0.001, deadline - monotonic())):
                async with lock, slots:
                    data, status, failure = await fetch_url_analysis_with_retry(
                        client, settings, url, key, apex_deja_muets=apex_deja_muets,
                        on_attempt=attempt_begins,
                    )
        except TimeoutError as error:
            data = {"initial_url": url, "initial_host": urlsplit(url).hostname or "",
                    "initial_apex": host, "analysis_incomplete": True,
                    "error": "sandbox_request:TimeoutError", "budget_exhausted": True}
            status, failure = "error", error
        # La preuve obtenue survit à l'échec d'une autre destination. Une
        # panne SQL reste une panne opérationnelle et interrompt le run.
        await _save_analysis(pool, message_id, "url", key, "url-sandbox", status, data, failure, started_at=started)
        return data, key, status == "ok"

    tasks = [asyncio.create_task(inspect(candidate)) for candidate in selected]
    try:
        inspected = await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    results: list[dict[str, object]] = []
    comparisons = 0
    for candidate, (data, key, profile_pending) in zip(selected, inspected):
        # Les regards secondaires gardent l'ordre de sélection : la vitesse
        # d'un serveur ne choisit pas quels liens obtiennent les trois places.
        profile_selected = should_compare_profiles(data, authenticated=authenticated, deja_compares=comparisons)
        if profile_selected:
            comparisons += 1
        if profile_pending and profile_selected:
            profile_started = monotonic()
            try:
                async with asyncio.timeout(max(0.001, deadline - monotonic())):
                    other, _, _ = await _fetch_url_analysis(client, settings, candidate["url"], key, profile="browser")
            except TimeoutError:
                other = {"error": "url_analysis_budget_exhausted", "analysis_incomplete": True}
            data = dict(data)
            data["profile_comparison"] = compare_profiles(data, other)
            data["profile_comparison"]["duration_ms"] = round((monotonic()-profile_started)*1000, 3)
            # Le second regard enrichit le résultat sans effacer les dates de
            # l'inspection primaire. Sa propre durée est conservée séparément.
            await pool.execute(
                "UPDATE external_analyses SET result=$3::jsonb "
                "WHERE message_id=$1::uuid AND subject_kind='url' AND subject_key=$2 AND source='url-sandbox'",
                message_id, key, _json(data),
            )
        explained_fetch = _explained_authenticated_same_apex_fetch_error(data, authenticated)
        if _explained_authenticated_redirect_limit(data, authenticated) or explained_fetch:
            data = dict(data)
            data["navigation_limit_explained"] = True
            data["navigation_limit_reason"] = (
                "authenticated_same_apex_fetch_error" if explained_fetch
                else "authenticated_https_chain_stable_on_final_apex"
            )
        results.append(_url_summary(data, key, candidate))
    _contextualize_equivalent_url_limits(results, authenticated)
    complete = all(value.get("role") == "render_resource" or value.get("analysis_skipped")
                   or value.get("navigation_limit_explained") or _is_definitive_target_failure(value.get("error"))
                   or not (value.get("error") or value.get("analysis_incomplete")) for value in results)
    coverage["actionable_analyzed"] = sum(value.get("role") != "render_resource" for value in results)
    coverage["render_resources_analyzed"] = sum(value.get("role") == "render_resource" for value in results)
    coverage["budget_exhausted"] = any(data.get("budget_exhausted") for data, _, _ in inspected)
    coverage["concurrency_limit"] = concurrency
    return results, complete, coverage

async def _analyze_attachments(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    message_id: str,
    raw: bytes,
    *, deadline: float | None = None,
) -> tuple[list[dict[str, object]], bool]:
    parts = _part_payloads(raw)
    rows = await pool.fetch(
        """
        SELECT path, filename, content_type, decoded_size_bytes, decoded_sha256
        FROM mime_parts WHERE message_id=$1::uuid AND is_attachment=true
        ORDER BY ordinal
        """,
        message_id,
    )
    results: list[dict[str, object]] = []
    complete = True
    local_deadline = monotonic() + MAX_ATTACHMENTS_SECONDS
    deadline = min(deadline, local_deadline) if deadline is not None else local_deadline
    total_bytes = 0
    images = documents = 0
    for row in rows:
        path = str(row["path"])
        key = str(row["decoded_sha256"] or path)
        item = parts.get(path)
        image = item is not None and item[1] in RASTER_IMAGE_TYPES
        images += int(image)
        documents += int(not image)
        total_bytes += len(item[2]) if item else 0
        reason = ""
        if item is None or len(item[2]) > MAX_ATTACHMENT_BYTES:
            reason = "payload_unavailable_or_too_large"
        elif images > MAX_IMAGE_ATTACHMENTS or documents > MAX_ATTACHMENTS:
            reason = "attachment_count_budget_exceeded"
        elif total_bytes > MAX_ATTACHMENT_BYTES:
            reason = "attachment_total_bytes_exceeded"
        elif monotonic() >= deadline:
            reason = "attachment_time_budget_exceeded"
        if reason:
            complete = False
            data = {
                "path": path,
                "filename": row["filename"],
                "content_type": row["content_type"],
                "sha256": key,
                "analysis_incomplete": True,
                "reason": reason,
            }
            await _save_analysis(
                pool, message_id, "attachment", key, "file-sandbox", "skipped", data
            )
            results.append(_attachment_summary(data))
            continue
        filename, content_type, payload = item
        cached = await pool.fetchrow(
            """
            SELECT status, result FROM external_analyses
            WHERE message_id=$1::uuid AND subject_kind='attachment'
              AND subject_key=$2 AND source='file-sandbox'
            """,
            message_id,
            key,
        )
        if cached is not None and cached["status"] == "ok":
            data = _json_object(cached["result"])
        else:
            try:
                async with asyncio.timeout(max(0.001, deadline - monotonic())):
                    response = await client.post(
                        f"{settings.file_sandbox_url}/analyze",
                        json={
                            "filename": filename,
                            "content_b64": base64.b64encode(payload).decode("ascii"),
                        },
                        timeout=min(35, max(0.001, deadline - monotonic())),
                    )
                response.raise_for_status()
                value = response.json()
                if not isinstance(value, dict):
                    raise TypeError("invalid file sandbox response")
            except Exception as exc:  # noqa: BLE001 - preuve d'incomplétude
                complete = False
                data = {
                    "path": path,
                    "filename": filename,
                    "content_type": content_type,
                    "sha256": key,
                    "analysis_incomplete": True,
                    "reason": "file_sandbox_request_failed",
                    "error": type(exc).__name__,
                }
                await _save_analysis(
                    pool,
                    message_id,
                    "attachment",
                    key,
                    "file-sandbox",
                    "error",
                    data,
                    exc,
                )
            else:
                data = _postgres_json_safe(value)  # type: ignore[assignment]
                if not isinstance(data, dict):
                    raise TypeError("invalid sanitized file sandbox response")
                data.update(
                    {
                        "path": path,
                        "filename": filename,
                        "content_type": content_type,
                        "sha256": key,
                    }
                )
                # Comme pour les URL, une panne PostgreSQL doit déclencher le
                # retry du run au lieu de fabriquer une analyse incomplète.
                await _save_analysis(
                    pool,
                    message_id,
                    "attachment",
                    key,
                    "file-sandbox",
                    "ok",
                    data,
                )
        if data.get("analysis_incomplete"):
            complete = False
        data.update(
            {
                "path": path,
                "filename": filename,
                "content_type": content_type,
                "sha256": key,
            }
        )
        results.append(_attachment_summary(data))
    return results, complete


def _technical_limit_reason(error: object) -> str:
    value = str(error or "analysis_incomplete")
    labels = {
        "fetch_error:HttpProtocolError": (
            "réponse HTTP non prise en charge par le sandbox"
        ),
        "hop_timeout": "délai de réponse HTTP dépassé",
        "sandbox_total_timeout": "budget total de navigation dépassé",
        "too_many_redirects": "limite de redirections atteinte",
        "analysis_incomplete": "inspection non terminée",
    }
    if value in labels:
        return labels[value]
    if value.startswith("sandbox_request:"):
        return "service d’inspection URL indisponible"
    if value.startswith("blocked_url:"):
        return "navigation interdite par la politique anti-SSRF"
    return "limite technique du sandbox"


def _attachment_limit_reason(value: dict[str, object]) -> str:
    reason = str(value.get("reason") or "")
    labels = {
        "payload_unavailable_or_too_large": (
            "contenu indisponible ou supérieur au budget d’analyse"
        ),
        "file_sandbox_request_failed": "service d’inspection fichier indisponible",
        "attachment_count_budget_exceeded": "nombre maximal de fichiers à inspecter dépassé",
        "attachment_total_bytes_exceeded": "taille totale des fichiers à inspecter dépassée",
        "attachment_time_budget_exceeded": "durée maximale d’inspection des fichiers atteinte",
    }
    if reason in labels:
        return labels[reason]
    findings = value.get("findings")
    if isinstance(findings, list):
        codes = [
            str(item.get("code"))
            for item in findings
            if isinstance(item, dict) and item.get("code")
        ]
        if codes:
            return "inspection partielle signalée par " + ", ".join(codes[:4])
    return "inspection du fichier non terminée"


async def _nature_facts(pool: asyncpg.Pool[Any], message_id: str) -> dict[str, object]:
    """Relit le cadre d'envoi observé par le hook, sans le recalculer."""
    facts = await pool.fetchval(
        """
        SELECT hr.facts FROM hook_runs hr
        JOIN investigations i ON i.id=hr.investigation_id
        WHERE i.message_id=$1::uuid AND hr.hook_name='nature' AND hr.status='ok'
        ORDER BY hr.created_at DESC LIMIT 1
        """,
        message_id,
    )
    # Un dossier analysé avant l'arrivée du hook n'a pas de cadre d'envoi : son
    # absence reste neutre, elle ne devient jamais une charge.
    return _json_object(facts) if facts is not None else {}


async def _content_context(pool: asyncpg.Pool[Any], message_id: str) -> dict[str, object]:
    """Relit ce que le hook content a constaté du message, sans le recalculer."""
    facts = await pool.fetchval(
        """
        SELECT hr.facts FROM hook_runs hr
        JOIN investigations i ON i.id=hr.investigation_id
        WHERE i.message_id=$1::uuid AND hr.hook_name='content' AND hr.status='ok'
        ORDER BY hr.created_at DESC LIMIT 1
        """,
        message_id,
    )
    context = _json_object(facts).get("content_context") if facts is not None else None
    return context if isinstance(context, dict) else {}


async def _headers_facts(pool: asyncpg.Pool[Any], message_id: str) -> dict[str, object]:
    """Relit ce que le hook headers a constaté, sans le recalculer.

    Le hook n'a pas accès à l'authentification : il ne peut consigner que le
    fait structurel (alignement syntaxique). C'est ici, où `authenticated`
    est connu, que ce fait peut devenir une corrélation favorable.
    """
    facts = await pool.fetchval(
        """
        SELECT hr.facts FROM hook_runs hr
        JOIN investigations i ON i.id=hr.investigation_id
        WHERE i.message_id=$1::uuid AND hr.hook_name='headers' AND hr.status='ok'
        ORDER BY hr.created_at DESC LIMIT 1
        """,
        message_id,
    )
    return _json_object(facts) if facts is not None else {}


async def _learned_signals(
    pool: asyncpg.Pool[Any], message_id: str, participant: str
) -> list[dict[str, object]]:
    """Ce que les qualifications passées disent des indices du message courant.

    L'utilisateur ne qualifie pas seulement un expéditeur : il qualifie un
    genre de message. Chaque feedback conserve les indices observés, ce qui
    permet de dire au juge combien de fois un même indice a accompagné une
    qualification humaine, pour d'autres expéditeurs. C'est un contexte
    probatoire de plus, jamais une décision : un indice fréquent dans les
    indésirables n'établit rien à lui seul.
    """
    rows = await pool.fetch(
        """
        WITH observed AS (
            SELECT DISTINCT c.clue_code
            FROM clues c
            JOIN investigations i ON i.id=c.investigation_id
            WHERE i.message_id=$1::uuid AND c.direction <> 'neutral'
        ), learned AS (
            SELECT code.value AS clue_code,
                   count(*) FILTER (WHERE l.label='legitimate') AS legitimate,
                   count(*) FILTER (
                       WHERE l.label IN ('spam','dangerous','suspect')
                   ) AS adverse,
                   count(DISTINCT l.sender_normalized) AS senders
            FROM labels l
            CROSS JOIN LATERAL jsonb_array_elements_text(
                coalesce(l.context->'signals','[]'::jsonb)
            ) AS code(value)
            WHERE l.is_ground_truth=true AND l.active=true
              AND sentimail_same_client(l.participant_email,$2)
            GROUP BY code.value
        )
        SELECT learned.* FROM learned
        JOIN observed ON observed.clue_code=learned.clue_code
        WHERE learned.legitimate + learned.adverse >= 2
          -- Un indice présent dans tous les messages ne distingue rien : seule
          -- une orientation nette des qualifications passées est informative.
          AND greatest(learned.legitimate, learned.adverse)::numeric
              / (learned.legitimate + learned.adverse) >= 0.8
        ORDER BY learned.adverse DESC, learned.legitimate DESC
        LIMIT 12
        """,
        message_id,
        participant,
    )
    return [
        {
            "clue_code": str(row["clue_code"]),
            "confirmed_legitimate": int(row["legitimate"]),
            "confirmed_adverse": int(row["adverse"]),
            "distinct_senders": int(row["senders"]),
        }
        for row in rows
    ]


async def _history(pool: asyncpg.Pool[Any], message_id: str) -> dict[str, object]:
    current = await pool.fetchrow(
        """
        SELECT envelope_from, from_header, envelope_recipients,
               raw_size_bytes, captured_at,
               (facts->>'attachment_count')::int AS attachment_count
        FROM messages WHERE id=$1::uuid
        """,
        message_id,
    )
    if current is None:
        raise RuntimeError("message not found")
    address = parseaddr(str(current["from_header"] or ""))[1]
    address = (address or str(current["envelope_from"])).casefold()
    domain = address.rsplit("@", 1)[-1] if "@" in address else ""
    participant = str((current["envelope_recipients"] or [""])[0]).casefold()
    # L'adresse se cherche telle quelle, jamais dans un motif LIKE : « _ » et
    # « % » y sont des jokers, et « jean_dupont@webmail.example », ouvrable par
    # n'importe qui, héritait du passé de « jean.dupont@webmail.example ».
    rows = await pool.fetch(
        """
        SELECT m.raw_size_bytes, m.captured_at,
               (m.facts->>'attachment_count')::int AS attachment_count
        FROM messages m
        WHERE m.id<>$1::uuid
          AND (lower(m.envelope_from)=$2 OR strpos(lower(m.from_header), $3) > 0)
          AND EXISTS (
              SELECT 1 FROM unnest(m.envelope_recipients) recipient
              WHERE sentimail_same_client(recipient,$4)
          )
        ORDER BY m.captured_at DESC LIMIT 200
        """,
        message_id,
        address,
        f"<{address}>",
        participant,
    )
    # Les labels sont lus par leurs colonnes propres : un apprentissage reste
    # opposable au prochain message même si le message d'origine a été purgé.
    labels = await pool.fetch(
        """
        SELECT l.label, count(*) AS count
        FROM labels l LEFT JOIN messages m ON m.id=l.message_id
        WHERE l.is_ground_truth=true AND l.active=true
          AND (
              (l.sender_normalized=$1
               AND sentimail_same_client(l.participant_email,$3))
              OR (
                  l.sender_normalized IS NULL
                  AND (lower(m.envelope_from)=$1 OR strpos(lower(m.from_header), $2) > 0)
                  AND EXISTS (
                      SELECT 1 FROM unnest(m.envelope_recipients) recipient
                      WHERE sentimail_same_client(recipient,$3)
                  )
              )
          )
        GROUP BY l.label
        """,
        address,
        f"<{address}>",
        participant,
    )
    feedback_rows = await pool.fetch(
        """
        SELECT l.label, l.created_at,
               left(coalesce(l.subject,m.subject,''),300) AS subject,
               left(coalesce(l.context->>'user_reason',''),1000) AS user_reason,
               left(coalesce(l.context->>'llm_explanation',''),1000) AS explanation,
               l.context->>'feedback_reason_code' AS feedback_reason_code
        FROM labels l LEFT JOIN messages m ON m.id=l.message_id
        WHERE l.is_ground_truth=true AND l.active=true
          AND (
              (l.sender_normalized=$1
               AND sentimail_same_client(l.participant_email,$3))
              OR (
                  l.sender_normalized IS NULL
                  AND (lower(m.envelope_from)=$1 OR strpos(lower(m.from_header), $2) > 0)
                  AND EXISTS (
                      SELECT 1 FROM unnest(m.envelope_recipients) recipient
                      WHERE sentimail_same_client(recipient,$3)
                  )
              )
          )
        ORDER BY l.created_at DESC LIMIT 20
        """,
        address,
        f"<{address}>",
        participant,
    )
    sizes = [int(row["raw_size_bytes"]) for row in rows]
    hours = [row["captured_at"].hour for row in rows]
    current_size = int(current["raw_size_bytes"])
    size_zscore: float | None = None
    if len(sizes) >= 5 and statistics.pstdev(sizes) > 0:
        size_zscore = (current_size - statistics.mean(sizes)) / statistics.pstdev(sizes)
    usual_hours = sorted(set(hours))
    label_counts = {str(row["label"]): int(row["count"]) for row in labels}
    # Une règle B supprime sans avis : elle ne s'applique qu'à une identité
    # prouvée. Un From usurpé ne fait ni tomber la victime sous la règle posée
    # contre l'usurpateur, ni échapper l'usurpateur à la sienne.
    identity = await read_proven_identity(pool, message_id)
    persistent_hold = await authenticated_hold(pool, message_id, identity)
    persistent_allow = await pool.fetchval(
        """
        SELECT EXISTS (
            SELECT 1 FROM sender_policies sp
            WHERE EXISTS (
                SELECT 1 FROM messages m, unnest(m.envelope_recipients) recipient
                WHERE m.id=$1::uuid
                  AND sentimail_same_client(recipient,sp.participant_email)
            )
              AND sp.active=true AND sp.action='allow'
              AND ((sp.scope='sender' AND sp.value_normalized=$2)
                OR (sp.scope='domain' AND sp.value_normalized=$3))
        )
        """,
        message_id,
        address,
        domain,
    )
    domain_profile = await pool.fetchrow(
        """
        SELECT en.status,
               en.data->>'creation_date' AS creation_date,
               en.data->>'age_days' AS age_days,
               ARRAY(
                   SELECT jsonb_array_elements_text(
                       coalesce(en.data->'countries','[]'::jsonb)
                   )
               ) AS countries
        FROM entities e JOIN enrichments en ON en.id=e.enrichment_id
        WHERE e.message_id=$1::uuid AND e.entity_type='domain'
          AND e.value_normalized=$2
        ORDER BY e.id LIMIT 1
        """,
        message_id,
        domain,
    )
    current_countries = await pool.fetch(
        """
        SELECT DISTINCT country
        FROM entities e JOIN enrichments en ON en.id=e.enrichment_id
        CROSS JOIN LATERAL jsonb_array_elements_text(
            coalesce(en.data->'countries','[]'::jsonb)
        ) country
        WHERE e.message_id=$1::uuid AND e.entity_type='ip'
          AND e.role LIKE 'header:received%'
        """,
        message_id,
    )
    historical_countries = await pool.fetch(
        """
        SELECT country, count(DISTINCT m.id) AS messages
        FROM messages m
        JOIN entities e ON e.message_id=m.id
        JOIN enrichments en ON en.id=e.enrichment_id
        CROSS JOIN LATERAL jsonb_array_elements_text(
            coalesce(en.data->'countries','[]'::jsonb)
        ) country
        WHERE m.id<>$1::uuid AND e.entity_type='ip'
          AND e.role LIKE 'header:received%'
          AND (lower(m.envelope_from)=$2 OR strpos(lower(m.from_header), $3) > 0)
          AND EXISTS (
              SELECT 1 FROM unnest(m.envelope_recipients) recipient
              WHERE lower(recipient)=$4
          )
        GROUP BY country ORDER BY messages DESC
        """,
        message_id,
        address,
        f"<{address}>",
        participant,
    )
    current_country_values = sorted(str(row["country"]) for row in current_countries)
    known_country_values = {
        str(row["country"]): int(row["messages"]) for row in historical_countries
    }
    learned_signals = await _learned_signals(pool, message_id, participant)
    apex = _apex(domain)
    # Apex éprouvé localement : une adresse jamais vue peut appartenir à un
    # domaine dont d'autres adresses ont déjà livré, toutes boîtes confondues.
    # Le label reste self-portant (voir _learned_signals) : la table `labels`
    # est interrogée directement, jamais via le message d'origine qui a pu
    # être purgé par la rétention.
    #
    # HIST-004 ne s'applique jamais quand l'adresse exacte a déjà un
    # historique (`rows` non vide) : les deux requêtes ci-dessous ne
    # payent donc leur coût que pour une adresse réellement nouvelle, au lieu
    # de tourner sur chaque message.
    # Le compte se lisait seulement pour une adresse jamais vue. Une adresse
    # connue - Nintendo, livrée deux fois - restait donc sans aucun fait de
    # livraison sur son apex, et son domaine s'accusait comme un inconnu.
    # Un message rangé dans les indésirables est « livré » pour le transport,
    # pas pour le destinataire : le compter faisait blanchir un domaine par son
    # propre spam. Le 25 septembre 2026, un faux renouvellement Prime Video
    # classé spam à 11:28 a « attesté » son domaine, et le suivant, à 11:30, a
    # vu son identité empruntée passer neutre puis a été livré comme légitime.
    # Un envoi que l'utilisateur a lui-même déclaré spam ou dangereux n'atteste
    # rien non plus. Le 3 novembre 2026, un faux reçu Amazon (M-fc7f44) a vu son
    # usurpation mise sans charge : la seule livraison d'outlook.com était un
    # hameçonnage du 20 août, livré puis étiqueté spam par le mainteneur.
    if True:
        apex_track_record = await pool.fetchrow(
            """
            SELECT count(*) AS delivered_count, min(m.captured_at) AS first_seen
            FROM messages m
            LEFT JOIN delivery_cases d ON d.message_id=m.id
            WHERE m.id<>$1::uuid
              AND m.delivery_status='delivered'
              AND coalesce(d.state,'')<>'original_filed_as_junk'
              AND coalesce(d.assessed_classification,'') NOT IN ('spam','dangerous')
              AND NOT EXISTS (
                  SELECT 1 FROM labels l
                  WHERE l.message_id=m.id AND l.is_ground_truth=true AND l.active=true
                    AND l.label IN ('spam','suspect','dangerous')
              )
              AND (
                  lower(split_part(m.envelope_from,'@',2))=$2
                  OR lower(split_part(m.envelope_from,'@',2)) LIKE $3
              )
            """,
            message_id,
            apex,
            f"%.{apex}",
        )
        # Sur une messagerie publique, le domaine réunit des inconnus sans lien
        # entre eux : seule l'adresse exacte a un passé qui lui appartient.
        sender_delivered_count = await pool.fetchval(
            """
            SELECT count(*)
            FROM messages m
            LEFT JOIN delivery_cases d ON d.message_id=m.id
            WHERE m.id<>$1::uuid
              AND m.delivery_status='delivered'
              AND coalesce(d.state,'')<>'original_filed_as_junk'
              AND coalesce(d.assessed_classification,'') NOT IN ('spam','dangerous')
              AND NOT EXISTS (
                  SELECT 1 FROM labels l
                  WHERE l.message_id=m.id AND l.is_ground_truth=true AND l.active=true
                    AND l.label IN ('spam','suspect','dangerous')
              )
              AND (lower(m.envelope_from)=$2 OR strpos(lower(m.from_header), $3) > 0)
            """,
            message_id,
            address,
            f"<{address}>",
        )
        apex_adverse_labels = await pool.fetchval(
            """
            SELECT count(*) FROM labels l
            WHERE l.is_ground_truth=true AND l.active=true
              AND l.label IN ('spam','dangerous')
              AND (
                  lower(split_part(coalesce(l.sender_normalized,''),'@',2))=$1
                  OR lower(split_part(coalesce(l.sender_normalized,''),'@',2)) LIKE $2
              )
            """,
            apex,
            f"%.{apex}",
        )
        apex_delivered_count = int((apex_track_record or {}).get("delivered_count") or 0)
        apex_first_seen = (apex_track_record or {}).get("first_seen")
        apex_track_record_age_days = (
            (current["captured_at"] - apex_first_seen).days
            if apex_first_seen is not None
            else None
        )
    # Ancienneté de sept jours minimum : sans elle, un envoi massif d'adresses
    # fraîches sous un même apex s'auto-blanchirait en quelques minutes.
    # Une messagerie publique ne s'éprouve pas : trois inconnus livrés depuis
    # gmail.com ne disent rien d'un quatrième.
    sender_apex_crowd = crowd_mailbox_domain(apex) if apex else False
    apex_established_locally = bool(
        not rows
        and not sender_apex_crowd
        and apex_delivered_count >= 3
        and isinstance(apex_track_record_age_days, int)
        and apex_track_record_age_days >= 7
        and int(apex_adverse_labels or 0) == 0
    )
    # Langue habituelle du destinataire : la dominance se lit sur ce que ce
    # destinataire a effectivement reçu (delivered), toutes boîtes confondues
    # n'aurait aucun sens ici - c'est l'habitude du lecteur qui compte. Bornée
    # aux 200 messages délivrés les plus récents (sous-requête avec LIMIT,
    # triée sur l'index existant `ix_messages_captured_at`) : un destinataire
    # ancien ne doit pas faire agréger un historique sans plafond.
    recipient_language_rows = await pool.fetch(
        """
        SELECT language, count(*) AS occurrences
        FROM (
            SELECT c.facts->>'language' AS language
            FROM clues c
            JOIN investigations i ON i.id=c.investigation_id
            JOIN messages m ON m.id=i.message_id
            WHERE c.clue_code='NATURE_MESSAGE_LANGUAGE'
              AND m.id<>$1::uuid
              AND m.delivery_status='delivered'
              AND EXISTS (
                  SELECT 1 FROM unnest(m.envelope_recipients) recipient
                  WHERE lower(recipient)=$2
              )
            ORDER BY m.captured_at DESC
            LIMIT 200
        ) bounded
        GROUP BY language
        """,
        message_id,
        participant,
    )
    recipient_language_counts = {
        str(row["language"]): int(row["occurrences"])
        for row in recipient_language_rows
        if row["language"]
    }
    recipient_language_total = sum(recipient_language_counts.values())
    recipient_dominant_language = (
        max(recipient_language_counts, key=lambda lang: recipient_language_counts[lang])
        if recipient_language_counts
        else None
    )
    recipient_language_dominance = (
        round(recipient_language_counts[recipient_dominant_language] / recipient_language_total, 3)
        if recipient_dominant_language and recipient_language_total
        else None
    )
    return {
        "sender_address": address,
        "participant_email": participant,
        "learned_signals": learned_signals,
        "sender_domain": domain,
        "sender_apex": apex,
        "previous_message_count": len(rows),
        "previous_active_days": len({row["captured_at"].date() for row in rows}),
        "first_seen": rows[-1]["captured_at"] if rows else current["captured_at"],
        "ground_truth_labels": label_counts,
        "mail_profile_history": await profile_history(pool, message_id, participant),
        "ground_truth_feedback": [
            {
                "label": str(row["label"]),
                "subject": str(row["subject"] or ""),
                "user_reason": str(row["user_reason"] or ""),
                "explanation": str(row["explanation"] or ""),
                "feedback_reason_code": row["feedback_reason_code"],
                "created_at": row["created_at"],
            }
            for row in feedback_rows
        ],
        "persistent_hold": bool(persistent_hold),
        "persistent_allow": bool(persistent_allow),
        "ask_only_on_real_doubt": await asks_only_on_real_doubt(
            pool, list(current["envelope_recipients"] or [])
        ),
        "usual_hours_utc": usual_hours,
        "current_hour_utc": current["captured_at"].hour,
        "hour_previously_seen": current["captured_at"].hour in usual_hours,
        "mean_size_bytes": round(statistics.mean(sizes), 2) if sizes else None,
        "size_zscore": round(size_zscore, 3) if size_zscore is not None else None,
        "current_size_bytes": current_size,
        "previous_attachment_rate": (
            round(sum(int(row["attachment_count"] or 0) > 0 for row in rows) / len(rows), 3)
            if rows
            else None
        ),
        "current_attachment_count": int(current["attachment_count"] or 0),
        "sender_domain_enriched": bool(domain_profile and domain_profile["status"] == "ok"),
        "sender_domain_creation_date": (
            domain_profile["creation_date"] if domain_profile else None
        ),
        "sender_domain_age_days": (
            domain_age(dict(domain_profile), current["captured_at"])
            if domain_profile else None
        ),
        "sender_domain_countries": list(domain_profile["countries"] or []) if domain_profile else [],
        "current_transport_countries": current_country_values,
        "historical_transport_countries": known_country_values,
        "unfamiliar_transport_countries": sorted(
            set(current_country_values) - set(known_country_values)
        ),
        "apex_delivered_count": apex_delivered_count,
        "sender_delivered_count": int(sender_delivered_count or 0),
        "sender_apex_crowd": sender_apex_crowd,
        "apex_track_record_age_days": apex_track_record_age_days,
        "apex_adverse_label_count": int(apex_adverse_labels or 0),
        "apex_established_locally": apex_established_locally,
        "recipient_language_total": recipient_language_total,
        "recipient_dominant_language": recipient_dominant_language,
        "recipient_language_dominance": recipient_language_dominance,
    }


_SENSITIVE_FORM_INPUTS = {
    "password": re.compile(
        r"(?:^|[_-])(?:password|passwd|passcode|session_password)(?:$|[_-])",
        re.IGNORECASE,
    ),
    "one_time_code": re.compile(
        r"(?:^|[_-])(?:otp|mfa|2fa|securitycode|verificationcode)(?:$|[_-])",
        re.IGNORECASE,
    ),
    "payment_card": re.compile(
        r"(?:^|[_-])(?:cvv|cvc|card(?:number)?|creditcard)(?:$|[_-])",
        re.IGNORECASE,
    ),
    "bank_account": re.compile(
        r"(?:^|[_-])(?:iban|bankaccount|accountnumber)(?:$|[_-])",
        re.IGNORECASE,
    ),
    "generic_secret": re.compile(
        r"(?:^|[_-])(?:secret|recoverykey|privatekey)(?:$|[_-])",
        re.IGNORECASE,
    ),
}


def _sensitive_form_categories(value: dict[str, object]) -> list[str]:
    forms = value.get("forms")
    if not isinstance(forms, list):
        return []
    categories: set[str] = set()
    for form in forms:
        if not isinstance(form, dict):
            continue
        inputs = form.get("inputs")
        names = inputs if isinstance(inputs, list) else []
        for category, pattern in _SENSITIVE_FORM_INPUTS.items():
            if any(pattern.search(str(name)) for name in names):
                categories.add(category)
    return sorted(categories)


def _attachment_signals(
    attachments: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Traduit les constats du bac à sable fichier, sans décider du verdict."""
    signals = attachment_clues(attachments)
    incomplete = [value for value in attachments if value.get("analysis_incomplete")]
    if incomplete:
        signals.append(
            {
                "article_code": "DEEP-005",
                "kind": "file_incomplete",
                "occurrences": len(incomplete),
                "attachment_references": [
                    {
                        "file_ref": str(value.get("sha256") or "")[:12],
                        "filename": value.get("filename"),
                        "content_type": value.get("content_type")
                        or value.get("mime"),
                        "reason": value.get("reason"),
                        "error": value.get("error"),
                        "technical_reason": _attachment_limit_reason(value),
                    }
                    for value in incomplete[:10]
                ],
            }
        )
    return signals


def attested_locally(history: dict[str, object], *, authenticated: bool) -> bool:
    """Ce domaine, authentifié, a-t-il déjà été livré ici ?

    Ce n'est pas une preuve d'identité : un domaine authentique peut se faire
    passer pour un autre. C'est un fait qui retire à la graphie seule le droit
    d'accuser - nintendo-europe.com, aligné DMARC et livré deux fois, s'est vu
    reprocher le 3 septembre 2026 d'« ajouter un mot » à nintendo.com.
    """
    if not authenticated:
        return False
    # Une messagerie publique (outlook.com, gmail.com...) réunit des inconnus :
    # une livraison d'un de ses comptes n'atteste rien d'un autre. Le 3 novembre
    # 2026, une adresse outlook.com jamais vue a ainsi emprunté Amazon sans
    # charge (M-fc7f44). Un historique sans compte par adresse n'atteste pas.
    crowd = history.get("sender_apex_crowd")
    if crowd is None:
        crowd = crowd_mailbox_domain(str(history.get("sender_apex") or ""))
    if crowd:
        return int(history.get("sender_delivered_count") or 0) >= 1
    return int(history.get("apex_delivered_count") or 0) >= 1


def _history_clue_codes(
    history: dict[str, object], nature: dict[str, object] | None
) -> set[str]:
    """Les codes d'indice que l'historique produira, avant qu'il ne les produise.

    Les indices d'historique naissent après les enquêteurs profonds et ne sont
    écrits en base qu'à la fin : un enquêteur qui relit les indices en base ne
    les voit donc jamais. Le contrôle d'identité, censé se taire devant un
    expéditeur explicitement autorisé, vérifiait celui-ci comme un inconnu -
    c'est ce qui a retenu un envoi autorisé le 3 septembre 2026.
    """
    signals, _ = _history_signals(history, nature)
    codes: set[str] = set()
    for signal in signals:
        rule = _SIGNAL_RULES.get(str(signal.get("article_code") or ""))
        if rule:
            codes.add(rule[0])
    return codes


def _history_signals(
    history: dict[str, object], nature: dict[str, object] | None
) -> tuple[list[dict[str, object]], int | None]:
    """Indices tirés de l'historique isolé du destinataire et de l'expéditeur."""
    signals: list[dict[str, object]] = []
    labels = history.get("ground_truth_labels") or {}
    legitimate = int(labels.get("legitimate", 0)) if isinstance(labels, dict) else 0
    adverse = sum(
        int(labels.get(name, 0))
        for name in ("spam", "suspect", "dangerous")
        if isinstance(labels, dict)
    )
    if legitimate >= 3 and adverse == 0:
        signals.append(
            {"article_code": "HIST-001", "kind": "confirmed_sender", "count": legitimate}
        )
    profile_memory = history.get("mail_profile_history") or {}
    profile_labels = profile_memory.get("labels") or {}
    profile_legitimate = int(profile_labels.get("legitimate", 0))
    profile_adverse = sum(
        int(profile_labels.get(name, 0))
        for name in ("spam", "suspect", "dangerous", "undetermined")
    )
    if (
        profile_legitimate >= 2 and profile_adverse == 0
        and not adverse and legitimate < 3
    ):
        signals.append({
            "article_code": "HIST-006", "kind": "confirmed_mail_profile",
            "count": profile_legitimate, "profile": profile_memory.get("profile"),
        })
    if (
        isinstance(nature, dict)
        and nature.get("sending_mode") == "bulk"
        and int(history.get("previous_message_count") or 0) == 0
        and legitimate == 0
    ):
        signals.append(
            {
                "article_code": "NATURE-002",
                "kind": "unsolicited_bulk",
                "sender_address": history.get("sender_address"),
                "sender_apex": history.get("sender_apex"),
                "unsubscribe_offered": bool(nature.get("unsubscribe_offered")),
                "claim_registers": list(nature.get("claim_registers") or []),
            }
        )
    if int(history.get("previous_message_count") or 0) == 0:
        signals.append({"article_code": "HIST-002", "kind": "first_seen"})
        if history.get("apex_established_locally"):
            signals.append(
                {
                    "article_code": "HIST-004",
                    "kind": "apex_established_locally",
                    "apex": history.get("sender_apex"),
                    "delivered_count": history.get("apex_delivered_count"),
                    "apex_track_record_age_days": history.get(
                        "apex_track_record_age_days"
                    ),
                }
            )
    current_language = (nature or {}).get("language")
    recipient_language_total = int(history.get("recipient_language_total") or 0)
    recipient_language_dominance = float(
        history.get("recipient_language_dominance") or 0
    )
    if (
        current_language
        and current_language == history.get("recipient_dominant_language")
        and recipient_language_total >= 10
        and recipient_language_dominance >= 0.7
    ):
        signals.append(
            {
                "article_code": "HIST-005",
                "kind": "recipient_usual_language",
                "language": current_language,
                "recipient_language_total": recipient_language_total,
                "recipient_language_dominance": recipient_language_dominance,
            }
        )
    if history.get("persistent_allow"):
        signals.append(
            {"article_code": "POLICY-002", "kind": "authenticated_sender_allow"}
        )
    domain_age = history.get("sender_domain_age_days")
    if isinstance(domain_age, int) and domain_age < 90:
        signals.append(
            {
                "article_code": "DOMAIN-001",
                "kind": "recent_sender_domain",
                "age_days": domain_age,
                "creation_date": history.get("sender_domain_creation_date"),
            }
        )
    elif isinstance(domain_age, int) and domain_age >= 730:
        signals.append(
            {
                "article_code": "DOMAIN-002",
                "kind": "established_sender_domain",
                "age_days": domain_age,
                "creation_date": history.get("sender_domain_creation_date"),
            }
        )
    elif not history.get("sender_domain_enriched"):
        signals.append(
            {
                "article_code": "DOMAIN-003",
                "kind": "sender_domain_age_unavailable",
                "sender_domain": history.get("sender_domain"),
            }
        )
    zscore = history.get("size_zscore")
    mean_size = history.get("mean_size_bytes")
    current_size = history.get("current_size_bytes")
    # Une habitude se lit sur des jours, pas sur des messages : douze envois
    # en quatre jours, dont cinq dans la même minute, ne font pas d'horaire
    # habituel (M-e36c20, 15 octobre 2026, 11 h 33 pris pour un écart).
    habit = (
        int(history.get("previous_message_count") or 0) >= 10
        and int(history.get("previous_active_days") or 0) >= 10
    )
    usual_hours_utc = history.get("usual_hours_utc") or []
    # Le z-score de taille s'emballe quand les tailles passées se ressemblent
    # trop : une newsletter 1,26x plus lourde que d'habitude donnait un écart
    # de 8,8 (M-a5b072, FlightAware). On n'y voit une anomalie que sur un
    # historique fourni ET un écart franc en valeur, hors fourchette moitié /
    # double. Un vrai saut (pièce jointe inhabituelle, x10) tire encore.
    unusual_size = bool(
        isinstance(zscore, (float, int))
        and abs(zscore) >= 3
        and habit
        and isinstance(mean_size, (float, int))
        and mean_size > 0
        and isinstance(current_size, (float, int))
        and not (0.5 * mean_size <= current_size <= 2 * mean_size)
    )
    unusual_hour = (
        habit
        and len(usual_hours_utc) <= 8
        and not history.get("hour_previously_seen")
    )
    unusual_country = bool(
        habit and history.get("unfamiliar_transport_countries")
    )
    if unusual_size or unusual_hour or unusual_country:
        signals.append({"article_code": "HIST-003", "kind": "behavior_deviation"})
    return signals, domain_age if isinstance(domain_age, int) else None


def _correlation_signals(
    *,
    authenticated: bool,
    domain_age: int | None,
    content_context: dict[str, object] | None,
    headers_facts: dict[str, object] | None,
) -> list[dict[str, object]]:
    """Preuves qui n'existent que par la réunion de plusieurs faits."""
    signals: list[dict[str, object]] = []
    transactional_purpose = str((content_context or {}).get("purpose") or "") in {
        "one_time_authentication",
        "account_security",
        "parcel_delivery",
        "payment",
    }
    if transactional_purpose and authenticated and domain_age is not None and domain_age >= 730:
        signals.append(
            {
                "article_code": "CORR-012",
                "kind": "transactional_coherence",
                "purpose": (content_context or {}).get("purpose"),
                "domain_age_days": domain_age,
            }
        )
    if bool((headers_facts or {}).get("rfc8058_structure_aligned")) and authenticated:
        signals.append(
            {
                "article_code": "CORR-013",
                "kind": "authenticated_rfc8058_unsubscribe",
                "unsubscribe_apex": (headers_facts or {}).get("unsubscribe_apex"),
            }
        )
    return signals


def _signals(
    urls: list[dict[str, object]],
    attachments: list[dict[str, object]],
    history: dict[str, object],
    complete: bool,
    *,
    authenticated: bool = False,
    nature: dict[str, object] | None = None,
    sender_apex: str = "",
    domain_ages: dict[str, int] | None = None,
    organisations: dict[str, set[str]] | None = None,
    content_context: dict[str, object] | None = None,
    headers_facts: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    signals: list[dict[str, object]] = []
    domain_ages = domain_ages or {}
    # Un groupe fait transiter ses liens par ses propres domaines : vu du seul
    # apex, cela ne se distingue pas d'une redirection vers un tiers. Le
    # titulaire RDAP tranche, quand le registre accepte de le dire.
    intra_group = same_organisation_destinations(
        urls, sender_apex=sender_apex, organisations=organisations or {}
    )
    if intra_group:
        signals.append(
            {
                "article_code": "DEEP-015",
                "destination_apexes": intra_group,
                "sender_apex": sender_apex,
            }
        )
    direct_apexes = {
        str(value.get("initial_apex") or "")
        for value in urls
        if value.get("initial_apex")
    }
    verified_display = [
        value
        for value in urls
        if value.get("displayed_apex")
        and value.get("final_apex")
        and value.get("displayed_apex") == value.get("final_apex")
    ]
    verified_deception = [
        value
        for value in urls
        if value.get("displayed_apex")
        and value.get("final_apex")
        and value.get("displayed_apex") != value.get("final_apex")
    ]
    if verified_display:
        signals.append(
            {
                "article_code": "DEEP-009",
                "kind": "displayed_domain_final_convergence",
                "occurrences": len(verified_display),
                "apexes": sorted(
                    {
                        str(value.get("final_apex") or "")
                        for value in verified_display
                    }
                ),
            }
        )
    if verified_deception:
        signals.append(
            {
                "article_code": "DEEP-011" if authenticated else "DEEP-010",
                "kind": (
                    "authenticated_displayed_domain_final_mismatch"
                    if authenticated
                    else "displayed_domain_final_mismatch"
                ),
                "occurrences": len(verified_deception),
                "pairs": sorted(
                    {
                        (
                            str(value.get("displayed_apex") or ""),
                            str(value.get("final_apex") or ""),
                        )
                        for value in verified_deception
                    }
                ),
            }
        )
    # Le service conditionnel se juge avant la redirection : il établit une
    # dissimulation, là où une redirection ne fait que la rendre possible.
    signals.extend(_cloaking_signals(urls))
    signals.extend(_verification_gate_signals(urls, sender_apex=sender_apex))
    signals.extend(_opaque_landing_signals(urls, sender_apex=sender_apex))
    cross_apex = [value for value in urls if value.get("cross_apex_redirect")]
    if cross_apex:
        pairs = sorted(
            {
                (
                    str(value.get("initial_apex") or ""),
                    str(value.get("final_apex") or ""),
                )
                for value in cross_apex
            }
        )
        finals_are_directly_observed = all(
            str(value.get("final_apex") or "") in direct_apexes
            for value in cross_apex
        )
        if authenticated and finals_are_directly_observed:
            signals.append(
                {
                    "article_code": "DEEP-006",
                    "kind": "authenticated_tracking_convergence",
                    "occurrences": len(cross_apex),
                    "pairs": pairs,
                }
            )
        elif not authenticated:
            signals.append(
                {
                    "article_code": "DEEP-008",
                    "kind": "unauthenticated_cross_apex_redirect",
                    "occurrences": len(cross_apex),
                    "pairs": pairs,
                }
            )
        else:
            signals.append(
                {
                    "article_code": "DEEP-001",
                    "kind": "cross_apex_redirect",
                    "occurrences": len(cross_apex),
                    "pairs": pairs,
                }
            )

    # Une destination actionnable, hors de l'apex de l'expéditeur, vers un
    # domaine fraîchement enregistré : le motif du phishing par abus d'ESP, où
    # un domaine établi et aligné DMARC renvoie vers un site créé la veille.
    # On tranche MÊME sous authentification - l'auth couvre l'émetteur, pas la
    # destination. Le discriminant contre les faux positifs (newsletters
    # authentifiées à redirection) est l'âge : elles pointent vers l'établi.
    fresh_destinations = sorted(
        {
            apex
            for value in urls
            if value.get("role") != "render_resource"
            and (apex := str(value.get("final_apex") or ""))
            and sender_apex
            and apex != sender_apex
            and isinstance(domain_ages.get(apex), int)
            and domain_ages[apex] < FRESH_DESTINATION_DAYS
        }
    )
    if fresh_destinations:
        signals.append(
            {
                "article_code": "DOMAIN-004",
                "kind": "recent_cross_apex_destination",
                "apexes": fresh_destinations,
                "age_days": min(domain_ages[apex] for apex in fresh_destinations),
                "sender_apex": sender_apex,
                "authenticated": authenticated,
            }
        )

    forms = [value for value in urls if value.get("forms")]
    sensitive_forms = [
        (value, categories)
        for value in forms
        if (categories := _sensitive_form_categories(value))
    ]
    deceptive_sensitive_forms = [
        (value, categories)
        for value, categories in sensitive_forms
        if not authenticated
        and bool(
            value.get("cross_apex_redirect")
            or (
                value.get("displayed_apex")
                and value.get("final_apex")
                and value.get("displayed_apex") != value.get("final_apex")
            )
        )
    ]
    if deceptive_sensitive_forms:
        signals.append(
            {
                "article_code": "DEEP-002",
                "kind": "contextually_deceptive_sensitive_url_forms",
                "occurrences": len(deceptive_sensitive_forms),
                "sensitive_categories": sorted(
                    {
                        category
                        for _, categories in deceptive_sensitive_forms
                        for category in categories
                    }
                ),
                "final_apexes": sorted(
                    {
                        str(value.get("final_apex") or "")
                        for value, _ in deceptive_sensitive_forms
                        if value.get("final_apex")
                    }
                ),
                "context": "unauthenticated_and_redirect_or_display_mismatch",
            }
        )
    elif sensitive_forms:
        signals.append(
            {
                "article_code": "DEEP-014",
                "kind": "ambient_sensitive_form_without_deceptive_context",
                "occurrences": len(sensitive_forms),
                "sensitive_categories": sorted(
                    {
                        category
                        for _, categories in sensitive_forms
                        for category in categories
                    }
                ),
                "final_apexes": sorted(
                    {
                        str(value.get("final_apex") or "")
                        for value, _ in sensitive_forms
                        if value.get("final_apex")
                    }
                ),
                "context": (
                    "authenticated_sender"
                    if authenticated
                    else "no_deceptive_link_correlation"
                ),
            }
        )
    elif forms:
        signals.append(
            {
                "article_code": "DEEP-007",
                "kind": "generic_url_forms",
                "occurrences": len(forms),
                "final_apexes": sorted(
                    {
                        str(value.get("final_apex") or "")
                        for value in forms
                        if value.get("final_apex")
                    }
                ),
            }
        )

    protected_action_urls = [
        value
        for value in urls
        if value.get("analysis_skipped")
        and value.get("skip_reason") == "protected_single_use_or_side_effect_url"
    ]
    if protected_action_urls:
        signals.append(
            {
                "article_code": "DEEP-013",
                "kind": "single_use_or_side_effect_url_not_visited",
                "occurrences": len(protected_action_urls),
                "roles": sorted(
                    {
                        str(value.get("role") or "unknown")
                        for value in protected_action_urls
                    }
                ),
            }
        )

    incomplete_urls = [
        value
        for value in urls
        if value.get("role") != "render_resource"
        and not value.get("navigation_limit_explained")
        and not _is_definitive_target_failure(value.get("error"))
        and (value.get("error") or value.get("analysis_incomplete"))
    ]
    if incomplete_urls:
        signals.append(
            {
                "article_code": "DEEP-003",
                "kind": "url_incomplete",
                "occurrences": len(incomplete_urls),
                "url_references": [
                    {
                        "url_ref": str(value.get("url_hash") or "")[:12],
                        "role": value.get("role"),
                        "initial_apex": value.get("initial_apex"),
                        "final_apex": value.get("final_apex"),
                        "visible_text": value.get("visible_text"),
                        "error": value.get("error") or "analysis_incomplete",
                        "technical_reason": _technical_limit_reason(
                            value.get("error") or "analysis_incomplete"
                        ),
                    }
                    for value in incomplete_urls[:10]
                ],
            }
        )

    explained_navigation_limits = [
        value for value in urls if value.get("navigation_limit_explained")
    ]
    if explained_navigation_limits:
        signals.append(
            {
                "article_code": "DEEP-012",
                "kind": "authenticated_stable_redirect_limit",
                "occurrences": len(explained_navigation_limits),
                "final_apexes": sorted(
                    {
                        str(value.get("final_apex") or "")
                        for value in explained_navigation_limits
                        if value.get("final_apex")
                    }
                ),
            }
        )

    # Ce que le bac à sable a réellement vu, constat par constat. L'ancien
    # signal unique disait « quelque chose de matériel » sans dire quoi : une
    # macro, une archive chiffrée et un PDF qui lance un programme y étaient
    # indiscernables, et tout ce qui passait sous le seuil disparaissait.
    signals.extend(_attachment_signals(attachments))
    history_clues, domain_age = _history_signals(history, nature)
    signals.extend(history_clues)
    signals.extend(
        _correlation_signals(
            authenticated=authenticated,
            domain_age=domain_age,
            content_context=content_context,
            headers_facts=headers_facts,
        )
    )
    if not complete:
        signals.append({"article_code": "POLICY-001", "kind": "incomplete_evidence"})
    return signals


async def _domain_ages(
    pool: asyncpg.Pool[Any], message_id: str
) -> dict[str, int]:
    """Âge RDAP par apex des domaines du message, quand il a été établi.

    On replie chaque domaine sur son apex : l'âge d'enregistrement est celui de
    l'apex, un sous-domaine (em7751.exemple.org) ne le change pas. On garde le
    plus petit âge observé par apex, par prudence.
    """
    rows = await pool.fetch(
        """
        SELECT e.value_normalized AS domain, en.data,
               m.captured_at
        FROM entities e JOIN enrichments en ON en.id=e.enrichment_id
        JOIN messages m ON m.id=e.message_id
        WHERE e.message_id=$1::uuid AND e.entity_type='domain'
          AND en.status='ok'
          AND (en.data ? 'age_days' OR en.data ? 'creation_date')
        """,
        message_id,
    )
    ages: dict[str, int] = {}
    for row in rows:
        apex = _apex(str(row["domain"] or ""))
        age = domain_age(_json_object(row["data"]), row["captured_at"])
        if not apex or age is None:
            continue
        ages[apex] = min(age, ages.get(apex, age))
    return ages


async def _domain_organisations(
    pool: asyncpg.Pool[Any], message_id: str
) -> dict[str, set[str]]:
    """Titulaire RDAP par apex, tel que le registre a bien voulu le dire.

    La donnée est déjà collectée par l'enrichissement : on la relit, sans
    aucun appel réseau supplémentaire.
    """
    rows = await pool.fetch(
        """
        SELECT e.value_normalized AS domain,
               en.data->'rdap'->'raw' AS rdap,
               en.data->'dns'->'ns' AS ns
        FROM entities e JOIN enrichments en ON en.id=e.enrichment_id
        WHERE e.message_id=$1::uuid AND e.entity_type='domain'
          AND en.status='ok'
          AND (en.data->'rdap' ? 'raw' OR en.data->'dns' ? 'ns')
        """,
        message_id,
    )
    organisations: dict[str, set[str]] = {}
    for row in rows:
        apex = _apex(str(row["domain"] or ""))
        if not apex:
            continue
        signature = organisations.setdefault(apex, set())
        raw = row["rdap"]
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                raw = None
        if raw is not None:
            signature.update(organisation_signature(raw))
        # La délégation DNS atteste ce que le RDAP masqué et les certificats
        # de validation de domaine ne disent plus : pour déléguer un domaine
        # à ses propres serveurs, il faut le contrôler.
        ns = row["ns"] if "ns" in row.keys() else None
        if isinstance(ns, str):
            try:
                ns = json.loads(ns)
            except ValueError:
                ns = None
        signature.update(nameserver_signature(ns))
    return organisations


async def _sender_site(
    client: httpx.AsyncClient,
    settings: Settings,
    sender_apex: str,
    registers: set[str],
) -> dict[str, str] | None:
    """Ce que l'expéditeur publie sur sa page d'accueil, quand la question se pose.

    Les enquêteurs d'identité et d'activité partagent cette lecture. Un refus
    ou une page interstitielle reste une absence de fait, sans seconde visite.
    """
    if not sender_apex or not registers:
        return None
    value, _, error = await _fetch_url_analysis(
        client, settings, f"https://{sender_apex}/", "sender-site"
    )
    if error is not None:
        return None
    texte = str(value.get("body_excerpt") or "")[:4000]
    # Un hébergeur qui refuse l'entrée répond à la place de l'expéditeur. Sa
    # page ne dit rien du métier de celui-ci : la retenir reviendrait à lui
    # reprocher un contenu qu'il n'a pas écrit - c'est ce qui a fait retenir
    # une alerte de connexion OpenAI le 21 août, comparée à « Enable
    # JavaScript and cookies to continue ». Aucun site lu vaut mieux qu'un
    # site qui n'est pas le sien.
    if is_interstitial(texte):
        return None
    return {
        "apex": str(value.get("final_apex") or sender_apex),
        "text": texte,
    }


# Marqueur du constat « domaine officiel avec un mot en plus », posé sans
# modèle. Lu par le moteur de verdict pour ne condamner que sur un fait.
MECHANICAL_APPENDED = "domaine_officiel_avec_mot_en_plus"


async def _identity_relation(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    *,
    display_name: str,
    from_apex: str,
    organisations: dict[str, set[str]] | None = None,
    attested_locally: bool = False,
    from_domain: str = "",
) -> tuple[dict[str, object] | None, dict[str, object]]:
    """Cherche qui est ce nom, qui est ce domaine, puis fait juger le rapport.

    Quatre garde-fous tiennent l'ensemble. Le premier : quand la recherche
    attribue le domaine émetteur à l'organisation cherchée, la question est
    close sans appeler personne - filiale, domaine régional, prestataire.
    Le deuxième : un fait de propriété déjà en base - délégation NS, titulaire
    RDAP, signataire DKIM - qui rattache l'émetteur à un apex officiel la
    clôt de même ; la graphie seule accusait e-ca-paris.fr le 3 septembre
    2026 alors que ses serveurs de noms étaient ceux du Crédit Agricole.
    Le troisième : une panne, un quota ou une réponse hors format ne produit
    aucun indice. Le quatrième : le modèle ne voit que deux noms et ce qu'une
    recherche publique en dit ; rien du message ne sort d'ici.
    """
    from sentimail_v3.code.identity_relation import (
        RELATION_PROMPT,
        appended_to_official,
        owned_by_official,
        relation_clue,
        relation_question,
    )
    from sentimail_v3.code.organisation_lookup import belongs
    from sentimail_v3.observation.organisation_search import (
        SearchUnavailable,
        about_domain,
        about_name,
    )

    try:
        sur_le_nom, apexes = await about_name(pool, client, settings, display_name)
    except SearchUnavailable as exc:
        # Le moteur n'a pas répondu : la question n'a pas de matière, elle ne
        # se pose pas au modèle, et le fait est écrit pour que l'enquêteur
        # note « non vérifié » plutôt qu'un vide.
        _log("deep.identity_relation_search_unavailable", kind=exc.kind, detail=exc.detail)
        return None, {"searched": False, "error": True, "search_unavailable": exc.kind}
    if apexes and belongs(from_apex, apexes):
        _log(
            "deep.identity_relation_cleared",
            display_name=display_name[:60],
            from_apex=from_apex,
        )
        return None, {
            "searched": True,
            "cleared": True,
            "official_apexes": apexes,
        }
    proprietaire = owned_by_official(from_apex, apexes, organisations or {})
    if proprietaire:
        _log(
            "deep.identity_relation_owned",
            from_apex=from_apex,
            officiel=proprietaire,
        )
        return None, {
            "searched": True,
            "cleared": True,
            "owned_via": proprietaire,
            "official_apexes": apexes,
        }
    imite = appended_to_official(from_apex, apexes, from_domain=from_domain)
    if imite:
        # Le domaine porte le nom d'un domaine officiel avec un mot en plus.
        # Le constat se lit sans avis, et le soumettre au modèle risquait ce
        # qu'il a fait : y voir un domaine de service de l'enseigne.
        _log("deep.identity_relation_appended", from_apex=from_apex, officiel=imite)
        return (
            _sans_charge_si_atteste(
            {
                "clue_code": "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
                "article_code": "DEEP-022",
                "direction": "adverse",
                "strength": 65,
                "confidence": 0.9,
                "statement": (
                    f"Le message se présente au nom de {display_name.strip()[:80]}, "
                    f"depuis un domaine qui reprend celui de {imite} en y ajoutant "
                    "un mot. Un domaine officiel ne s'écrit pas ainsi."
                ),
                "facts": {
                    "from_apex": from_apex,
                    "from_domain": from_domain or from_apex,
                    "claimed_organisation": display_name.strip()[:80],
                    # Pas d'explication à part : l'énoncé dit déjà tout, et
                    # l'avis la répétait après la phrase qui nomme les domaines.
                    "official_apexes": apexes[:3],
                    # Le constat est mécanique : c'est lui, et non la lecture
                    # du modèle, qui peut fonder un classement sans question.
                    "constat": MECHANICAL_APPENDED,
                    "verified_by": "search",
                },
            },
                attested_locally,
            ),
            {"searched": True, "appended_to": imite, "official_apexes": apexes},
        )
    try:
        sur_le_domaine = await about_domain(pool, client, settings, from_apex)
    except SearchUnavailable as exc:
        # Le nom sortait de la mémoire, le domaine devait partir dehors : sans
        # lui, le modèle comparerait un nom à une chaîne de caractères.
        _log("deep.identity_relation_search_unavailable", kind=exc.kind, detail=exc.detail)
        return None, {
            "searched": False,
            "error": True,
            "search_unavailable": exc.kind,
            "official_apexes": apexes,
        }
    try:
        content, _ = await provider_chat_json(
            pool,
            client,
            settings,
            messages=[
                {"role": "system", "content": RELATION_PROMPT},
                {
                    "role": "user",
                    "content": relation_question(
                        display_name=display_name,
                        from_apex=from_apex,
                        sur_le_nom=sur_le_nom,
                        sur_le_domaine=sur_le_domaine,
                        official_apexes=apexes,
                    ),
                },
            ],
            max_tokens=300,
            role="identity_claim",
        )
    except Exception as exc:  # noqa: BLE001 - une question sans réponse n'accuse pas
        _log("deep.identity_relation_error", error=type(exc).__name__)
        return None, {"searched": bool(sur_le_nom or sur_le_domaine), "error": True}
    start, end = content.find("{"), content.rfind("}")
    try:
        parsed = json.loads(content[start : end + 1])
    except (ValueError, TypeError):
        return None, {"searched": True, "unparsed": True}
    clue = relation_clue(
        parsed,
        display_name=display_name,
        from_apex=from_apex,
        official_apexes=apexes,
        searched=bool(sur_le_nom and sur_le_domaine),
        from_domain=from_domain,
    )
    if clue is not None:
        clue = _sans_charge_si_atteste(clue, attested_locally)
    return clue, {
        "searched": True,
        "results_on_name": len(sur_le_nom),
        "results_on_domain": len(sur_le_domaine),
        "official_apexes": apexes,
        # Ce que le modèle a lu du rapport : vrai, faux ou indécis. Sans ce
        # fait, une organisation trouvée au rapport non tranché passait pour
        # un vide chez l'enquêteur sender_relation.
        "rapport": parsed.get("rapport"),
    }


def _sans_charge_si_atteste(
    clue: dict[str, object], attested_locally: bool
) -> dict[str, object]:
    """Le constat reste écrit ; s'il vise un domaine authentifié déjà livré, il
    cesse de charger.

    L'indice garde son article et son code : il est jugé et appris comme les
    autres. Seule sa direction change, parce qu'un fait - ce domaine a
    authentifié des messages qu'on a livrés - vaut plus que la ressemblance
    de deux noms. Un inconnu qui accole une marque reste accusé à pleine
    force.
    """
    if not attested_locally:
        return clue
    facts = dict(clue.get("facts") or {})
    facts["attested_locally"] = True
    return {
        **clue,
        "direction": "neutral",
        "strength": 0,
        "statement": (
            str(clue.get("statement") or "")
            + " Cet expéditeur est toutefois authentifié et t’a déjà écrit : "
            "je le note sans l’accuser."
        ),
        "facts": facts,
    }


def _sans_charge_si_cite(clue: dict[str, object]) -> dict[str, object]:
    """La marque n'est écrite que dans le texte transféré d'une messagerie
    publique : le constat reste écrit pour le juge, il cesse de charger et ne
    fonde aucun faisceau."""
    if clue.get("direction") != "adverse":
        return clue
    facts = dict(clue.get("facts") or {})
    facts["uncharged"] = "cited_only"
    return {
        **clue,
        "direction": "neutral",
        "strength": 0,
        "statement": (
            str(clue.get("statement") or "")
            + " La marque n’apparaît que dans le texte transféré depuis une "
            "messagerie publique : je le note sans l’accuser."
        ),
        "facts": facts,
    }


def _display_name(from_header: str) -> str:
    """La partie lisible d'un en-tête « De », sans son adresse."""
    nom, _ = parseaddr(from_header)
    return sans_bruit(nom.strip())


def _from_domain_of(parsed: Any) -> str:
    """Le domaine complet de l'adresse affichée, sous-domaines compris.

    L'apex dit qui possède ; le domaine complet dit ce qu'on a voulu faire
    lire. « cic-notification.sju.somesepta.best » porte le nom volé dans un
    sous-domaine que l'apex « somesepta.best » ne montre pas.
    """
    _, adresse = parseaddr(str(parsed.message.get("from_header") or ""))
    return adresse.rsplit("@", 1)[-1].strip().casefold() if "@" in adresse else ""


def _from_address_of(parsed: Any) -> str:
    """L'adresse affichée, telle qu'elle est écrite."""
    _, adresse = parseaddr(str(parsed.message.get("from_header") or ""))
    return adresse.strip() if "@" in adresse else ""


def _subject_of(parsed: Any) -> str:
    """L'objet que le destinataire lit, sans les signes glissés dans les mots.

    « Carte A′̍meli » ne désigne personne pour un lecteur d'organisation ; le
    même objet nettoyé désigne l'Assurance Maladie (M-96852d, 30 octobre 2026).
    """
    return sans_bruit(str(parsed.message.get("subject") or ""))


def _readable_body(parsed: Any) -> str:
    """Le corps que le destinataire lit : le texte brut, sinon le texte visible
    du HTML. Même point de départ que le hook contenu et que le dossier du
    juge : trois lecteurs, un seul texte."""
    return readable_text(
        parsed.message.get("body_text"), parsed.message.get("body_html")
    )[0]


def _display_name_of(parsed: Any) -> str:
    """Le nom que le destinataire lit, pris là où le parseur le range.

    L'analyse profonde le cherchait sous « from », clé que le parseur n'écrit
    pas : le nom était donc toujours vide, et les deux contrôles qui reposent
    sur lui - l'identité revendiquée, la cohérence d'activité - jugeaient l'un
    sans jamais poser sa question, l'autre sans le nom qu'il croyait voir.
    Le passage par cette fonction est ce qui rend l'accord testable.
    """
    return _display_name(str(parsed.message.get("from_header") or ""))


async def _claimed_organisation(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    *,
    display_name: str,
    subject: str,
    body: str,
) -> tuple[str, dict[str, object]]:
    """Au nom de qui ce message se présente-t-il ? Lu, jamais deviné.

    Le nom affiché ne suffit plus : le 16 septembre 2026, « Annuel-Famille »
    ne désignait personne et « Prime Famille » était écrit dans le corps. Le
    modèle lit les trois - nom, objet, texte visible - et recopie le nom tel
    qu'il est écrit ; l'appelant vérifie ensuite que le message l'écrit bien.
    Une panne rend une chaîne vide et se note : elle n'accuse personne.
    """
    from sentimail_v3.code.identity_relation import (
        CLAIM_PROMPT,
        claim_question,
        parse_claim,
    )

    try:
        content, _ = await provider_chat_json(
            pool,
            client,
            settings,
            messages=[
                {"role": "system", "content": CLAIM_PROMPT},
                {
                    "role": "user",
                    "content": claim_question(
                        display_name=display_name, subject=subject, text=body
                    ),
                },
            ],
            max_tokens=200,
            role="sender_relation",
        )
    except Exception as exc:  # noqa: BLE001 - une lecture manquée n'accuse pas
        _log("deep.claim_error", error=type(exc).__name__)
        return "", {"asked": True, "error": type(exc).__name__}
    organisation = parse_claim(content)
    return organisation, {"asked": True, "read": organisation}


async def _activity_coherence(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    site: dict[str, str] | None,
    subject: str,
    body: str,
    clue_codes: set[str],
    display_name: str = "",
    message_purpose: str = "",
    *,
    always: bool = False,
) -> dict[str, object] | None:
    """Demande à un modèle si ce message peut émaner de cet expéditeur.

    L'appel est isolé et court : une question, une réponse binaire motivée. Il
    est aussi fail-soft - une panne du modèle ne produit aucun indice, et
    surtout aucune accusation par défaut.

    `always` retire les dispenses de `should_ask` : l'enquêteur
    `sender_relation` a déjà décidé que le métier lu est exploitable, et il
    regarde aussi les expéditeurs connus.
    """
    headline = str((site or {}).get("text") or "")[:600]
    if not always and not should_ask(
        headline,
        clue_codes,
        message_purpose=message_purpose,
    ):
        return None
    try:
        content, _ = await provider_chat_json(
            pool,
            client,
            settings,
            messages=[
                {"role": "system", "content": COHERENCE_PROMPT},
                {
                    "role": "user",
                    "content": coherence_question(
                        site_headline=headline,
                        display_name=display_name,
                        subject=subject,
                        body=body,
                        message_purpose=message_purpose,
                    ),
                },
            ],
            max_tokens=300,
            role="activity_coherence",
        )
    except Exception as exc:  # noqa: BLE001 - une question sans réponse n'accuse pas
        _log("deep.coherence_error", error=type(exc).__name__)
        return None
    start, end = content.find("{"), content.rfind("}")
    try:
        parsed = json.loads(content[start : end + 1])
    except (ValueError, TypeError):
        return None
    return coherence_clue(
        parsed,
        sender_apex=str((site or {}).get("apex") or ""),
        display_name=display_name,
        published_activity=headline,
        message_subject=subject,
    )


async def analyze_message(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    message_id: str,
) -> dict[str, object]:
    deadline = monotonic() + max(0.001, float(getattr(settings, "deep_analysis_deadline_seconds", 240)))
    cache_key = await observation_fingerprint(pool, message_id, settings)
    stored = await pool.fetchval(
        "SELECT raw_eml FROM messages WHERE id=$1::uuid", message_id
    )
    raw = reveal(stored, load_key(settings.raw_eml_key_file))
    if not isinstance(raw, bytes):
        raise TypeError("raw message unavailable")
    urls, urls_complete, url_coverage = await _analyze_urls(
        pool, client, settings, message_id, raw, deadline=deadline
    )
    attachments, attachments_complete = await _analyze_attachments(
        pool, client, settings, message_id, raw, deadline=deadline
    )
    history = await _history(pool, message_id)
    # Une panne ou une absence RDAP/WHOIS retire une information de contexte,
    # mais ne rend pas l'inspection matérielle du message incomplète.
    complete = urls_complete and attachments_complete
    authenticated = await _message_is_dmarc_aligned(pool, message_id)
    nature = await _nature_facts(pool, message_id)
    content_context = await _content_context(pool, message_id)
    headers_facts = await _headers_facts(pool, message_id)
    sender_apex = _apex(str(history.get("sender_domain") or ""))
    domain_ages = await _domain_ages(pool, message_id)
    organisations = await _domain_organisations(pool, message_id)
    parsed = parse_message(raw)
    try:
        stored_facts = _json_object(await pool.fetchval("SELECT facts FROM messages WHERE id=$1::uuid", message_id))
    except (TypeError, ValueError):
        stored_facts = {}
    visible = stored_facts.get("visible_content")
    body = (visible["text"] if isinstance(visible, dict)
            and visible.get("version") == VISIBLE_CONTENT_VERSION
            and isinstance(visible.get("text"), str) and not visible.get("truncated")
            else _readable_body(parsed))
    corps = _body_with_attachments(body, attachments)
    registers = activity_registers(
        str(parsed.message.get("subject") or ""),
        corps[:8000],
    )
    # La cohérence de l'identité a besoin de la page même sans registre
    # d'activité. Un résultat absent est partagé aussi, jamais redemandé.
    site_partage = await load_observation(pool, message_id, "sender_site", cache_key) if cache_key else None
    if site_partage is None:
        try:
            async with asyncio.timeout(max(0.001, min(45, deadline - monotonic()))):
                site_partage = await _sender_site(client, settings, sender_apex, registers or {"coherence"})
        except TimeoutError:
            site_partage = None
        if cache_key and site_partage is not None:
            await save_observation(pool, message_id, "sender_site", cache_key, site_partage)
    # Les enquêteurs qui ont besoin du monde extérieur passent par leur
    # registre : chacun est exécuté, chacun rend compte, et le superviseur peut
    # constater qu'ils ont bien tourné. Enterré dans cette fonction, un tel
    # contrôle disparaissait en silence dès qu'un chemin le contournait.
    contexte = SimpleNamespace(
        pool=pool,
        client=client,
        settings=settings,
        message_id=message_id,
        observation_fingerprint=cache_key,
        analysis_deadline=deadline,
        clue_codes={
            str(row["clue_code"])
            for row in await pool.fetch(
                """
                SELECT DISTINCT c.clue_code FROM clues c
                JOIN investigations i ON i.id=c.investigation_id
                WHERE i.message_id=$1::uuid
                """,
                message_id,
            )
        }
        # Les indices d'historique n'existent pas encore en base à cet
        # instant : sans eux, un expéditeur explicitement autorisé est
        # vérifié comme un inconnu.
        | _history_clue_codes(history, nature),
        sender_apex=sender_apex,
        # Ce que la délégation DNS, le RDAP et DKIM attestent de chaque
        # domaine du message : un fait de propriété, là où la graphie seule
        # accuse.
        organisations=organisations,
        subject=_subject_of(parsed),
        # Le texte que le destinataire lit, d'où qu'il vienne : sur un mail
        # HTML seul, body_text est vide et les enquêteurs lisaient le vide.
        body=corps,
        # Le nom que le destinataire lit. C'est lui qui porte l'identité
        # revendiquée, et le domaine qui dit qui a réellement envoyé : les
        # comparer est le seul moyen de voir un message se présenter sous une
        # identité qui n'est pas la sienne.
        display_name=_display_name_of(parsed),
        from_domain=_from_domain_of(parsed),
        # L'adresse entière, pour reconnaître un nom de personne qu'elle
        # écrit (« sophia.wong@ ») : une personne ne se cherche pas comme une
        # organisation.
        from_address=_from_address_of(parsed),
        sender_site=site_partage,
        message_purpose=str(content_context.get("purpose") or ""),
        # Authentifié et déjà livré : un constat de graphie ne charge plus.
        sender_attested=attested_locally(history, authenticated=authenticated),
        # Le destinataire, pour que son nom ne parte jamais vers la recherche
        # comme s'il était une organisation.
        recipient=str(history.get("participant_email") or ""),
        url_analyses=urls,
    )
    deep_hook_results = await run_deep_hooks(list(DEEP_HOOKS), contexte)
    complete = complete and not any(r.error_type == "TimeoutError" for r in deep_hook_results)
    deep_hook_clues = [
        clue for result in deep_hook_results for clue in result.clues
    ]
    signals = _signals(
        urls,
        attachments,
        history,
        complete,
        authenticated=authenticated,
        nature=nature,
        sender_apex=sender_apex,
        domain_ages=domain_ages,
        organisations=organisations,
        content_context=content_context,
        headers_facts=headers_facts,
    )
    signals.extend(deep_hook_clues)
    # Le texte lu dans les images et les fichiers passe par les motifs du
    # contrôle de contenu, qui ne lit que le corps visible : un faux reçu tenu
    # dans une image (M-fc7f44, 3 novembre 2026) ne laissait aucun indice.
    try:
        signals.extend(
            await attachment_text_signals(
                attachments,
                visible_body_chars=len(str(body or "").strip()),
                already_observed=set(contexte.clue_codes),
            )
        )
    except Exception as exc:  # noqa: BLE001 - un constat absent, pas une chaîne arrêtée
        _log("deep.attachment_text_error", error=type(exc).__name__)
    # Récidive de campagne : le squelette du message reprend-il celui d'un
    # message déjà qualifié ? Le label de la campagne source informe le juge,
    # la ressemblance seule ne décide de rien.
    try:
        campaign = await match_campaign(pool, message_id)
    except Exception:  # noqa: BLE001 - mémoire consultative, fail-soft
        campaign = None
    if campaign is not None:
        adverse = str(campaign["label"]) in {"spam", "dangerous", "suspect"}
        signals.append(
            {
                "article_code": "CORR-011",
                "clue_code": "TPLT_KNOWN_CAMPAIGN",
                "direction": "adverse" if adverse else "favorable",
                "strength": 55 if adverse else 20,
                "confidence": float(campaign["jaccard"]),
                "statement": (
                    "Ce message reprend le gabarit d’une campagne déjà "
                    f"qualifiée « {campaign['label']} »"
                    + (" (même objet)" if campaign.get("same_subject") else "")
                    + f", ressemblance {campaign['jaccard']}."
                ),
            }
        )
    return {
        "complete": complete,
        # Le juge doit savoir de quel côté l'analyse a échoué : un lien qui
        # refuse le bac à sable et un fichier jamais ouvert n'ont pas le même
        # sens. Le second reste décisif même pour un expéditeur authentifié.
        "urls_complete": urls_complete,
        "attachments_complete": attachments_complete,
        "deep_hook_runs": [
            {
                "hook_name": r.hook_name,
                "hook_version": r.hook_version,
                "status": r.status,
                "duration_ms": r.duration_ms,
                "facts": r.facts,
                "error_type": r.error_type,
                "error_detail": r.error_detail,
                "cache_reused": getattr(r, "cache_reused", False),
            }
            for r in deep_hook_results
        ],
        "budgets": {
            "urls_base": BASE_URLS,
            "urls_hard_max": MAX_URLS,
            "urls_applied": url_coverage.get("adaptive_budget"),
            "attachments": MAX_ATTACHMENTS,
            "images": MAX_IMAGE_ATTACHMENTS,
            "attachment_bytes": MAX_ATTACHMENT_BYTES,
            "attachment_seconds": MAX_ATTACHMENTS_SECONDS,
        },
        "url_coverage": url_coverage,
        "url_analyses": urls,
        "attachment_analyses": attachments,
        "history": history,
        "sender_dmarc_aligned": authenticated,
        "signals": signals,
    }


_SIGNAL_RULES: dict[str, tuple[str, str, int, float, str]] = {
    "DEEP-015": (
        "URL_SAME_ORGANISATION_DESTINATION",
        "favorable",
        25,
        0.85,
        "La destination du lien appartient au même titulaire que le domaine expéditeur.",
    ),
    "DEEP-001": (
        "URL_SANDBOX_CROSS_APEX",
        "neutral",
        0,
        0.9,
        "Le sandbox observe une redirection inter-apex qui doit être expliquée.",
    ),
    "DEEP-002": (
        "URL_SANDBOX_FORM",
        "adverse",
        65,
        0.85,
        "Le contenu distant expose un formulaire demandant une donnée sensible.",
    ),
    "DEEP-003": (
        "URL_SANDBOX_INCOMPLETE",
        "neutral",
        0,
        1.0,
        "Limite technique : au moins une URL n’a pas pu être entièrement inspectée.",
    ),
    "DEEP-004": (
        "ATTACHMENT_SANDBOX_MATERIAL",
        "adverse",
        100,
        0.98,
        "Le sandbox fichier relève un contenu actif ou malveillant matériel.",
    ),
    "DEEP-005": (
        "ATTACHMENT_SANDBOX_INCOMPLETE",
        "neutral",
        0,
        1.0,
        "Limite technique : au moins une pièce jointe n’a pas pu être entièrement inspectée.",
    ),
    "DEEP-006": (
        "URL_AUTHENTICATED_TRACKING_CONVERGENCE",
        "favorable",
        25,
        0.9,
        "Les redirections d’un expéditeur authentifié convergent vers un apex aussi lié directement.",
    ),
    "DEEP-007": (
        "URL_GENERIC_FORM",
        "neutral",
        0,
        0.95,
        "La page distante contient un formulaire générique sans champ sensible détecté.",
    ),
    "DEEP-008": (
        "URL_UNAUTHENTICATED_CROSS_APEX",
        "adverse",
        35,
        0.75,
        "Un expéditeur non authentifié redirige vers un autre apex sans corrélation établie.",
    ),
    "DEEP-009": (
        "URL_DISPLAY_FINAL_CONVERGENCE",
        "favorable",
        25,
        0.95,
        "Le domaine affiché converge vers la destination finale après le lien de suivi.",
    ),
    "DEEP-010": (
        "URL_DISPLAY_FINAL_MISMATCH",
        "adverse",
        65,
        0.9,
        "Un expéditeur non authentifié présente un domaine différent de la destination finale vérifiée.",
    ),
    "DEEP-011": (
        "URL_AUTHENTICATED_DISPLAY_FINAL_MISMATCH",
        "neutral",
        0,
        0.95,
        "Un expéditeur authentifié présente un domaine différent de la destination finale ; le contexte doit l’expliquer.",
    ),
    "DEEP-012": (
        "URL_AUTHENTICATED_STABLE_REDIRECT_LIMIT",
        "neutral",
        0,
        0.95,
        "La limite de navigation est atteinte dans une chaîne HTTPS authentifiée qui boucle sur l’apex final.",
    ),
    "DEEP-013": (
        "URL_PROTECTED_ACTION_NOT_VISITED",
        "neutral",
        0,
        1.0,
        "Une URL à usage unique ou à effet de bord a été reconnue avant toute navigation et n’a pas été visitée.",
    ),
    "DEEP-014": (
        "URL_AMBIENT_SENSITIVE_FORM",
        "neutral",
        0,
        0.95,
        "Une page distante contient un formulaire sensible, mais le message ne présente pas de contexte trompeur corrélé permettant de l’imputer à sa demande.",
    ),
    "DEEP-024": (
        "URL_FAKE_HUMAN_VERIFICATION",
        "adverse",
        80,
        0.9,
        "Un lien mène à une fausse page de vérification « êtes-vous humain », servie comme une page ordinaire hors du domaine de l’expéditeur et sans autre contenu : un décor qui fait croire à un site protégé et arrête les contrôles avant la suite.",
    ),
    "DEEP-025": (
        "URL_OPAQUE_LANDING",
        "neutral",
        0,
        0.9,
        "Un lien d’action mène, hors du domaine de l’expéditeur, à une page minuscule qui ne montre rien sans exécuter de script : ni texte, ni lien, ni formulaire. Le contrôle du lien n’a rien pu lire de la destination.",
    ),
    "HIST-001": (
        "HISTORY_CONFIRMED_LEGITIMATE_SENDER",
        "favorable",
        30,
        0.9,
        "L’utilisateur a déjà confirmé plusieurs messages de cet expéditeur.",
    ),
    "HIST-006": (
        "HISTORY_CONFIRMED_MAIL_PROFILE", "favorable", 20, 0.9,
        "L’utilisateur a déjà confirmé ce type de courrier de la même identité authentifiée.",
    ),
    "HIST-002": (
        "HISTORY_FIRST_OBSERVATION",
        "neutral",
        0,
        1.0,
        "L’expéditeur ne dispose pas encore d’un historique local.",
    ),
    "HIST-003": (
        "HISTORY_BEHAVIOR_DEVIATION",
        "adverse",
        35,
        0.75,
        "L’heure ou la taille s’écarte des habitudes observées pour l’expéditeur.",
    ),
    "HIST-004": (
        "HISTORY_APEX_ESTABLISHED_LOCALLY",
        "favorable",
        25,
        0.85,
        "Cette adresse est nouvelle, mais son domaine a déjà livré plusieurs "
        "messages sans aucune étiquette défavorable, toutes boîtes confondues.",
    ),
    "HIST-005": (
        "HISTORY_RECIPIENT_USUAL_LANGUAGE",
        "favorable",
        15,
        0.8,
        "Le message est rédigé dans la langue que ce destinataire reçoit déjà très majoritairement.",
    ),
    "DOMAIN-001": (
        "SENDER_DOMAIN_RECENT",
        "adverse",
        55,
        0.9,
        "Le domaine de l’expéditeur a été créé récemment.",
    ),
    "DOMAIN-002": (
        "SENDER_DOMAIN_ESTABLISHED",
        "favorable",
        15,
        0.85,
        "Le domaine de l’expéditeur est établi depuis plusieurs années.",
    ),
    "DOMAIN-003": (
        "SENDER_DOMAIN_AGE_UNAVAILABLE",
        "neutral",
        0,
        1.0,
        "La date de création du domaine expéditeur n’a pas pu être établie.",
    ),
    "DOMAIN-004": (
        "URL_CROSS_APEX_FRESH_DESTINATION",
        "adverse",
        60,
        0.9,
        "Un lien actionnable mène, hors de l’apex de l’expéditeur, vers un "
        "domaine enregistré depuis peu ; l’authentification de l’expéditeur ne "
        "couvre pas la destination.",
    ),
    "CORR-012": (
        "CORRELATION_TRANSACTIONAL_COHERENCE",
        "favorable",
        25,
        0.85,
        "Le message est une notification transactionnelle authentifiée, "
        "envoyée depuis un domaine établi : trois faits réunis, difficiles à "
        "contrefaire ensemble.",
    ),
    "CORR-013": (
        "CORRELATION_AUTHENTICATED_RFC8058_UNSUBSCRIBE",
        "favorable",
        20,
        0.9,
        "Le message propose une désinscription en un clic sur le domaine de "
        "l’expéditeur, et cet expéditeur est authentifié.",
    ),
    # Écrit en juin, jeté en silence jusqu'au 27 août : le signal était produit,
    # mais aucune règle ne savait le dire. Le fait a pourtant été constaté sur
    # le courrier réel.
    "DEEP-020": (
        "URL_CONDITIONAL_SERVING",
        "adverse",
        75,
        0.9,
        "Un lien du message répond différemment selon l’identité de qui le demande.",
    ),
    # Même sort : une adresse exacte jamais vue qui porte les marqueurs d'un
    # envoi de masse ne produisait rien. Son domaine parent est un autre fait :
    # il peut être connu et établi sans prouver que cet envoi était attendu.
    "NATURE-002": (
        "NATURE_UNSOLICITED_BULK_FIRST_CONTACT",
        "adverse",
        20,
        0.8,
        "Le message porte des marqueurs d’envoi de masse. Cette adresse exacte "
        "n’avait encore aucun historique local ni confirmation humaine pour ce "
        "client ; son domaine parent est évalué séparément.",
    ),
    "POLICY-001": (
        "EVIDENCE_INCOMPLETE",
        "neutral",
        0,
        1.0,
        "La chaîne de preuve profonde est incomplète ; ce manque n’est pas une preuve à charge.",
    ),
    "POLICY-002": (
        "AUTHENTICATED_SENDER_ALLOW",
        "favorable",
        25,
        1.0,
        "L’utilisateur a explicitement autorisé cet expéditeur exact par SMTP authentifié.",
    ),
}


async def persist_deep_hook_runs(
    pool: asyncpg.Pool[Any], investigation_id: str, results: list[Any]
) -> None:
    """Inscrit le passage de chaque enquêteur profond, abouti ou non.

    C'est cette trace qui rend la garantie d'exécution vérifiable : sans elle,
    on ne peut pas distinguer un contrôle qui n'a rien trouvé d'un contrôle qui
    n'a jamais tourné.
    """
    for order, value in enumerate(results, start=200):
        result = (
            SimpleNamespace(**value) if isinstance(value, dict) else value
        )
        await pool.execute(
            """
            INSERT INTO hook_runs (
                investigation_id, hook_name, hook_version, run_order, status,
                duration_ms, facts, error_type, error_detail
            ) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)
            """,
            investigation_id,
            result.hook_name,
            result.hook_version,
            order,
            result.status,
            result.duration_ms,
            _json(result.facts),
            result.error_type,
            pg_text(result.error_detail),
        )


async def persist_signals(
    pool: asyncpg.Pool[Any], investigation_id: str, analysis: dict[str, object]
) -> None:
    raw_signals = analysis.get("signals")
    signals = raw_signals if isinstance(raw_signals, list) else []
    async with pool.acquire() as connection, connection.transaction():
        await connection.execute("SELECT id FROM investigations WHERE id=$1::uuid FOR UPDATE", investigation_id)
        exists = await connection.fetchval(
            """
            SELECT EXISTS (
                SELECT 1 FROM hook_runs
                WHERE investigation_id=$1::uuid AND hook_name='deep_evidence'
            )
            """,
            investigation_id,
        )
        binding = await connection.fetchval(
            "SELECT EXISTS(SELECT 1 FROM verdicts WHERE investigation_id=$1::uuid AND is_binding)",
            investigation_id,
        )
        if binding:
            return
        if exists:
            await connection.execute(
                "DELETE FROM hook_runs WHERE investigation_id=$1::uuid AND run_order>=100", investigation_id
            )
        await persist_deep_hook_runs(
            connection, investigation_id, analysis.get("deep_hook_runs") or []
        )
        hook_run_id = await connection.fetchval(
            """
            INSERT INTO hook_runs (
                investigation_id, hook_name, hook_version, run_order, status,
                duration_ms, facts
            ) VALUES ($1::uuid,'deep_evidence','2.3.0',100,'ok',0,$2::jsonb)
            RETURNING id
            """,
            investigation_id,
            _json(analysis),
        )
        edition_id = await connection.fetchval(
            "SELECT edition_id FROM investigations WHERE id=$1::uuid",
            investigation_id,
        )
        articles = {
            row["article_code"]: row
            for row in await connection.fetch(
                """
                SELECT id, article_code, title, principle, default_direction,
                       default_strength, severity, limitations, parameters
                FROM code_articles WHERE edition_id=$1 AND enabled=true
                """,
                edition_id,
            )
        }
        favorable = 0
        adverse = 0
        neutral = 0
        for ordinal, signal in enumerate(signals):
            if not isinstance(signal, dict):
                continue
            article_code = str(signal.get("article_code") or "")
            rule = _SIGNAL_RULES.get(article_code)
            if rule is None:
                # Certains signaux arrivent déjà qualifiés : ceux qui viennent
                # d'un jugement de sens, où la direction et l'énoncé sont le
                # résultat de l'appréciation, pas d'une table de traduction.
                if not signal.get("clue_code"):
                    # Un fait constaté qui ne sait pas se dire disparaît. Deux
                    # articles y sont restés des mois sans que rien ne le
                    # signale : le journal le dit désormais.
                    _log(
                        "deep.signal_untranslated",
                        article_code=article_code or "(sans article)",
                        kind=str(signal.get("kind") or ""),
                    )
                    continue
                clue_code = str(signal["clue_code"])
                direction = str(signal.get("direction") or "neutral")
                strength = int(signal.get("strength") or 0)
                confidence = float(signal.get("confidence") or 0.75)
                statement = str(signal.get("statement") or "")
            else:
                clue_code, direction, strength, confidence, statement = rule
            if article_code in {"DEEP-024", "DEEP-025"}:
                hosts = signal.get("final_hosts")
                if isinstance(hosts, list) and hosts:
                    statement += " Hébergée sur : " + ", ".join(
                        str(value) for value in hosts[:4]
                    ) + "."
            elif article_code in {"DEEP-002", "DEEP-014"}:
                categories = signal.get("sensitive_categories")
                if isinstance(categories, list) and categories:
                    statement += " Catégories observées : " + ", ".join(
                        str(value) for value in categories
                    ) + "."
            elif article_code == "DEEP-003":
                references = signal.get("url_references")
                if isinstance(references, list) and references:
                    labels = []
                    for value in references[:4]:
                        if not isinstance(value, dict):
                            continue
                        label = str(value.get("visible_text") or "").strip()
                        labels.append(
                            (f"« {label} » - " if label else "")
                            + f"{value.get('initial_apex') or 'apex inconnu'} "
                            f"[réf. {value.get('url_ref') or '?'}] : "
                            f"{value.get('technical_reason') or 'inspection non terminée'}"
                        )
                    if labels:
                        statement += " URL concernées : " + "; ".join(labels) + "."
            elif article_code == "DEEP-005":
                references = signal.get("attachment_references")
                if isinstance(references, list) and references:
                    labels = []
                    for value in references[:4]:
                        if not isinstance(value, dict):
                            continue
                        labels.append(
                            f"{value.get('filename') or 'fichier sans nom'} "
                            f"[réf. {value.get('file_ref') or '?'}] : "
                            f"{value.get('technical_reason') or 'inspection non terminée'}"
                        )
                    if labels:
                        statement += " Fichiers concernés : " + "; ".join(labels) + "."
            if article_code == "HIST-001":
                strength = min(50, 20 + int(signal.get("count") or 0) * 3)
            elif article_code == "DOMAIN-001":
                strength = 70 if int(signal.get("age_days") or 0) < 30 else 35
                statement += (
                    f" Âge observé : {int(signal.get('age_days') or 0)} jours"
                    + (
                        f", création : {signal.get('creation_date')}."
                        if signal.get("creation_date")
                        else "."
                    )
                )
            elif article_code == "DOMAIN-002":
                statement += (
                    f" Âge observé : {int(signal.get('age_days') or 0)} jours"
                    + (
                        f", création : {signal.get('creation_date')}."
                        if signal.get("creation_date")
                        else "."
                    )
                )
            elif article_code == "DOMAIN-004":
                apexes = signal.get("apexes")
                statement += (
                    f" Destination : {', '.join(str(a) for a in apexes)}"
                    if isinstance(apexes, list) and apexes
                    else ""
                ) + f" ; âge observé : {int(signal.get('age_days') or 0)} jours."
            article = articles.get(article_code)
            snapshot = dict(article) if article else {}
            if snapshot.get("id") is not None:
                snapshot["id"] = str(snapshot["id"])
            await connection.execute(
                """
                INSERT INTO clues (
                    investigation_id, hook_run_id, article_id, article_code,
                    clue_code, direction, strength, confidence, statement,
                    facts, provenance, article_snapshot, ordinal
                ) VALUES (
                    $1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,
                    '{"source":"deep-analysis"}'::jsonb,$11::jsonb,$12
                )
                """,
                investigation_id,
                hook_run_id,
                article["id"] if article else None,
                article_code,
                clue_code,
                direction,
                strength,
                confidence,
                pg_text(statement),
                _json(signal),
                _json(snapshot),
                ordinal,
            )
            favorable += strength if direction == "favorable" else 0
            adverse += strength if direction == "adverse" else 0
            neutral += direction == "neutral"
        # Les convergences se calculent ici, et nulle part ailleurs : c'est le
        # seul moment où les indices statiques et l'analyse profonde sont tous
        # écrits. Elles deviennent des indices comme les autres, pour entrer au
        # dossier, au jugement et à l'apprentissage par la même porte.
        observed_rows = await connection.fetch(
            """
            SELECT DISTINCT ON (clue_code) clue_code,facts
            FROM clues WHERE investigation_id=$1::uuid
            ORDER BY clue_code,strength DESC,id DESC
            """,
            investigation_id,
        )
        observed = {str(row["clue_code"]) for row in observed_rows}
        evidence: dict[str, dict[str, object]] = {}
        for row in observed_rows:
            try:
                item = _json_object(row["facts"])
            except (TypeError, ValueError):
                continue
            nested = item.get("facts")
            evidence[str(row["clue_code"])] = (
                dict(nested) if isinstance(nested, dict) else dict(item)
            )
        # Un constat gardé sans charge - domaine authentifié déjà livré - reste
        # écrit sous son code ; il ne doit pas pour autant fonder un faisceau
        # qui, lui, accuse à pleine force.
        observed -= {
            code
            for code, facts in evidence.items()
            if facts.get("attested_locally") is True or facts.get("uncharged")
        }
        message_identity = await connection.fetchrow(
            """
            SELECT m.from_header, m.envelope_from,
                   (SELECT h.value_decoded FROM headers h
                    WHERE h.message_id=m.id AND h.name_normalized='reply-to'
                    ORDER BY h.ordinal LIMIT 1) AS reply_to
            FROM messages m
            JOIN investigations i ON i.message_id=m.id
            WHERE i.id=$1::uuid
            """,
            investigation_id,
        )
        identity = (
            identity_facts(
                message_identity["from_header"],
                message_identity["envelope_from"],
                message_identity["reply_to"],
            )
            if message_identity is not None
            else {}
        )
        for ordinal, convergence in enumerate(
            correlations(observed, identity=identity, evidence=evidence), start=900
        ):
            await connection.execute(
                """
                INSERT INTO clues (
                    investigation_id, hook_run_id, article_code, clue_code,
                    direction, strength, confidence, statement, facts,
                    provenance, ordinal
                ) VALUES (
                    $1::uuid,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,
                    '{"source":"correlation"}'::jsonb,$10
                )
                """,
                investigation_id,
                hook_run_id,
                convergence["article_code"],
                convergence["clue_code"],
                convergence["direction"],
                convergence["strength"],
                convergence["confidence"],
                pg_text(convergence["statement"]),
                _json(convergence["facts"]),
                ordinal,
            )
            adverse += int(convergence["strength"])
        await connection.execute(
            """
            UPDATE investigations SET
                favorable_points=(SELECT coalesce(sum(strength) FILTER(WHERE direction='favorable'),0)
                                  FROM clues WHERE investigation_id=$1::uuid),
                adverse_points=(SELECT coalesce(sum(strength) FILTER(WHERE direction='adverse'),0)
                                FROM clues WHERE investigation_id=$1::uuid),
                neutral_clues=(SELECT count(*) FROM clues WHERE investigation_id=$1::uuid AND direction='neutral'),
                summary=summary || $2::jsonb
            WHERE id=$1::uuid
            """,
            investigation_id,
            _json({"deep_analysis_complete": bool(analysis.get("complete"))}),
        )


# Ce qu'une page vivante ne fait pas varier d'elle-même. Un texte qui change
# entre deux appels est banal - une date, un jeton, une personnalisation. Une
# destination, un statut ou un formulaire qui changent selon l'identité du
# visiteur, non : c'est du service conditionnel, c'est-à-dire du cloaking.
_CLOAKING_FACTS = ("final_apex", "final_status", "form_count")


def _profile_facts(rendu: dict[str, object]) -> dict[str, object]:
    formulaires = rendu.get("forms")
    return {
        "final_apex": rendu.get("final_apex"),
        "final_status": rendu.get("final_status"),
        "form_count": len(formulaires) if isinstance(formulaires, list) else 0,
    }


def compare_profiles(
    scanner: dict[str, object] | None,
    browser: dict[str, object] | None,
) -> dict[str, object]:
    """Compare deux rendus du même lien, obtenus sous deux identités.

    Quarante pour cent des URL de phishing servent une page anodine au scanner
    et la vraie page au visiteur. Un seul profil ne peut pas le voir : il faut
    demander deux fois et comparer.

    La comparaison ne porte que sur des faits de structure. Comparer le texte
    ferait de tout site daté ou personnalisé un cloaker, et un faux « dangereux »
    coûte plus cher ici qu'un signal manquant : l'empreinte de contenu est donc
    rapportée comme contexte, jamais comme preuve.

    Une comparaison impossible - un rendu absent ou en erreur - ne conclut pas
    au calme. Elle se déclare incomplète, et l'examen final en tient compte.
    """
    profils = [
        str((rendu or {}).get("profile") or defaut)
        for rendu, defaut in ((scanner, "scanner"), (browser, "browser"))
    ]
    exploitable = all(
        isinstance(rendu, dict) and not rendu.get("error")
        for rendu in (scanner, browser)
    )
    if not exploitable:
        return {
            "cloaking_detected": False,
            "comparison_incomplete": True,
            "divergences": [],
            "context": [],
            "evidence": {},
            "profiles": profils,
        }

    faits_scanner = _profile_facts(scanner or {})
    faits_browser = _profile_facts(browser or {})
    divergences = [
        nom for nom in _CLOAKING_FACTS if faits_scanner[nom] != faits_browser[nom]
    ]
    contexte = (
        ["content_digest"]
        if (scanner or {}).get("content_digest") != (browser or {}).get("content_digest")
        else []
    )
    return {
        "cloaking_detected": bool(divergences),
        "comparison_incomplete": False,
        "divergences": divergences,
        "context": contexte,
        "evidence": {
            nom: {profils[0]: faits_scanner[nom], profils[1]: faits_browser[nom]}
            for nom in divergences
        },
        "profiles": profils,
    }


# Une comparaison coûte une requête de plus. Trois par message suffisent à
# établir qu'un site sert deux pages différentes ; au-delà, on paie sans rien
# apprendre de neuf.
MAX_PROFILE_COMPARISONS = 3


def should_compare_profiles(
    rendu: dict[str, object],
    *,
    authenticated: bool,
    deja_compares: int,
) -> bool:
    """Faut-il redemander ce lien sous une seconde identité ?

    Pas partout : une seconde inspection de chaque lien doublerait le coût que
    l'on vient de réduire. Elle se réserve aux expéditeurs que rien n'authentifie,
    là où le cloaking se cache. Face à un expéditeur dont SPF, DKIM et DMARC
    s'alignent, se présenter en navigateur n'apprendrait rien et ferait sortir le
    bac à sable sous une fausse identité sans raison de le faire.

    Il faut aussi un premier rendu exploitable : sans lui, il n'y a rien à
    comparer.
    """
    if authenticated:
        return False
    if deja_compares >= MAX_PROFILE_COMPARISONS:
        return False
    if rendu.get("analysis_skipped") or rendu.get("error"):
        return False
    return True


def _verification_gate_signals(
    urls: list[dict[str, object]], *, sender_apex: str
) -> list[dict[str, object]]:
    """Le faux sas « vérifiez que vous êtes humain », vu par le bac à sable.

    Un vrai mur anti-robot refuse le scanner (403) et reste un constat neutre ;
    une page servie en 200 qui n'est QUE ce décor est une tromperie. Le détail
    du partage vit dans ``code/verification_gate``.
    """
    gates = [
        value
        for value in urls
        if value.get("role") != "render_resource"
        and is_fake_verification_gate(
            final_status=value.get("final_status"),
            body_excerpt=value.get("body_excerpt"),
            visible_link_count=value.get("visible_link_count"),
            final_apex=value.get("final_apex"),
            sender_apex=sender_apex,
        )
    ]
    if not gates:
        return []
    return [
        {
            "article_code": "DEEP-024",
            "kind": "fake_human_verification_gate",
            "occurrences": len(gates),
            "final_hosts": sorted(
                {str(value.get("final_host") or "") for value in gates} - {""}
            ),
            "sender_apex": sender_apex,
            "excerpt": str(gates[0].get("body_excerpt") or "")[:200],
        }
    ]


def _opaque_landing_signals(
    urls: list[dict[str, object]], *, sender_apex: str
) -> list[dict[str, object]]:
    """La coquille sans script au bout d'un lien d'action, vue par le bac à sable.

    « Rien observé » et « rien à voir » ne disent pas la même chose : le
    constat, neutre, dit que le contrôle n'a rien pu lire. Le détail du partage
    vit dans ``code/opaque_landing``.
    """
    coquilles: list[dict[str, object]] = []
    for value in urls:
        if value.get("role") == "render_resource":
            continue
        chain = value.get("redirect_chain")
        dernier = chain[-1] if isinstance(chain, list) and chain else {}
        if not isinstance(dernier, dict):
            dernier = {}
        if is_opaque_landing(
            final_status=value.get("final_status"),
            content_type=dernier.get("content_type"),
            size=dernier.get("size"),
            body_excerpt=value.get("body_excerpt"),
            visible_link_count=value.get("visible_link_count"),
            form_count=value.get("form_count"),
            final_apex=value.get("final_apex"),
            sender_apex=sender_apex,
            link_context=value.get("link_context"),
        ):
            coquilles.append(value)
    if not coquilles:
        return []
    return [
        {
            "article_code": "DEEP-025",
            "kind": "opaque_landing",
            "occurrences": len(coquilles),
            "final_hosts": sorted(
                {str(value.get("final_host") or "") for value in coquilles} - {""}
            ),
            "sender_apex": sender_apex,
        }
    ]


def _cloaking_signals(urls: list[dict[str, object]]) -> list[dict[str, object]]:
    """Le service conditionnel établi, transformé en indice pesable.

    Ce n'est pas une redirection inter-apex, que tout prestataire de suivi
    pratique légitimement. C'est le même lien répondant différemment selon
    l'identité de qui demande : la page montrée au scanner n'est pas celle
    montrée au visiteur. Aucun service authentique n'a de raison de faire cela.

    N'avoir pas cherché n'accuse personne : seuls les liens réellement comparés
    et divergents produisent l'indice.
    """
    cloakes = [value for value in urls if value.get("cloaking_detected")]
    if not cloakes:
        return []
    divergences = sorted(
        {
            str(nom)
            for value in cloakes
            for nom in (value.get("cloaking_divergences") or [])
        }
    )
    return [
        {
            "article_code": "DEEP-020",
            "kind": "conditional_serving",
            "occurrences": len(cloakes),
            "divergences": divergences,
            "destinations": sorted(
                {
                    str(value.get("final_apex") or "")
                    for value in cloakes
                    if value.get("final_apex")
                }
            ),
        }
    ]
