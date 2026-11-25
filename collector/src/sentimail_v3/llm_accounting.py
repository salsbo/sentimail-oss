"""Trace les tentatives de modèle sans conserver leur contenu ni leurs secrets."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from typing import Any, Awaitable, Callable, Iterator
from uuid import UUID

logger = logging.getLogger("sentimail-v3-llm-accounting")
Reservation = Callable[[], Awaitable[tuple[int | None, str | None]]]


class LlmQuotaExceeded(RuntimeError):
    """Une tentative refusée par le quota ne contacte aucun fournisseur."""


@dataclass(frozen=True)
class _Scope:
    message_id: str | None = None
    verdict_run_id: str | None = None
    conversation_id: str | None = None
    purpose: str | None = None
    reserve_call: Reservation | None = None


_scope: ContextVar[_Scope] = ContextVar("sentimail_llm_scope", default=_Scope())


@contextmanager
def llm_scope(**fields: Any) -> Iterator[None]:
    """Ajoute un rattachement local à la tâche et restaure le précédent à la sortie."""
    token = _scope.set(replace(_scope.get(), **{key: value for key, value in fields.items() if value is not None}))
    try:
        yield
    finally:
        _scope.reset(token)


def _identifier(value: object) -> str | None:
    text = str(value or "")
    return text if "://" not in text and re.fullmatch(r"[A-Za-z0-9_.:/-]{1,160}", text) else None


def _uuid(value: object) -> UUID | None:
    try:
        return UUID(str(value)) if value else None
    except (ValueError, TypeError):
        return None


def token_counts(usage: Any) -> tuple[int | None, int | None, int | None, int | None]:
    """Normalise OpenAI, Anthropic et Ollama ; le cache reste une partie explicite."""
    usage = usage if isinstance(usage, dict) else {}

    def number(value: Any) -> int | None:
        return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**63 - 1 else None

    details = usage.get("prompt_tokens_details")
    details = details if isinstance(details, dict) else {}
    cache_read = number(usage.get("cache_read_input_tokens", usage.get("prompt_cache_hit_tokens", details.get("cached_tokens"))))
    cache_create = number(usage.get("cache_creation_input_tokens"))
    incoming = number(usage.get("prompt_tokens", usage.get("prompt_eval_count", usage.get("input_tokens"))))
    # Chez Anthropic, input_tokens exclut les deux populations de cache.
    if "input_tokens" in usage and "prompt_tokens" not in usage and incoming is not None:
        incoming += (cache_read or 0) + (cache_create or 0)
        incoming = number(incoming)
    outgoing = number(usage.get("completion_tokens", usage.get("eval_count", usage.get("output_tokens"))))
    return incoming, outgoing, cache_read, cache_create


async def _write(pool: Any, method: str, query: str, *args: Any) -> Any:
    if pool is None:
        return None
    try:
        async with asyncio.timeout(2):
            return await getattr(pool, method)(query, *args)
    except Exception as exc:
        # Le journal ne peut ni casser l'examen ni publier la requête ou une
        # erreur contenant une adresse, un extrait de courrier ou un secret.
        logger.warning("llm_accounting.unavailable type=%s", type(exc).__name__)
        return None


async def observed_call(
    pool: Any, *, role: str | None, provider: str, model: str,
    invoke: Callable[[], Awaitable[tuple[str, dict[str, Any]]]],
    fallback: bool = False,
) -> tuple[str, dict[str, Any]]:
    """Une réservation et une ligne de journal par tentative, repli compris."""
    scope = _scope.get()
    quota_id = None
    if scope.reserve_call is not None:
        quota_id, reason = await scope.reserve_call()
        if reason:
            raise LlmQuotaExceeded(reason)
    identifier = await _write(pool, "fetchval", """
        INSERT INTO llm_attempt_events(message_id,verdict_run_id,conversation_id,
            purpose,role,provider,model_name,is_fallback,quota_event_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id
        """, _uuid(scope.message_id), _uuid(scope.verdict_run_id), _uuid(scope.conversation_id),
        _identifier(scope.purpose), _identifier(role or "verdict"),
        _identifier(provider), _identifier(model), fallback, quota_id)
    started = time.monotonic()
    metadata: dict[str, Any] = {}
    error: BaseException | None = None
    try:
        content, metadata = await invoke()
        if quota_id is not None:
            metadata["quota_event_id"] = quota_id
        return content, metadata
    except BaseException as exc:
        error = exc
        raise
    finally:
        duration_ms = max(0, (time.monotonic() - started) * 1000)
        status = "cancelled" if isinstance(error, asyncio.CancelledError) else "error" if error else "complete"
        error_type = type(error).__name__ if error else None
        counts = token_counts(getattr(error, "usage", {}) if error else metadata.get("usage"))
        cause = getattr(error, "__cause__", None)
        response = getattr(cause, "response", None)
        http_status = (getattr(error, "http_status", None) or getattr(response, "status_code", None)) if error else metadata.get("http_status")
        if not isinstance(http_status, int) or isinstance(http_status, bool) or not 100 <= http_status <= 599:
            http_status = None
        if identifier is not None:
            await _write(pool, "execute", """
                UPDATE llm_attempt_events SET status=$2,completed_at=now(),
                    duration_ms=$3,error_type=$4,http_status=$5,input_tokens=$6,
                    output_tokens=$7,cache_read_tokens=$8,cache_creation_tokens=$9
                WHERE id=$1
                """, identifier, status, duration_ms, error_type, http_status, *counts)
        if quota_id is not None:
            await _write(pool, "execute", """UPDATE llm_call_events SET status=$2,
                provider=$3,model_name=$4,error_type=$5,completed_at=now() WHERE id=$1""",
                quota_id, "error" if error else "complete", _identifier(provider), _identifier(model), error_type)
