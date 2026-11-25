from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, NamedTuple

import asyncpg
import httpx

from sentimail_v3.config import Settings
from sentimail_v3.llm_accounting import observed_call


class LlmError(RuntimeError):
    """Erreur bornee et sans secret expose lors d'un appel LLM."""

    def __init__(
        self, message: str, *, usage: Any = None, http_status: int | None = None,
        deadline_exceeded: bool = False,
    ) -> None:
        super().__init__(message)
        self.usage = usage
        self.http_status = http_status
        # Le fournisseur n'a pas répondu dans le délai total de la tentative.
        self.deadline_exceeded = deadline_exceeded


# Les modèles Claude récents refusent `temperature` (HTTP 400) et répondent plus
# longuement que la limite historique de 2400 jetons : rejeu du 2026-11-11 sur
# 50 dossiers, jusqu'à 2842 jetons (Sonnet 5.5) et 4305 (Haiku 5.5). Une réponse
# coupée est un JSON invalide, donc un verdict perdu.
ANTHROPIC_MIN_OUTPUT_TOKENS = 6000


def with_system_addendum(
    messages: list[dict[str, str]], addendum: str | None
) -> list[dict[str, str]]:
    """Ajoute un complément à la fin du message système, sans modifier l'original."""
    if not addendum:
        return messages
    result: list[dict[str, str]] = []
    done = False
    for item in messages:
        if not done and item.get("role") == "system":
            item = {**item, "content": item["content"].rstrip() + "\n\n" + addendum}
            done = True
        result.append(item)
    return result


ROLES = ("conversation", "analysis", "verdict")
# Enquêteurs courts de l'analyse profonde : une question, une réponse brève.
INVESTIGATOR_ROLES = frozenset(
    {"requested_action", "sender_relation", "identity_claim", "activity_coherence"}
)
_LOCAL_ROLE_ALIASES = {
    "requested_action": "analysis",
    "sender_relation": "analysis",
    "identity_claim": "analysis",
    "activity_coherence": "analysis",
}


def local_role(role: str | None) -> str | None:
    """Rassemble les enquêteurs courts sous un rôle local administrable."""
    if role is None:
        return None
    return _LOCAL_ROLE_ALIASES.get(role, role)


async def local_route(
    pool: asyncpg.Pool[Any], role: str | None
) -> tuple[str, bool] | None:
    """Modèle local servant ce rôle, et si un repli distant reste permis."""
    role = local_role(role)
    if not role:
        return None
    row = await pool.fetchrow(
        "SELECT model_name, fallback_enabled FROM llm_local_routing "
        "WHERE role=$1 AND enabled=true",
        role,
    )
    if row is None:
        return None
    return str(row["model_name"]), bool(row["fallback_enabled"])


async def local_chat_json(
    client: httpx.AsyncClient,
    *,
    base_url: str,
    model: str,
    messages: list[dict[str, str]],
    max_tokens: int,
    deadline_seconds: float | None = None,
) -> tuple[str, dict[str, Any]]:
    """Appelle un modèle servi localement par Ollama, en JSON strict."""
    if not base_url:
        raise LlmError("aucune adresse de modèle local configurée")
    payload: Any = None
    try:
        response = await _post_within_deadline(
            client, deadline_seconds, url=f"{base_url.rstrip('/')}/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.1, "num_predict": max_tokens},
            },
            # Un modèle local démarre à froid : le premier appel charge les
            # poids en mémoire et prend bien plus longtemps que les suivants.
            timeout=300.0,
        )
        response.raise_for_status()
        payload = response.json()
        content = payload["message"]["content"]
    except httpx.HTTPStatusError as exc:
        raise LlmError(f"modèle local HTTP {exc.response.status_code}") from exc
    except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
        raise LlmError("réponse du modèle local invalide", usage=payload,
                       http_status=response.status_code if payload is not None else None) from exc
    if not isinstance(content, str) or not content.strip():
        raise LlmError("le modèle local a répondu vide", usage={
            "prompt_eval_count": payload.get("prompt_eval_count"),
            "eval_count": payload.get("eval_count"),
        }, http_status=response.status_code)
    return content, {
        "model": payload.get("model"),
        "finish_reason": payload.get("done_reason"),
        "usage": {
            "prompt_eval_count": payload.get("prompt_eval_count"),
            "eval_count": payload.get("eval_count"),
        },
        "provider": "ollama",
        "local": True,
        "http_status": response.status_code,
    }


class ProviderRoute(NamedTuple):
    provider: str
    base_url: str
    model: str
    api_key: str
    token_limit_param: str
    # Champ(s) propriétaire(s) qu'un fournisseur exige dans le corps de la
    # requête (ex. `thinking` DeepSeek) : la config le porte, jamais
    # l'adaptateur.
    body_extras: dict[str, Any] = {}


_SECRET_FILENAME_RE = re.compile(r"^[a-z0-9_]{1,64}$")


def _coerce_body_extras(value: Any) -> dict[str, Any]:
    """`body_extras` vient de jsonb : asyncpg le rend en `str` sans codec
    dédié, en `dict` avec un codec configuré. Les deux formes sont acceptées,
    tout le reste (colonne absente, null, valeur illisible) retombe sur {}."""
    if isinstance(value, str):
        if not value.strip():
            return {}
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return {}
    return value if isinstance(value, dict) else {}


def _provider_role(role: str | None) -> str:
    """La carte qui répond : la conversation a la sienne, l'analyse tout le reste."""
    return "conversation" if role == "conversation" else "verdict"


async def active_provider(
    pool: asyncpg.Pool[Any], settings: Settings, role: str | None = None
) -> ProviderRoute:
    row = await pool.fetchrow(
        "SELECT provider,base_url,model_name,token_limit_param,secret_filename,"
        "body_extras FROM llm_role_providers WHERE role=$1",
        _provider_role(role),
    )
    if row is None:
        # Table vide : l'instance vit sur son environnement, comme avant. Ce
        # repli EST le chemin historique DeepSeek : son API raisonne par
        # défaut, et un dossier de verdict long épuiserait max_tokens en
        # raisonnement, contenu vide à l'arrivée (régression du 22/08).
        if not settings.deepseek_api_key:
            raise LlmError("aucun fournisseur LLM n'est configuré")
        model = (
            settings.deepseek_assistant_model
            if _provider_role(role) == "conversation"
            else settings.deepseek_verdict_model
        )
        return ProviderRoute(
            "openai_compatible", settings.deepseek_base_url, model,
            settings.deepseek_api_key, "max_tokens",
            {"thinking": {"type": "disabled"}},
        )
    filename = str(row["secret_filename"])
    if not _SECRET_FILENAME_RE.fullmatch(filename):
        raise LlmError("fichier de secret fournisseur refusé")
    path = (Path(settings.provider_secrets_dir) / filename).resolve()
    # Redondant avec la regex ci-dessus par construction (elle interdit déjà
    # '/' et '..') : garde-fou volontaire pour rester la seule vraie défense
    # si la regex venait un jour à se relâcher.
    if path.parent != Path(settings.provider_secrets_dir).resolve():
        raise LlmError("fichier de secret fournisseur refusé")
    try:
        key = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        # Illisible ou mal encodé -> clé vide, jamais une exception qui
        # ferait échouer l'appel LLM sur un problème de fichier local.
        key = ""
    # Une clé vide est permise : un endpoint local n'en demande pas.
    return ProviderRoute(
        str(row["provider"]), str(row["base_url"]), str(row["model_name"]),
        key, str(row["token_limit_param"]),
        _coerce_body_extras(row.get("body_extras")),
    )


async def _post_within_deadline(
    client: httpx.AsyncClient, deadline_seconds: float | None, **request: Any
) -> httpx.Response:
    """Borne l'appel entier, pas seulement chaque lecture.

    Le délai httpx repart à chaque octet reçu : un serveur qui a envoyé ses
    en-têtes puis fait traîner le corps tient la ligne tant qu'il émet quelque
    chose. Le 14 septembre 2026, un appel Flash a duré 901 s ainsi, et le juge
    est resté suspendu avec lui. Le dépassement devient une LlmError : c'est
    la seule erreur que le repli d'un palier vers l'autre rattrape.
    """
    if deadline_seconds is None:
        return await client.post(**request)
    try:
        return await asyncio.wait_for(client.post(**request), timeout=deadline_seconds)
    except asyncio.TimeoutError as exc:
        raise LlmError(
            f"délai total de {deadline_seconds:g} s dépassé", deadline_exceeded=True
        ) from exc


async def openai_compatible_chat_json(
    client: httpx.AsyncClient, *, route: ProviderRoute,
    messages: list[dict[str, str]], max_tokens: int,
    deadline_seconds: float | None = None,
) -> tuple[str, dict[str, Any]]:
    headers = {"Authorization": f"Bearer {route.api_key}"} if route.api_key else {}
    body: dict[str, Any] = {
        "model": route.model,
        "messages": messages,
        "response_format": {"type": "json_object"},
        route.token_limit_param: max_tokens,
    }
    # `max_completion_tokens` et le refus de `temperature` viennent de la même
    # génération d'API OpenAI (les modèles "raisonneurs") : c'est pourquoi un
    # seul réglage (`token_limit_param`) suffit à piloter les deux à la fois.
    if route.token_limit_param != "max_completion_tokens":
        body["temperature"] = 0.1
    # Les champs propriétaires du fournisseur (ex. `thinking` DeepSeek)
    # l'emportent sur le corps générique : la config sait ce que son API
    # attend, l'adaptateur ne connaît aucun nom de fournisseur.
    body.update(route.body_extras or {})
    response = await _post_within_deadline(
        client, deadline_seconds,
        url=f"{route.base_url.rstrip('/')}/chat/completions",
        headers=headers, json=body,
    )
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise LlmError(f"LLM HTTP {response.status_code}") from exc
    payload: Any = None
    try:
        payload = response.json()
        choice = payload["choices"][0]
        content = choice["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise LlmError("réponse LLM invalide", usage=payload.get("usage") if isinstance(payload, dict) else None,
                       http_status=response.status_code) from exc
    if not isinstance(content, str) or not content.strip():
        raise LlmError("réponse LLM vide", usage=payload.get("usage"), http_status=response.status_code)
    metadata = {
        "id": payload.get("id"),
        "model": payload.get("model"),
        "system_fingerprint": payload.get("system_fingerprint"),
        "finish_reason": choice.get("finish_reason"),
        "usage": payload.get("usage") or {},
        "http_status": response.status_code,
    }
    return content, metadata


async def anthropic_chat_json(
    client: httpx.AsyncClient, *, route: ProviderRoute,
    messages: list[dict[str, str]], max_tokens: int,
    deadline_seconds: float | None = None,
) -> tuple[str, dict[str, Any]]:
    system = "\n\n".join(
        item["content"] for item in messages if item.get("role") == "system"
    )
    anthropic_messages = [
        item for item in messages if item.get("role") in {"user", "assistant"}
    ]
    response = await _post_within_deadline(
        client, deadline_seconds,
        url=f"{route.base_url.rstrip('/')}/v1/messages",
        headers={
            "x-api-key": route.api_key,
            "anthropic-version": "2023-06-01",
        },
        json={
            "model": route.model,
            "system": system,
            "messages": anthropic_messages,
            # Pas de `temperature` : les modèles Claude actuels la refusent.
            "max_tokens": max(max_tokens, ANTHROPIC_MIN_OUTPUT_TOKENS),
        },
    )
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise LlmError(f"Anthropic HTTP {response.status_code}") from exc
    payload: Any = None
    try:
        payload = response.json()
        content = "".join(
            str(block.get("text") or "")
            for block in payload["content"]
            if isinstance(block, dict) and block.get("type") == "text"
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise LlmError("Anthropic response shape is invalid", usage=payload.get("usage") if isinstance(payload, dict) else None,
                       http_status=response.status_code) from exc
    if not content.strip():
        raise LlmError("Anthropic returned an empty response", usage=payload.get("usage"), http_status=response.status_code)
    return content, {
        "id": payload.get("id"),
        "model": payload.get("model"),
        "finish_reason": payload.get("stop_reason"),
        "usage": payload.get("usage") or {},
        "http_status": response.status_code,
    }


def _investigator_attempt_seconds(settings: Settings) -> float:
    """Délai d'une tentative d'enquêteur : deux tentatives tiennent toujours
    dans les deux tiers du délai de l'enquêteur, quel que soit le réglage."""
    seconds = float(getattr(settings, "investigator_llm_attempt_seconds", 15))
    hook = float(getattr(settings, "deep_hook_deadline_seconds", 45))
    return max(0.001, min(seconds, hook / 3))


async def _remote_chat_json(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    *,
    messages: list[dict[str, str]],
    max_tokens: int,
    role: str | None,
    model_override: str | None = None,
    deadline_seconds: float | None = None,
    fallback: bool = False,
    provider_addenda: dict[str, str] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Interroge le fournisseur distant configuré pour ce rôle.

    Un enquêteur court borne chaque tentative et la refait une fois quand le
    fournisseur ne répond pas. Le 12 novembre 2026, un seul appel resté sans
    réponse a consommé les 45 s de `sender_relation` : passage sans constat,
    alors que l'appel suivant répondait en 1,5 s. Seul le dépassement de délai
    est retenté ; une erreur du fournisseur garde son traitement. Un délai
    explicite de l'appelant l'emporte et n'est pas retenté. Le modèle local,
    qui charge ses poids à froid, n'est pas concerné.
    """
    route = await active_provider(pool, settings, role)
    messages = with_system_addendum(messages, (provider_addenda or {}).get(route.provider))
    if model_override:
        route = route._replace(model=model_override)
    bounded = role in INVESTIGATOR_ROLES and deadline_seconds is None
    deadline = (
        _investigator_attempt_seconds(settings)
        if bounded
        else deadline_seconds
        if deadline_seconds is not None
        else settings.remote_llm_deadline_seconds
    )
    adapter = anthropic_chat_json if route.provider == "anthropic" else openai_compatible_chat_json

    async def attempt() -> tuple[str, dict[str, Any]]:
        return await observed_call(
            pool, role=role, provider=route.provider, model=route.model, fallback=fallback,
            invoke=lambda: adapter(client, route=route, messages=messages,
                                   max_tokens=max_tokens, deadline_seconds=deadline),
        )

    attempts = 1
    try:
        content, metadata = await attempt()
    except LlmError as exc:
        if not (bounded and exc.deadline_exceeded):
            raise
        attempts = 2
        content, metadata = await attempt()
        metadata["retried_after_deadline"] = True
    metadata["provider"] = route.provider
    metadata["base_url"] = route.base_url
    metadata["attempt_count"] = attempts
    return content, metadata


async def provider_chat_json(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    *,
    messages: list[dict[str, str]],
    max_tokens: int,
    role: str | None = None,
    model_override: str | None = None,
    allow_local: bool = True,
    deadline_seconds: float | None = None,
    provider_addenda: dict[str, str] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Le rôle décide qui répond : le modèle local s'il sert ce rôle, sinon
    le fournisseur distant configuré. Un échec local retombe sur le distant,
    et le dit dans les métadonnées plutôt que de passer inaperçu."""
    route = await local_route(pool, role) if allow_local else None
    if route is not None:
        model, fallback = route
        local_attempted = bool(settings.local_llm_url)
        try:
            if not local_attempted:
                raise LlmError("aucune adresse de modèle local configurée")
            content, metadata = await observed_call(
                pool, role=role, provider="ollama", model=model,
                invoke=lambda: local_chat_json(
                    client, base_url=settings.local_llm_url, model=model,
                    messages=messages, max_tokens=max_tokens,
                    deadline_seconds=deadline_seconds,
                ),
            )
            metadata["attempt_count"] = 1
            return content, metadata
        except LlmError as exc:
            if not fallback:
                raise
            local_failure = str(exc)
        # Repli direct sur le fournisseur distant : passer par
        # provider_chat_json referait perdre le rôle (_provider_role(None)
        # répondrait toujours "verdict"), y compris pour une conversation.
        content, metadata = await _remote_chat_json(
            pool, client, settings,
            messages=messages, max_tokens=max_tokens, role=role,
            model_override=model_override, deadline_seconds=deadline_seconds,
            fallback=True, provider_addenda=provider_addenda,
        )
        metadata["local_fallback_from"] = model
        metadata["local_failure"] = local_failure
        metadata["attempt_count"] = int(metadata.get("attempt_count") or 1) + int(local_attempted)
        return content, metadata
    return await _remote_chat_json(
        pool, client, settings,
        messages=messages, max_tokens=max_tokens, role=role,
        model_override=model_override, deadline_seconds=deadline_seconds,
        provider_addenda=provider_addenda,
    )
