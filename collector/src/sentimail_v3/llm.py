from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, NamedTuple

import asyncpg
import httpx

from sentimail_v3.config import Settings


class LlmError(RuntimeError):
    """Erreur bornee et sans secret expose lors d'un appel LLM."""


ROLES = ("conversation", "verdict")


async def local_route(
    pool: asyncpg.Pool[Any], role: str | None
) -> tuple[str, bool] | None:
    """Modèle local servant ce rôle, et si un repli distant reste permis."""
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
) -> tuple[str, dict[str, Any]]:
    """Appelle un modèle servi localement par Ollama, en JSON strict."""
    if not base_url:
        raise LlmError("aucune adresse de modèle local configurée")
    try:
        response = await client.post(
            f"{base_url.rstrip('/')}/api/chat",
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
        raise LlmError("réponse du modèle local invalide") from exc
    if not isinstance(content, str) or not content.strip():
        raise LlmError("le modèle local a répondu vide")
    return content, {
        "model": payload.get("model"),
        "finish_reason": payload.get("done_reason"),
        "usage": {
            "prompt_eval_count": payload.get("prompt_eval_count"),
            "eval_count": payload.get("eval_count"),
        },
        "provider": "ollama",
        "local": True,
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


async def openai_compatible_chat_json(
    client: httpx.AsyncClient, *, route: ProviderRoute,
    messages: list[dict[str, str]], max_tokens: int,
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
    response = await client.post(
        f"{route.base_url.rstrip('/')}/chat/completions",
        headers=headers, json=body,
    )
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise LlmError(f"LLM HTTP {response.status_code}") from exc
    try:
        payload = response.json()
        choice = payload["choices"][0]
        content = choice["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise LlmError("réponse LLM invalide") from exc
    if not isinstance(content, str) or not content.strip():
        raise LlmError("réponse LLM vide")
    metadata = {
        "id": payload.get("id"),
        "model": payload.get("model"),
        "system_fingerprint": payload.get("system_fingerprint"),
        "finish_reason": choice.get("finish_reason"),
        "usage": payload.get("usage") or {},
    }
    return content, metadata


async def anthropic_chat_json(
    client: httpx.AsyncClient, *, route: ProviderRoute,
    messages: list[dict[str, str]], max_tokens: int,
) -> tuple[str, dict[str, Any]]:
    system = "\n\n".join(
        item["content"] for item in messages if item.get("role") == "system"
    )
    anthropic_messages = [
        item for item in messages if item.get("role") in {"user", "assistant"}
    ]
    response = await client.post(
        f"{route.base_url.rstrip('/')}/v1/messages",
        headers={
            "x-api-key": route.api_key,
            "anthropic-version": "2023-06-01",
        },
        json={
            "model": route.model,
            "system": system,
            "messages": anthropic_messages,
            "temperature": 0.1,
            "max_tokens": max_tokens,
        },
    )
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise LlmError(f"Anthropic HTTP {response.status_code}") from exc
    try:
        payload = response.json()
        content = "".join(
            str(block.get("text") or "")
            for block in payload["content"]
            if isinstance(block, dict) and block.get("type") == "text"
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise LlmError("Anthropic response shape is invalid") from exc
    if not content.strip():
        raise LlmError("Anthropic returned an empty response")
    return content, {
        "id": payload.get("id"),
        "model": payload.get("model"),
        "finish_reason": payload.get("stop_reason"),
        "usage": payload.get("usage") or {},
    }


async def _remote_chat_json(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    *,
    messages: list[dict[str, str]],
    max_tokens: int,
    role: str | None,
) -> tuple[str, dict[str, Any]]:
    """Interroge le fournisseur distant configuré pour ce rôle."""
    route = await active_provider(pool, settings, role)
    if route.provider == "anthropic":
        content, metadata = await anthropic_chat_json(
            client, route=route, messages=messages, max_tokens=max_tokens)
    else:
        content, metadata = await openai_compatible_chat_json(
            client, route=route, messages=messages, max_tokens=max_tokens)
    metadata["provider"] = route.provider
    metadata["base_url"] = route.base_url
    return content, metadata


async def provider_chat_json(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    *,
    messages: list[dict[str, str]],
    max_tokens: int,
    role: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Le rôle décide qui répond : le modèle local s'il sert ce rôle, sinon
    le fournisseur distant configuré. Un échec local retombe sur le distant,
    et le dit dans les métadonnées plutôt que de passer inaperçu."""
    route = await local_route(pool, role)
    if route is not None:
        model, fallback = route
        try:
            return await local_chat_json(
                client,
                base_url=settings.local_llm_url,
                model=model,
                messages=messages,
                max_tokens=max_tokens,
            )
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
        )
        metadata["local_fallback_from"] = model
        metadata["local_failure"] = local_failure
        return content, metadata
    return await _remote_chat_json(
        pool, client, settings,
        messages=messages, max_tokens=max_tokens, role=role,
    )
