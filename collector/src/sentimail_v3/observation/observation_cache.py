"""Réutiliser un constat abouti sans lui donner le pouvoir d'une décision."""

from __future__ import annotations

import asyncio
import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from sentimail_v3.postgres_values import pg_jsonsafe

_SAFE_SETTINGS = (
    "search_base_url", "deepseek_base_url", "deepseek_verdict_model",
    "deepseek_assistant_model", "anthropic_model", "openai_model", "local_llm_url",
    "deepseek_timeout_seconds", "remote_llm_deadline_seconds",
    "economy_llm_deadline_seconds", "deep_hook_deadline_seconds",
    "investigator_llm_attempt_seconds",
    "deep_analysis_deadline_seconds", "url_analysis_deadline_seconds",
    "url_analysis_concurrency", "auto_delivery_confidence", "decision_mode",
    "url_sandbox_url", "file_sandbox_url", "knowledge_embedding_model",
)

_REVISION_SQL = """
SELECT m.raw_sha256,
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(l) ORDER BY l.id)::text,'[]'))
    FROM labels l) AS feedback,
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.id)::text,'[]'))
    FROM sender_policies p) AS policies,
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.participant_email,p.name)::text,'[]'))
    FROM participant_preferences p) AS preferences,
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.edition_id,a.article_code)::text,'[]'))
    FROM code_articles a) AS corpus,
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id)::text,'[]'))
    FROM code_editions e) AS editions,
 (SELECT md5(coalesce(jsonb_agg(jsonb_build_array(
      role,provider,base_url,model_name,token_limit_param,validated_at,updated_at
    ) ORDER BY role)::text,'[]')) FROM llm_role_providers) AS providers,
 (SELECT md5(coalesce(jsonb_agg(to_jsonb(r) ORDER BY role)::text,'[]'))
    FROM llm_local_routing r) AS local_routing,
 (SELECT md5(coalesce(jsonb_agg(jsonb_build_array(fqdn,status,client_id,updated_at)
      ORDER BY fqdn)::text,'[]')) FROM domains) AS domains
FROM messages m WHERE m.id=$1::uuid AND m.redacted_at IS NULL
"""


@lru_cache(maxsize=1)
def package_fingerprint() -> str:
    """Une seule lecture du code installé par processus, puis empreinte stable."""
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    files = sorted(root.rglob("*.py"))
    if not files:
        raise RuntimeError("code source absent")
    for path in files:
        digest.update(str(path.relative_to(root)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def fingerprint(value: Any) -> str:
    """Hache les entrées JSON sans conserver leur texte dans la clé."""
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str,
    ).encode()).hexdigest()


async def observation_fingerprint(pool: Any, message_id: str, settings: Any) -> str | None:
    try:
        async with asyncio.timeout(2):
            row = await pool.fetchrow(_REVISION_SQL, message_id)
        if row is None:
            return None
        parameters = {name: getattr(settings, name, None) for name in _SAFE_SETTINGS}
        parameters["search_enabled"] = bool(getattr(settings, "search_api_key", ""))
        return fingerprint({"code": package_fingerprint(), "revisions": dict(row),
                            "parameters": parameters})
    except Exception:
        return None


def observation_failed(value: Any, *, _depth: int = 0) -> bool:
    """Un skip dû à une source en panne doit pouvoir être réessayé."""
    if _depth > 30:
        return True
    if isinstance(value, dict):
        for key, item in value.items():
            name = str(key).casefold()
            if (("error" in name or "unavailable" in name or name in ("unparsed", "failures")
                 or "incomplete" in name) and bool(item)):
                return True
            if (name in ("parsed", "complete") or name.endswith("_complete")) and item is False:
                return True
            if name in ("status", "outcome", "reason") and item in (
                "error", "search_unavailable", "unparsed", "incomplete",
            ):
                return True
            if observation_failed(item, _depth=_depth+1):
                return True
    elif isinstance(value, (list, tuple)):
        return any(observation_failed(item, _depth=_depth+1) for item in value)
    return False


async def load_observation(
    pool: Any, message_id: str, stage: str, fingerprint: str | None,
) -> dict[str, Any] | None:
    if not fingerprint:
        return None
    try:
        async with asyncio.timeout(2):
            value = await pool.fetchval("""
                SELECT oc.result FROM observation_cache oc
                JOIN messages m ON m.id=oc.message_id
                WHERE oc.message_id=$1::uuid AND oc.stage=$2 AND oc.fingerprint=$3
                  AND oc.expires_at>now() AND m.redacted_at IS NULL
            """, message_id, stage, fingerprint)
        value = json.loads(value) if isinstance(value, str) else value
        return value if isinstance(value, dict) and not observation_failed(value) else None
    except Exception:
        return None


async def save_observation(
    pool: Any, message_id: str, stage: str, fingerprint: str | None,
    result: dict[str, Any], *, ttl_seconds: int = 21600,
) -> bool:
    if not fingerprint or not isinstance(result, dict) or observation_failed(result):
        return False
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        return False
    try:
        async with asyncio.timeout(2):
            inserted = await pool.fetchval("""
                WITH target AS MATERIALIZED (
                    SELECT id FROM messages
                    WHERE id=$1::uuid AND redacted_at IS NULL FOR SHARE
                )
                INSERT INTO observation_cache(message_id,stage,fingerprint,result,expires_at)
                SELECT id,$2,$3,$4::jsonb,now()+make_interval(secs=>$5) FROM target
                ON CONFLICT (message_id,stage,fingerprint) DO UPDATE
                  SET result=EXCLUDED.result,created_at=now(),expires_at=EXCLUDED.expires_at
                  WHERE observation_cache.expires_at<=now()
                RETURNING true
            """, message_id, stage, fingerprint, json.dumps(pg_jsonsafe(result), default=str), min(ttl_seconds, 21600))
        return bool(inserted)
    except Exception:
        return False
