"""Confier un rôle à un modèle local, après l'avoir éprouvé.

Basculer vers un modèle open source n'est pas une case à cocher : un modèle qui
ne rend pas du JSON exploitable, ou qui invente, casse le service sans prévenir.
Cette commande sert donc d'abord à essayer, ensuite seulement à activer.

L'épreuve est volontairement bête et vérifiable : on demande au modèle ce que le
code lui demande réellement — un objet JSON, avec les clés attendues — et on
regarde s'il le fait. Ce n'est pas une mesure de la qualité de jugement, c'est
un préalable : un modèle qui échoue ici n'a aucune chance plus loin.

Usage :
    python -m sentimail_v3.supervision.local_llm --list
    python -m sentimail_v3.supervision.local_llm --probe qwen3:14b
    python -m sentimail_v3.supervision.local_llm --enable conversation --model qwen3:14b
    python -m sentimail_v3.supervision.local_llm --disable conversation
"""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

import asyncpg
import httpx

from sentimail_v3.config import load_settings
from sentimail_v3.llm import ROLES, LlmError, local_chat_json

# Ce que le code attend vraiment d'un modèle : un objet, des clés précises,
# rien autour. Les trois rôles ont des exigences différentes.
PROBES: dict[str, dict[str, Any]] = {
    "conversation": {
        "system": (
            "Tu réponds uniquement par un objet JSON avec les clés "
            '"tool" (chaîne) et "arguments" (objet). Aucun texte autour.'
        ),
        "user": "Je veux savoir combien de messages tu as retenus cette semaine.",
        "required": ("tool",),
    },
    "verdict": {
        "system": (
            "Tu réponds uniquement par un objet JSON avec les clés "
            '"unfavorable" (objet), "favorable" (objet) et "final_verdict" '
            '(objet contenant "classification" et "delivery_decision"). '
            "Aucun texte autour."
        ),
        "user": (
            "Dossier : un message authentifié DMARC=pass, sans URL ni pièce "
            "jointe, d'un expéditeur déjà accepté. Rends ton verdict."
        ),
        "required": ("unfavorable", "favorable", "final_verdict"),
    },
    "analysis": {
        "system": (
            "Tu identifies uniquement l'action demandée. Réponds par un objet "
            'JSON avec les clés "actions" (liste) et "explication" (chaîne).'
        ),
        "user": "Merci de me renvoyer le code de vérification reçu par SMS.",
        "required": ("actions", "explication"),
    },
}


def _extract(content: str) -> dict[str, Any] | None:
    start, end = content.find("{"), content.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        value = json.loads(content[start : end + 1])
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


async def probe(model: str, base_url: str) -> dict[str, Any]:
    """Vérifie que le modèle rend ce que le code sait lire, pour chaque rôle."""
    report: dict[str, Any] = {"model": model, "roles": {}}
    async with httpx.AsyncClient() as client:
        for role, case in PROBES.items():
            try:
                content, metadata = await local_chat_json(
                    client,
                    base_url=base_url,
                    model=model,
                    messages=[
                        {"role": "system", "content": case["system"]},
                        {"role": "user", "content": case["user"]},
                    ],
                    max_tokens=800,
                )
            except LlmError as exc:
                report["roles"][role] = {"ok": False, "reason": str(exc)}
                continue
            value = _extract(content)
            if value is None:
                report["roles"][role] = {"ok": False, "reason": "réponse non JSON"}
                continue
            missing = [key for key in case["required"] if key not in value]
            report["roles"][role] = {
                "ok": not missing,
                "missing_keys": missing,
                "tokens": (metadata.get("usage") or {}).get("eval_count"),
            }
    return report


async def _state(pool: asyncpg.Pool[Any]) -> list[dict[str, Any]]:
    rows = await pool.fetch(
        "SELECT role, model_name, enabled, fallback_enabled, updated_at "
        "FROM llm_local_routing ORDER BY role"
    )
    return [dict(row) for row in rows]


async def _set(
    pool: asyncpg.Pool[Any],
    role: str,
    model: str,
    *,
    enabled: bool,
    fallback: bool,
) -> None:
    async with pool.acquire() as connection, connection.transaction():
        await connection.execute(
            """
            INSERT INTO llm_local_routing (
                role, model_name, enabled, fallback_enabled, updated_at
            ) VALUES ($1,$2,$3,$4,now())
            ON CONFLICT (role) DO UPDATE SET
                model_name=excluded.model_name, enabled=excluded.enabled,
                fallback_enabled=excluded.fallback_enabled, updated_at=now()
            """,
            role,
            model,
            enabled,
            fallback,
        )
        await connection.execute(
            "INSERT INTO audit_log(actor,action,payload) VALUES "
            "('operator','llm.local_routing_changed',$1::jsonb)",
            json.dumps(
                {
                    "role": role,
                    "model": model,
                    "enabled": enabled,
                    "fallback_enabled": fallback,
                },
                ensure_ascii=False,
            ),
        )


async def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m sentimail_v3.supervision.local_llm",
        description="Confie un rôle à un modèle local, ou le lui retire.",
    )
    parser.add_argument("--list", action="store_true", help="état du routage")
    parser.add_argument("--probe", metavar="MODELE", help="éprouve un modèle")
    parser.add_argument("--enable", choices=ROLES, help="confie ce rôle au local")
    parser.add_argument("--disable", choices=ROLES, help="rend ce rôle au distant")
    parser.add_argument("--model", help="modèle local à utiliser pour --enable")
    parser.add_argument(
        "--no-fallback",
        action="store_true",
        help="interdit le repli distant (à réserver au local déjà éprouvé)",
    )
    arguments = parser.parse_args()
    settings = load_settings()

    if arguments.probe:
        print(json.dumps(await probe(arguments.probe, settings.local_llm_url), indent=2, ensure_ascii=False))
        return

    pool = await asyncpg.create_pool(settings.database_url)
    assert pool is not None
    try:
        if arguments.enable:
            if not arguments.model:
                parser.error("--enable exige --model")
            await _set(
                pool,
                arguments.enable,
                arguments.model,
                enabled=True,
                fallback=not arguments.no_fallback,
            )
        if arguments.disable:
            current = await pool.fetchval(
                "SELECT model_name FROM llm_local_routing WHERE role=$1",
                arguments.disable,
            )
            await _set(
                pool,
                arguments.disable,
                str(current or "-"),
                enabled=False,
                fallback=True,
            )
        for row in await _state(pool):
            state = "local" if row["enabled"] else "distant"
            repli = "avec repli" if row["fallback_enabled"] else "sans repli"
            print(f"{row['role']:14s} {state:8s} {row['model_name']:20s} {repli}")
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(_main())
