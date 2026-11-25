"""Configurer et mesurer la cascade Flash -> Pro.

Usage :
    python -m sentimail_v3.supervision.model_routing --status
    python -m sentimail_v3.supervision.model_routing --shadow
    python -m sentimail_v3.supervision.model_routing --enforce
    python -m sentimail_v3.supervision.model_routing --off

``shadow`` compare les deux modèles mais seul Pro décide. ``enforce`` n'est à
utiliser qu'après un échantillon sans divergence de livraison dangereuse.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
from typing import Any

import asyncpg

from sentimail_v3.config import load_settings
from sentimail_v3.judgment.classifier_runtime import corpus_fingerprint
from sentimail_v3.judgment.model_routing import JUDGMENT_RULES_VERSION

MIN_SHADOW_SAMPLES = 50
MIN_AGREEMENT_RATE = 0.95


def enforcement_blocker(samples: int, agreements: int, unsafe: int) -> str | None:
    """Le garde qui empêche Flash de livrer avant d'être réellement mesuré."""
    if samples < MIN_SHADOW_SAMPLES:
        return f"échantillon insuffisant ({samples}/{MIN_SHADOW_SAMPLES})"
    if unsafe:
        return f"{unsafe} divergence(s) de livraison dangereuse"
    if agreements / samples < MIN_AGREEMENT_RATE:
        return (
            f"accord insuffisant ({agreements / samples:.1%}, "
            f"minimum {MIN_AGREEMENT_RATE:.0%})"
        )
    return None


async def qualification_context(executor: Any) -> dict[str, str]:
    """Les comparaisons ne valent que pour le prompt, les règles et le Code lus."""
    # Import local : le moteur utilise aussi le routage pendant son chargement.
    from sentimail_v3.judgment.verdict_engine import PROMPT_VERSION

    return {
        "prompt_version": PROMPT_VERSION,
        "corpus_sha256": await corpus_fingerprint(executor),
        "rules_version": JUDGMENT_RULES_VERSION,
    }


async def _summary(executor: Any, target: dict[str, Any], context: dict[str, str]) -> dict[str, Any]:
    row = await executor.fetchrow(
        """
        SELECT count(*) AS samples,
               count(*) FILTER (WHERE agreement) AS agreements,
               count(*) FILTER (WHERE NOT agreement) AS divergences,
               count(*) FILTER (WHERE unsafe_delivery_divergence) AS unsafe
        FROM verdict_model_routing_evaluations
        WHERE economy_model_name=$1 AND premium_model_name=$2
          AND confidence_margin=$3 AND prompt_version=$4
          AND corpus_sha256=$5 AND rules_version=$6
        """,
        target["economy_model_name"], target["premium_model_name"],
        target["confidence_margin"], context["prompt_version"],
        context["corpus_sha256"], context["rules_version"],
    )
    return dict(row)


async def _set_mode(
    pool: asyncpg.Pool[Any],
    mode: str,
    economy: str | None,
    premium: str | None,
    margin: float | None,
) -> None:
    """Qualifie puis applique la cible dans une transaction, sous le même verrou."""
    if mode not in {"off", "shadow", "enforced"}:
        raise ValueError("mode de cascade inconnu")
    if margin is not None and (not math.isfinite(margin) or not 0 <= margin <= 0.20):
        raise ValueError("la marge doit être comprise entre 0 et 0.20")
    if any(value is not None and not value.strip() for value in (economy, premium)):
        raise ValueError("un nom de modèle ne peut pas être vide")
    async with pool.acquire() as connection, connection.transaction():
        row = await connection.fetchrow(
            "SELECT * FROM verdict_model_routing WHERE singleton=true FOR UPDATE"
        )
        if row is None:
            raise ValueError("configuration de cascade absente")
        target = dict(row)
        if economy is not None:
            target["economy_model_name"] = economy
        if premium is not None:
            target["premium_model_name"] = premium
        if margin is not None:
            target["confidence_margin"] = margin
        if mode == "enforced":
            # Le calcul et l'activation lisent la même frontière : aucune
            # révision du Code ni comparaison déjà en écriture ne s'intercale.
            await connection.execute(
                "LOCK TABLE code_articles, verdict_model_routing_evaluations IN SHARE MODE"
            )
        context = await qualification_context(connection)
        if mode == "enforced":
            summary = await _summary(connection, target, context)
            blocker = enforcement_blocker(summary["samples"], summary["agreements"], summary["unsafe"])
            if blocker:
                raise ValueError("activation refusée pour la configuration cible : " + blocker)
        await connection.execute(
            """
            UPDATE verdict_model_routing SET mode=$1,
                economy_model_name=$2, premium_model_name=$3, confidence_margin=$4,
                configured_by='operator',updated_at=now()
            WHERE singleton=true
            """,
            mode, target["economy_model_name"], target["premium_model_name"], target["confidence_margin"],
        )
        await connection.execute(
            "INSERT INTO audit_log(actor,action,payload) VALUES "
            "('operator','llm.model_routing_changed',$1::jsonb)",
            json.dumps({"mode": mode, **{key: target[key] for key in (
                "economy_model_name", "premium_model_name", "confidence_margin")},
                **context}, ensure_ascii=False),
        )


async def _report(pool: asyncpg.Pool[Any]) -> dict[str, object]:
    async with pool.acquire() as connection, connection.transaction():
        config = await connection.fetchrow(
            "SELECT mode,economy_model_name,premium_model_name,confidence_margin,"
            "configured_by,updated_at FROM verdict_model_routing WHERE singleton=true FOR SHARE"
        )
        context = await qualification_context(connection)
        summary = await _summary(connection, dict(config), context) if config else {}
    return {
        "configuration": dict(config) if config else None,
        "qualification_context": context,
        "evaluation": summary,
    }


async def _main() -> None:
    parser = argparse.ArgumentParser(description="Configure la cascade Flash vers Pro.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--status", action="store_true")
    group.add_argument("--shadow", action="store_true")
    group.add_argument("--enforce", action="store_true")
    group.add_argument("--off", action="store_true")
    parser.add_argument("--economy-model")
    parser.add_argument("--premium-model")
    parser.add_argument("--confidence-margin", type=float)
    arguments = parser.parse_args()
    if arguments.confidence_margin is not None and not 0 <= arguments.confidence_margin <= 0.20:
        parser.error("--confidence-margin doit être compris entre 0 et 0.20")
    mode = (
        "shadow" if arguments.shadow else
        "enforced" if arguments.enforce else
        "off" if arguments.off else None
    )
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url)
    try:
        if mode:
            try:
                await _set_mode(
                    pool, mode, arguments.economy_model,
                    arguments.premium_model, arguments.confidence_margin,
                )
            except ValueError as exc:
                parser.error(str(exc))
        print(json.dumps(await _report(pool), ensure_ascii=False, indent=2, default=str))
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(_main())
