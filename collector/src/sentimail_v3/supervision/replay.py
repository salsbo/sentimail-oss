"""Rejeu d'un dossier : réanalyse et jugement avec le Code et les hooks à jour.

Le rejeu remet un message dans la file d'analyse au lieu de bricoler son état à
la main. Il efface le jugement précédent après l'avoir résumé dans l'audit,
rejoue les hooks sur l'EML conservé pour que le dossier reflète le Code actuel,
libère les compteurs de tentatives, et laisse le pipeline reprendre son cours.

Quand la rétention a déjà effacé l'EML, l'observation ne peut plus être refaite :
seul le jugement est rejoué, et le rapport le signale.

Un message déjà livré ne peut pas être rappelé : le rejeu sert alors à vérifier
la détection, jamais à revenir sur la livraison. Un message en cours de
conversation garde son avis MAIA ; aucun second avis n'est envoyé.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

import asyncpg

from sentimail_v3.config import load_settings
from sentimail_v3.crypto import load_key
from sentimail_v3.execution.delivery_state import TERMINAL
from sentimail_v3.observation.storage import Store

# Un message consommé est une réponse SMTP de l'utilisateur, pas un dossier.
REPLAYABLE_STATUSES = ("captured", "analyzing", "held", "deferred", "delivered")
MAX_BATCH = 50


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


async def select_cases(
    pool: asyncpg.Pool[Any], selector: str, limit: int
) -> list[asyncpg.Record]:
    """Résout un préfixe d'identifiant, ou tous les dossiers d'un état donné."""
    if selector in {"held", "delivered", "captured", "analyzing", "deferred"}:
        return await pool.fetch(
            """
            SELECT id::text, delivery_status, captured_at, from_header, subject
            FROM messages WHERE delivery_status=$1
            ORDER BY captured_at DESC LIMIT $2
            """,
            selector,
            min(limit, MAX_BATCH),
        )
    return await pool.fetch(
        """
        SELECT id::text, delivery_status, captured_at, from_header, subject
        FROM messages
        WHERE id::text LIKE $1 || '%' AND delivery_status = ANY($2::text[])
        LIMIT $3
        """,
        selector.casefold(),
        list(REPLAYABLE_STATUSES),
        min(limit, MAX_BATCH),
    )


async def replay_case(
    pool: asyncpg.Pool[Any],
    message_id: str,
    *,
    fresh_evidence: bool = False,
    reobserve: bool = True,
    encryption_key: bytes | None = None,
) -> dict[str, object]:
    """Remet un dossier dans la file d'analyse et trace ce qui a été effacé."""
    async with pool.acquire() as connection, connection.transaction():
        message = await connection.fetchrow(
            """
            SELECT id::text, delivery_status FROM messages
            WHERE id=$1::uuid FOR UPDATE
            """,
            message_id,
        )
        if message is None:
            raise ValueError(f"message inconnu : {message_id}")
        if message["delivery_status"] not in REPLAYABLE_STATUSES:
            raise ValueError(
                f"état non rejouable : {message['delivery_status']}"
            )
        previous = await connection.fetchrow(
            """
            SELECT vr.status, vr.attempts, vr.error_type,
                   vr.response->'verdict'->>'classification' AS classification,
                   vr.response->'verdict'->>'delivery_decision' AS delivery_decision
            FROM verdict_runs vr
            JOIN investigations i ON i.id=vr.investigation_id
            WHERE i.message_id=$1::uuid
            ORDER BY vr.created_at DESC LIMIT 1
            """,
            message_id,
        )
        # La suppression du run libère aussi ses compteurs d'appels LLM, dont la
        # clé (run, tentative) interdirait sinon toute nouvelle tentative.
        removed_runs = await connection.execute(
            """
            DELETE FROM verdict_runs
            WHERE investigation_id IN (
                SELECT id FROM investigations WHERE message_id=$1::uuid
            )
            """,
            message_id,
        )
        removed_evidence = "0"
        if fresh_evidence:
            removed_evidence = await connection.execute(
                "DELETE FROM external_analyses WHERE message_id=$1::uuid",
                message_id,
            )
        # Un message livré ne se rouvre pas. Le rejouer sert alors à vérifier
        # la détection, jamais à revenir sur la livraison : on garde l'état
        # terminal, ce qui laisse `release_original` refuser (already_delivered)
        # si un nouveau verdict tentait de livrer.
        terminal = message["delivery_status"] in TERMINAL
        if not terminal:
            await connection.execute(
                """
                UPDATE messages
                SET delivery_status='analyzing', last_delivery_error=NULL
                WHERE id=$1::uuid
                """,
                message_id,
            )
        report = {
            "message_id": message_id,
            "terminal_kept": terminal,
            "previous_delivery_status": message["delivery_status"],
            "previous_verdict": dict(previous) if previous is not None else None,
            "verdict_runs_removed": removed_runs.rsplit(" ", 1)[-1],
            "external_analyses_removed": removed_evidence.rsplit(" ", 1)[-1],
            "fresh_evidence": fresh_evidence,
        }
    # Hors de la transaction d'état : les hooks lisent le message et écrivent
    # une nouvelle observation. Sans EML conservé, seul le jugement est rejoué.
    report["reobserved"] = (
        await Store(pool, encryption_key).reinvestigate(message_id)
        if reobserve
        else False
    )
    async with pool.acquire() as connection, connection.transaction():
        await connection.execute(
            "INSERT INTO audit_log(actor,action,payload) VALUES "
            "('operator','case.replayed',$1::jsonb)",
            _json(report),
        )
    return report


def replay_outcome(delivery_status: str, *, decision_mode: bool) -> dict[str, object]:
    """Ce que le rejeu produira réellement, selon le mode du moteur.

    Le moteur ne va pas chercher les mêmes dossiers selon son mode : en
    décision, il ne reprend que ce qui est encore en cours d'analyse ; en
    observation, il ne juge que ce qui est déjà livré. Rejouer un message hors
    de cette sélection refait bien l'observation, mais aucun jugement ne suit.

    Annoncer « le pipeline reprend son cours » dans ce cas laissait croire
    qu'une correction venait d'être vérifiée alors que rien n'avait été rejugé.
    """
    # Le rejeu remet les dossiers non terminaux en « analyzing » : c'est ce
    # statut d'arrivée qu'il faut confronter à la sélection du moteur. Raisonner
    # sur le statut d'avant le rejeu annoncerait l'inverse de ce qui se passe
    # pour un message retenu.
    after = delivery_status if delivery_status in TERMINAL else "analyzing"
    judged = (
        after in ("captured", "analyzing")
        if decision_mode
        else after == "delivered"
    )
    if judged:
        return {
            "verdict_expected": True,
            "explanation": "Le moteur reprendra ce dossier et rendra un nouveau jugement.",
        }
    attendu = "encore en cours d’analyse" if decision_mode else "déjà livrés"
    return {
        "verdict_expected": False,
        "explanation": (
            f"L’observation est refaite, mais aucun jugement ne suivra : en mode "
            f"{'décision' if decision_mode else 'observation'}, le moteur ne reprend "
            f"que les messages {attendu}, et celui-ci reste « {after} ». "
            "Pour éprouver une correction de bout en bout, envoie un message de test."
        ),
    }


async def run(selector: str, *, fresh_evidence: bool, limit: int, apply: bool) -> None:
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    try:
        cases = await select_cases(pool, selector, limit)
        if not cases:
            print("Aucun dossier rejouable ne correspond à cette sélection.")
            return
        for case in cases:
            print(
                f"{case['id']} | {case['delivery_status']} | "
                f"{case['captured_at']:%Y-%m-%d %H:%M} | "
                f"{str(case['subject'] or '(sans objet)')[:60]}"
            )
        if not apply:
            print(
                f"\n{len(cases)} dossier(s) sélectionné(s). "
                "Relance avec --apply pour rejouer."
            )
            return
        for case in cases:
            report = await replay_case(
                pool,
                case["id"],
                fresh_evidence=fresh_evidence,
                encryption_key=load_key(settings.raw_eml_key_file),
            )
            print(f"rejoué : {_json(report)}")
        outcomes = {
            str(case["delivery_status"]): replay_outcome(
                str(case["delivery_status"]), decision_mode=settings.decision_mode
            )
            for case in cases
        }
        juges = sum(
            1 for case in cases if outcomes[str(case["delivery_status"])]["verdict_expected"]
        )
        print(f"\n{len(cases)} dossier(s) réobservé(s), dont {juges} qui seront rejugés.")
        for statut, outcome in sorted(outcomes.items()):
            if not outcome["verdict_expected"]:
                print(f"  « {statut} » : {outcome['explanation']}")
        if juges:
            print("Suis l'avancement dans les journaux du service verdict.")
    finally:
        await pool.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m sentimail_v3.supervision.replay",
        description=(
            "Rejoue un dossier avec les hooks et le Code a jour. "
            "Sans --apply, la commande se contente de lister la selection."
        ),
    )
    parser.add_argument(
        "selector",
        help=(
            "prefixe d'identifiant de message, ou un etat complet : "
            "held, delivered, captured, analyzing, deferred"
        ),
    )
    parser.add_argument(
        "--fresh-evidence",
        action="store_true",
        help=(
            "refait aussi les inspections externes (URL, pieces jointes) au lieu "
            "de reutiliser les resultats deja enregistres"
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=1,
        help=f"nombre maximum de dossiers, plafonne a {MAX_BATCH} (defaut : 1)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="execute reellement le rejeu",
    )
    arguments = parser.parse_args()
    asyncio.run(
        run(
            arguments.selector,
            fresh_evidence=arguments.fresh_evidence,
            limit=arguments.limit,
            apply=arguments.apply,
        )
    )


if __name__ == "__main__":
    main()
