"""Ce que MAIA peut consulter pour répondre, et pour qui.

Un assistant qui ne sait rien ne peut répondre qu'à ce qu'on lui met sous les
yeux. Pour qu'il réponde à « pourquoi as-tu retenu ce message ? » ou « qui
bloques-tu pour moi ? », il lui faut consulter la base — donc un moyen de le
faire sans jamais devenir un explorateur de boîtes.

La garantie tient en une règle, et elle n'est pas négociable : **le destinataire
n'est jamais un paramètre**. Il vient du jeton SMTP authentifié, il est injecté
par le code, et aucune formulation du modèle ne peut le changer. Un outil ne
sait pas répondre « pour quelqu'un d'autre », il ne sait répondre que pour la
personne qui écrit.

Deux autres bornes : ces outils lisent, ils n'écrivent jamais — toute action
passe par la politique déterministe — et ils ne servent aucun contenu de
message. Objet, expéditeur, date, verdict : de quoi comprendre une décision,
jamais de quoi lire le courrier.
"""

from __future__ import annotations

from typing import Any

import asyncpg
import httpx

from sentimail_v3.config import Settings
from sentimail_v3.code.knowledge import search as search_knowledge

MAX_ROWS = 20

TOOLS: dict[str, str] = {
    "pending_messages": "Les messages qui attendent encore ton avis.",
    "recent_messages": "Les derniers messages reçus et ce qu'ils sont devenus.",
    "explain_message": (
        "Pourquoi un message a été retenu ou livré. Paramètre : subject "
        "(un fragment de l'objet)."
    ),
    "my_rules": "Les listes et qualifications enregistrées pour toi.",
    "statistics": "Combien de messages reçus, livrés, retenus sur la période.",
    "mail_standards": (
        "Ce que disent les normes de la messagerie (RFC SPF, DKIM, DMARC, SMTP, "
        "ARC, désabonnement). Paramètre : question, formulée avec les termes "
        "techniques anglais des RFC (unsubscribe, alignment, envelope sender, "
        "header field) car les textes sont en anglais. Sert à expliquer, jamais "
        "à juger un message."
    ),
}


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def catalogue() -> str:
    return "\n".join(f"- {name} : {help_text}" for name, help_text in TOOLS.items())


async def run_tool(
    pool: asyncpg.Pool[Any],
    name: str,
    arguments: dict[str, Any],
    *,
    participant: str,
    client: httpx.AsyncClient | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Exécute un outil pour le seul destinataire authentifié."""
    if name not in TOOLS:
        return {"error": "outil inconnu", "available": sorted(TOOLS)}
    if not participant:
        return {"error": "aucun destinataire authentifié"}

    if name == "mail_standards":
        # Cette connaissance n'appartient à personne : elle est publique. Elle
        # reste néanmoins derrière l'authentification, comme le reste, et elle
        # explique sans jamais rien prouver sur un message.
        question = str(arguments.get("question") or "").strip()
        if len(question) < 3:
            return {"error": "précise ce que tu veux savoir"}
        passages = await search_knowledge(
            pool,
            question,
            client=client,
            base_url=settings.knowledge_embedding_url if settings else "",
            model=settings.knowledge_embedding_model if settings else "",
        )
        if not passages:
            return {
                "passages": [],
                "note": "aucun passage des normes ne correspond à cette question",
            }
        return {
            "passages": [
                {
                    "document": passage.title,
                    "section": passage.section,
                    "text": passage.body,
                    "url": passage.url,
                }
                for passage in passages
            ],
            "usage": "documentation citable, jamais une preuve sur un message",
        }

    if name == "pending_messages":
        rows = await pool.fetch(
            """
            SELECT m.subject, m.from_header, m.captured_at
            FROM messages m
            JOIN delivery_cases dc ON dc.message_id=m.id
            JOIN conversations c ON c.case_id=dc.id
            WHERE m.delivery_status='held'
              AND dc.state IN ('review_notice_pending','awaiting_reply')
              AND sentimail_same_client_mailbox(c.participant_email,$1)
            ORDER BY m.captured_at DESC LIMIT $2
            """,
            participant,
            MAX_ROWS,
        )
        return {
            "pending": [
                {
                    "subject": str(row["subject"] or "(sans objet)")[:120],
                    "sender": str(row["from_header"] or "")[:90],
                    "received": f"{row['captured_at']:%d/%m %H:%M}",
                }
                for row in rows
            ]
        }

    if name == "recent_messages":
        rows = await pool.fetch(
            """
            SELECT m.subject, m.from_header, m.delivery_status, m.captured_at
            FROM messages m
            WHERE EXISTS (
                SELECT 1 FROM unnest(m.envelope_recipients) recipient
                WHERE sentimail_same_client_mailbox(recipient,$1)
            )
            ORDER BY m.captured_at DESC LIMIT $2
            """,
            participant,
            MAX_ROWS,
        )
        return {
            "messages": [
                {
                    "subject": str(row["subject"] or "(sans objet)")[:120],
                    "sender": str(row["from_header"] or "")[:90],
                    "outcome": str(row["delivery_status"]),
                    "received": f"{row['captured_at']:%d/%m %H:%M}",
                }
                for row in rows
            ]
        }

    if name == "explain_message":
        fragment = str(arguments.get("subject") or "").strip()
        if len(fragment) < 3:
            return {"error": "précise un fragment de l'objet du message"}
        row = await pool.fetchrow(
            """
            SELECT m.id, m.subject, m.from_header, m.delivery_status
            FROM messages m
            WHERE m.subject ILIKE '%' || $2 || '%' ESCAPE '\\'
              AND EXISTS (
                  SELECT 1 FROM unnest(m.envelope_recipients) recipient
                  WHERE sentimail_same_client_mailbox(recipient,$1)
              )
            ORDER BY m.captured_at DESC LIMIT 1
            """,
            participant,
            _escape_like(fragment),
        )
        if row is None:
            return {"error": "aucun message de ta boîte ne correspond"}
        clues = await pool.fetch(
            """
            SELECT DISTINCT ON (c.clue_code) c.clue_code, c.direction, c.strength,
                   c.statement
            FROM clues c
            JOIN investigations i ON i.id=c.investigation_id
            WHERE i.message_id=$1 AND c.direction <> 'neutral'
            ORDER BY c.clue_code, c.strength DESC
            """,
            row["id"],
        )
        return {
            "subject": str(row["subject"] or "")[:120],
            "sender": str(row["from_header"] or "")[:90],
            "outcome": str(row["delivery_status"]),
            "evidence": [
                {
                    "clue_code": str(clue["clue_code"]),
                    "direction": str(clue["direction"]),
                    "strength": int(clue["strength"]),
                    "statement": str(clue["statement"] or "")[:200],
                }
                for clue in sorted(
                    clues, key=lambda value: -int(value["strength"])
                )[:12]
            ],
        }

    if name == "my_rules":
        policies = await pool.fetch(
            """
            SELECT scope, value_normalized, action, active
            FROM sender_policies
            WHERE sentimail_same_client(participant_email,$1)
            ORDER BY created_at DESC LIMIT $2
            """,
            participant,
            MAX_ROWS,
        )
        labels = await pool.fetch(
            """
            SELECT label, count(*) AS total
            FROM labels
            WHERE sentimail_same_client(participant_email,$1) AND active=true
            GROUP BY label
            """,
            participant,
        )
        return {
            "lists": [
                {
                    "sender": str(row["value_normalized"]),
                    "scope": (
                        "domaine entier" if row["scope"] == "domain" else "adresse"
                    ),
                    "list": "blanche" if row["action"] == "allow" else "noire",
                    "active": bool(row["active"]),
                }
                for row in policies
            ],
            "qualifications": {
                str(row["label"]): int(row["total"]) for row in labels
            },
        }

    row = await pool.fetchrow(
        """
        SELECT count(*) AS total,
               count(*) FILTER (WHERE delivery_status='delivered') AS delivered,
               count(*) FILTER (WHERE delivery_status='held') AS held,
               min(captured_at)::date AS since
        FROM messages m
        WHERE EXISTS (
            SELECT 1 FROM unnest(m.envelope_recipients) recipient
            WHERE sentimail_same_client_mailbox(recipient,$1)
        )
        """,
        participant,
    )
    return {
        "received": int(row["total"] or 0),
        "delivered": int(row["delivered"] or 0),
        "held": int(row["held"] or 0),
        "since": str(row["since"] or ""),
    }
