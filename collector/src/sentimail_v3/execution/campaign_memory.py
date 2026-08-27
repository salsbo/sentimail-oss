"""Mémoire des gabarits de campagne, en local pur.

On enregistre l'empreinte de squelette des messages qualifiés (par l'humain ou
classés en indésirable à haute confiance) ; un message entrant dont le
squelette correspond porte alors le label de la campagne source. La
correspondance passe par un index LSH : les clés de bande d'un message proche
recoupent celles d'un gabarit appris, ce qui évite de comparer à toute la base.

Le résultat n'est jamais un verdict : il propage le LABEL et le score vers le
juge. Un même squelette peut être partagé par des expéditeurs honnêtes (un
gabarit d'ESP) ; c'est le label appris qui informe, pas la ressemblance seule.
"""

from __future__ import annotations

from typing import Any

import asyncpg

from sentimail_v3.code.template_fingerprint import (
    band_keys,
    dom_minhash,
    jaccard,
    subject_template,
)

# Deux squelettes sont « la même campagne » au-delà de ce seuil de Jaccard.
# Assez haut pour ne pas confondre deux emails du même ESP aux contenus
# distincts, assez bas pour tolérer la personnalisation.
_MATCH_THRESHOLD = 0.8


async def _fingerprint(
    pool: asyncpg.Pool[Any], message_id: str
) -> tuple[list[int], str] | None:
    row = await pool.fetchrow(
        "SELECT subject, body_html FROM messages WHERE id=$1::uuid", message_id
    )
    if row is None:
        return None
    signature = dom_minhash(str(row["body_html"] or ""))
    if signature is None:
        return None
    return signature, subject_template(str(row["subject"] or ""))


async def remember_campaign(
    pool: asyncpg.Pool[Any], message_id: str, label: str
) -> bool:
    """Enregistre le gabarit d'un message qualifié. Faux si trop pauvre."""
    fingerprint = await _fingerprint(pool, message_id)
    if fingerprint is None:
        return False
    signature, subject = fingerprint
    async with pool.acquire() as connection, connection.transaction():
        fingerprint_id = await connection.fetchval(
            """
            INSERT INTO template_fingerprints (message_id, label, signature,
                subject_template)
            VALUES ($1::uuid, $2, $3, $4) RETURNING id
            """,
            message_id,
            label,
            signature,
            subject,
        )
        await connection.execute(
            """
            INSERT INTO template_lsh_buckets (fingerprint_id, band_key)
            SELECT $1, unnest($2::text[])
            """,
            fingerprint_id,
            band_keys(signature),
        )
    return True


async def match_campaign(
    pool: asyncpg.Pool[Any], message_id: str
) -> dict[str, object] | None:
    """Le label de la campagne dont ce message reprend le gabarit, ou None."""
    fingerprint = await _fingerprint(pool, message_id)
    if fingerprint is None:
        return None
    signature, subject = fingerprint
    candidates = await pool.fetch(
        """
        SELECT DISTINCT f.id, f.label, f.signature, f.subject_template
        FROM template_lsh_buckets b
        JOIN template_fingerprints f ON f.id=b.fingerprint_id
        WHERE b.band_key = ANY($1::text[])
        """,
        band_keys(signature),
    )
    best: dict[str, object] | None = None
    for candidate in candidates:
        score = jaccard(signature, list(candidate["signature"]))
        if score < _MATCH_THRESHOLD:
            continue
        if best is None or score > float(best["jaccard"]):
            best = {
                "label": str(candidate["label"]),
                "jaccard": round(score, 3),
                "same_subject": bool(
                    subject and subject == str(candidate["subject_template"] or "")
                ),
            }
    return best
