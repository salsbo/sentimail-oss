"""Un expéditeur que l'utilisateur a lui-même autorisé.

La liste blanche n'ouvre aucune porte : elle dit seulement que le bruit
habituel de ce correspondant ne mérite pas de question. Savoir si elle
s'applique sert donc à une seule chose ici — expliquer à l'utilisateur pourquoi
on le dérange malgré son autorisation.
"""

from __future__ import annotations

from email.utils import parseaddr
from typing import Any

import asyncpg


async def pool_trusts_sender(
    pool: asyncpg.Pool[Any], dossier: Any
) -> bool:
    """L'expéditeur de ce dossier figure-t-il en liste blanche active ?"""
    from_header = str(dossier["from_header"] or "")
    recipients = [str(value) for value in (dossier["envelope_recipients"] or [])]
    sender = parseaddr(from_header)[1].casefold()
    if not sender or not recipients:
        return False
    return bool(
        await pool.fetchval(
            """
            SELECT EXISTS (
                SELECT 1 FROM sender_policies
                WHERE active=true AND action='allow' AND scope='sender'
                  AND value_normalized=$1
                  AND EXISTS (
                      SELECT 1 FROM unnest($2::text[]) recipient
                      WHERE sentimail_same_client(participant_email,recipient)
                  )
            )
            """,
            sender,
            [value.casefold() for value in recipients],
        )
    )
