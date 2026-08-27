"""Ce que le rapport d'entretien compte comme anomalie, et ce qu'il ne doit pas.

Un dossier abandonné faute de réponse est un état voulu, décidé et tracé. Le
compter parmi les « messages retenus sans que tu en sois averti » transforme
une décision en incident : le rapport signale dix-huit anomalies là où il ne
s'est rien passé d'anormal, et le vrai signal - un avis qui n'est jamais parti -
se noie dedans.
"""

from __future__ import annotations

import os
import unittest

import asyncpg
from sentimail_v3.observation.storage import Store
from sentimail_v3.supervision.caretaker import collect
from test_parser import RAW

SMTP = {
    "peer_ip": "172.20.0.12",
    "peer_port": 25,
    "helo": "mx.example",
    "protocol": "ESMTP",
    "tls": {},
    "authenticated": False,
    "mail_options": [],
    "rcpt_options": {},
}


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class RetenuesSansAvisTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        self.created: list[str] = []

    async def asyncTearDown(self) -> None:
        await self.pool.execute(
            "DELETE FROM messages WHERE id = ANY($1::uuid[])", self.created
        )
        await self.pool.close()

    async def _hold(self, state: str) -> str:
        result = await Store(self.pool).capture(
            RAW, "bounce@sender.example", [f"caretaker-{state}@example.org"], SMTP
        )
        self.created.append(result.message_id)
        await self.pool.execute(
            "UPDATE messages SET delivery_status='held' WHERE id=$1::uuid",
            result.message_id,
        )
        await self.pool.execute(
            "UPDATE delivery_cases SET state=$2 WHERE message_id=$1::uuid",
            result.message_id,
            state,
        )
        return result.message_id

    async def test_un_dossier_abandonne_n_est_pas_une_anomalie(self) -> None:
        avant = (await collect(self.pool))["retenues_sans_avis"]
        await self._hold("ignored")
        self.assertEqual((await collect(self.pool))["retenues_sans_avis"], avant)

    async def test_une_retenue_vraiment_muette_reste_signalee(self) -> None:
        # Le signal doit continuer d'exister : un dossier retenu dans un état
        # qui n'attend rien et n'a rien envoyé est une vraie anomalie.
        avant = (await collect(self.pool))["retenues_sans_avis"]
        await self._hold("analysis_pending")
        self.assertEqual((await collect(self.pool))["retenues_sans_avis"], avant + 1)


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class RetenuesNonProtegeesTests(unittest.IsolatedAsyncioTestCase):
    """Le superviseur veille sur les retenues vivantes, pas sur les abandons.

    Ses deux compteurs cherchent la trace d'un avis parti. Un dossier abandonné
    avant que le sien ne parte n'en aura jamais : le message reste « retenu »
    pour toujours, et l'alerte qu'il déclenche ne pourra plus jamais
    s'éteindre - alors que le dossier, lui, est clos.
    """

    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        self.created: list[str] = []

    async def asyncTearDown(self) -> None:
        await self.pool.execute(
            "DELETE FROM messages WHERE id = ANY($1::uuid[])", self.created
        )
        await self.pool.close()

    async def _hold_sans_avis(self, state: str) -> str:
        result = await Store(self.pool).capture(
            RAW, "bounce@sender.example", [f"guard-{state}@example.org"], SMTP
        )
        self.created.append(result.message_id)
        await self.pool.execute(
            "UPDATE messages SET delivery_status='held' WHERE id=$1::uuid",
            result.message_id,
        )
        await self.pool.execute(
            """
            UPDATE delivery_cases SET state=$2, updated_at=now()-interval '20 minutes'
            WHERE message_id=$1::uuid
            """,
            result.message_id,
            state,
        )
        return result.message_id

    async def _compteurs(self) -> tuple[int, int]:
        from sentimail_v3.supervision.watchdog import REVIEW_GUARD_SQL

        row = await self.pool.fetchrow(REVIEW_GUARD_SQL)
        return int(row["unprotected_holds"]), int(row["silent_holds"])

    async def test_un_dossier_abandonne_ne_reste_pas_en_alerte(self) -> None:
        avant = await self._compteurs()
        await self._hold_sans_avis("ignored")
        self.assertEqual(await self._compteurs(), avant)

    async def test_une_retenue_vivante_sans_avis_alerte_toujours(self) -> None:
        avant = await self._compteurs()
        await self._hold_sans_avis("awaiting_reply")
        apres = await self._compteurs()
        self.assertEqual(apres, (avant[0] + 1, avant[1] + 1))
