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


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class RetenuesFermeesTests(unittest.IsolatedAsyncioTestCase):
    """Une retenue fermée par le secours reste en alerte tant que rien ne la conclut.

    Chaque retentative réhorodate le dossier : le compteur ne regarde donc pas
    l'heure. Il retombe quand l'avis part, quand le dossier est abandonné, ou
    quand le message quitte la retenue.
    """

    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        self.created: list[str] = []
        self.participants: list[str] = []

    async def asyncTearDown(self) -> None:
        await self.pool.execute(
            "DELETE FROM messages WHERE id = ANY($1::uuid[])", self.created
        )
        await self.pool.execute(
            "DELETE FROM conversations WHERE participant_email = ANY($1::text[])",
            self.participants,
        )
        await self.pool.close()

    async def _retenue_fermee(
        self, state: str, avis: tuple[str, int] | None = None
    ) -> tuple[str, str | None]:
        participant = f"ferme-{state}-{len(self.created)}@dest.example"
        result = await Store(self.pool).capture(
            RAW, "rebond@exp.example", [participant], SMTP
        )
        self.created.append(result.message_id)
        self.participants.append(participant)
        await self.pool.execute(
            "UPDATE messages SET delivery_status='held' WHERE id=$1::uuid",
            result.message_id,
        )
        case_id = await self.pool.fetchval(
            """
            UPDATE delivery_cases SET state=$2, updated_at=now(),
                details=details
                  || '{"review_guard":"fail_closed","review_guard_attempts":1}'::jsonb
            WHERE message_id=$1::uuid RETURNING id
            """,
            result.message_id,
            state,
        )
        if avis is None:
            return result.message_id, None
        conversation_id = await self.pool.fetchval(
            """
            INSERT INTO conversations (case_id,participant_email,status)
            VALUES ($1,$2,'awaiting_user') RETURNING id
            """,
            case_id,
            participant,
        )
        action_id = await self.pool.fetchval(
            """
            INSERT INTO smtp_actions (case_id,action,token_hash,reply_address,expires_at)
            VALUES ($1,'release_original',NULL,'maia@sentinel.dest.example',
                    now()+interval '30 days')
            RETURNING id
            """,
            case_id,
        )
        outbox_id = await self.pool.fetchval(
            """
            INSERT INTO assistant_outbox (
                conversation_id,action_id,recipient,sender,reply_to,subject,
                body_text,status,attempts
            ) VALUES ($1,$2,$3,'maia@dest.example','maia@sentinel.dest.example',
                      '[SentiMail] Ton avis','corps',$4,$5)
            RETURNING id::text
            """,
            conversation_id,
            action_id,
            participant,
            avis[0],
            avis[1],
        )
        return result.message_id, str(outbox_id)

    async def _fermees(self) -> int:
        from sentimail_v3.supervision.watchdog import FAIL_CLOSED_SQL

        return int(await self.pool.fetchval(FAIL_CLOSED_SQL))

    async def test_une_retenue_fermee_reste_en_alerte_jusqu_a_l_avis(self) -> None:
        avant = await self._fermees()
        await self._retenue_fermee("review_notice_pending")
        self.assertEqual(await self._fermees(), avant + 1)

    async def test_une_retenue_fermee_abandonnee_ne_sonne_plus(self) -> None:
        avant = await self._fermees()
        await self._retenue_fermee("ignored")
        self.assertEqual(await self._fermees(), avant)

    async def test_une_retenue_fermee_dont_l_avis_est_parti_ne_sonne_plus(self) -> None:
        avant = await self._fermees()
        await self._retenue_fermee("awaiting_reply", avis=("sent", 1))
        self.assertEqual(await self._fermees(), avant)

    async def test_la_reconciliation_ne_reprend_pas_un_avis_epuise_ferme(self) -> None:
        from types import SimpleNamespace
        from unittest.mock import AsyncMock, patch

        from sentimail_v3.execution.review_guard import reconcile_one_review_hold

        message_id, outbox_id = await self._retenue_fermee(
            "awaiting_reply", avis=("error", 5)
        )
        # Dans une transaction annulée à la fin : d'autres dossiers de la base
        # de test pourraient être éligibles, et le passage ne doit rien y écrire.
        async with self.pool.acquire() as connection:
            transaction = connection.transaction()
            await transaction.start()
            try:
                with patch(
                    "sentimail_v3.execution.review_guard.hold_with_review_or_fail_open",
                    new=AsyncMock(return_value="review_notice_queued"),
                ) as recreer, patch(
                    "sentimail_v3.execution.review_guard.fail_open_held_message",
                    new=AsyncMock(return_value="held_fail_closed"),
                ) as secours:
                    await reconcile_one_review_hold(
                        connection,  # type: ignore[arg-type]
                        SimpleNamespace(),  # type: ignore[arg-type]
                        SimpleNamespace(queue_invitation=AsyncMock()),  # type: ignore[arg-type]
                    )
                ligne = await connection.fetchrow(
                    "SELECT status,attempts,last_error FROM assistant_outbox WHERE id=$1::uuid",
                    outbox_id,
                )
            finally:
                await transaction.rollback()

        vises = [
            str(call.args[-1]) for call in recreer.await_args_list
        ] + [str(call.args[2]) for call in secours.await_args_list]
        self.assertNotIn(message_id, vises)
        self.assertEqual((ligne["status"], ligne["attempts"]), ("error", 5))
        self.assertIsNone(ligne["last_error"])
