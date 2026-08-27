from __future__ import annotations

import os
import unittest

import asyncpg
from sentimail_v3.supervision.replay import REPLAYABLE_STATUSES, replay_case, select_cases
from sentimail_v3.observation.storage import Store
from test_parser import RAW

SMTP = {
    "peer_ip": "172.20.0.11",
    "peer_port": 25,
    "helo": "mx.example",
    "protocol": "ESMTP",
    "tls": {},
    "authenticated": False,
    "mail_options": [],
    "rcpt_options": {},
}


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class ReplayIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        self.created: list[str] = []

    async def asyncTearDown(self) -> None:
        await self.pool.execute(
            "DELETE FROM messages WHERE id = ANY($1::uuid[])", self.created
        )
        await self.pool.close()

    async def _case(self, status: str, recipient: str) -> str:
        result = await Store(self.pool).capture(
            RAW, "bounce@sender.example", [recipient], SMTP
        )
        await self.pool.execute(
            "UPDATE messages SET delivery_status=$2 WHERE id=$1::uuid",
            result.message_id,
            status,
        )
        self.created.append(result.message_id)
        return result.message_id

    async def _add_failed_verdict(self, message_id: str) -> None:
        run_id = await self.pool.fetchval(
            """
            INSERT INTO verdict_runs (
                investigation_id, engine, model_name, prompt_version,
                status, attempts, response
            )
            SELECT id,'deepseek','deepseek-v4-pro','test','error',3,
                   '{"verdict":{"classification":"legitimate","delivery_decision":"deliver"}}'::jsonb
            FROM investigations WHERE message_id=$1::uuid
            RETURNING id
            """,
            message_id,
        )
        for attempt in (1, 2, 3):
            await self.pool.execute(
                """
                INSERT INTO verdict_llm_call_events (
                    verdict_run_id, message_id, attempt, status
                ) VALUES ($1,$2::uuid,$3,'error')
                """,
                run_id,
                message_id,
                attempt,
            )

    async def test_replay_frees_the_exhausted_attempts_and_keeps_the_trace(
        self,
    ) -> None:
        message_id = await self._case("held", "replay-held@example.org")
        await self._add_failed_verdict(message_id)

        report = await replay_case(self.pool, message_id)

        self.assertEqual(report["previous_delivery_status"], "held")
        self.assertEqual(report["previous_verdict"]["delivery_decision"], "deliver")
        self.assertEqual(
            await self.pool.fetchval(
                "SELECT delivery_status FROM messages WHERE id=$1::uuid", message_id
            ),
            "analyzing",
        )
        self.assertEqual(
            await self.pool.fetchval(
                """
                SELECT count(*) FROM verdict_runs vr
                JOIN investigations i ON i.id=vr.investigation_id
                WHERE i.message_id=$1::uuid
                """,
                message_id,
            ),
            0,
        )
        self.assertEqual(
            await self.pool.fetchval(
                "SELECT count(*) FROM verdict_llm_call_events WHERE message_id=$1::uuid",
                message_id,
            ),
            0,
        )
        audited = await self.pool.fetchval(
            """
            SELECT payload->>'previous_delivery_status' FROM audit_log
            WHERE action='case.replayed' AND payload->>'message_id'=$1
            ORDER BY id DESC LIMIT 1
            """,
            message_id,
        )
        self.assertEqual(audited, "held")

    async def test_the_case_is_observed_again_with_the_current_hooks(self) -> None:
        message_id = await self._case("held", "replay-observe@example.org")
        await self.pool.execute(
            """
            DELETE FROM clues WHERE investigation_id IN (
                SELECT id FROM investigations WHERE message_id=$1::uuid
            )
            """,
            message_id,
        )

        report = await replay_case(self.pool, message_id)

        self.assertTrue(report["reobserved"])
        self.assertGreater(
            await self.pool.fetchval(
                """
                SELECT count(*) FROM clues c
                JOIN investigations i ON i.id=c.investigation_id
                WHERE i.message_id=$1::uuid
                """,
                message_id,
            ),
            0,
        )
        self.assertEqual(
            await self.pool.fetchval(
                "SELECT count(*) FROM delivery_cases WHERE message_id=$1::uuid",
                message_id,
            ),
            1,
        )
        self.assertIsNotNone(
            await self.pool.fetchval(
                "SELECT investigation_id FROM delivery_cases WHERE message_id=$1::uuid",
                message_id,
            )
        )

    async def test_a_redacted_case_can_still_replay_its_judgment(self) -> None:
        message_id = await self._case("held", "replay-redacted@example.org")
        await self.pool.execute(
            "UPDATE messages SET raw_eml=NULL, redacted_at=now() WHERE id=$1::uuid",
            message_id,
        )
        report = await replay_case(self.pool, message_id)
        self.assertFalse(report["reobserved"])
        self.assertEqual(
            await self.pool.fetchval(
                "SELECT delivery_status FROM messages WHERE id=$1::uuid", message_id
            ),
            "analyzing",
        )

    async def test_evidence_is_kept_unless_explicitly_refreshed(self) -> None:
        message_id = await self._case("held", "replay-evidence@example.org")
        for key in ("a", "b"):
            await self.pool.execute(
                """
                INSERT INTO external_analyses (
                    message_id, subject_kind, subject_key, source, status, result
                ) VALUES ($1::uuid,'url',$2,'url-sandbox','ok','{}'::jsonb)
                """,
                message_id,
                key,
            )

        await replay_case(self.pool, message_id)
        self.assertEqual(
            await self.pool.fetchval(
                "SELECT count(*) FROM external_analyses WHERE message_id=$1::uuid",
                message_id,
            ),
            2,
        )

        await replay_case(self.pool, message_id, fresh_evidence=True)
        self.assertEqual(
            await self.pool.fetchval(
                "SELECT count(*) FROM external_analyses WHERE message_id=$1::uuid",
                message_id,
            ),
            0,
        )

    async def test_a_user_reply_is_never_replayed_as_a_case(self) -> None:
        message_id = await self._case("consumed", "replay-consumed@example.org")
        with self.assertRaises(ValueError):
            await replay_case(self.pool, message_id)
        self.assertEqual(
            await self.pool.fetchval(
                "SELECT delivery_status FROM messages WHERE id=$1::uuid", message_id
            ),
            "consumed",
        )

    async def test_selection_by_prefix_ignores_non_replayable_messages(self) -> None:
        message_id = await self._case("consumed", "replay-select@example.org")
        self.assertEqual(await select_cases(self.pool, message_id[:8], 5), [])
        self.assertNotIn("consumed", REPLAYABLE_STATUSES)


if __name__ == "__main__":
    unittest.main()

    async def test_replaying_a_delivered_message_never_reopens_it(self) -> None:
        # Invariant terminal : un message livré rejoué garde son état, pour que
        # release_original refuse (already_delivered) et ne double pas l'envoi.
        message_id = await self._case("delivered", "replay-delivered@example.org")
        report = await replay_case(self.pool, message_id, reobserve=False)
        self.assertTrue(report["terminal_kept"])
        self.assertEqual(
            await self.pool.fetchval(
                "SELECT delivery_status FROM messages WHERE id=$1::uuid", message_id
            ),
            "delivered",
        )
