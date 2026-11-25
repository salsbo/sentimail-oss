from __future__ import annotations

import os
import unittest
import uuid
from types import SimpleNamespace

import asyncpg
from sentimail_v3.execution.hold_lifecycle import (
    abandon_participant_holds,
    remind_stale_holds,
    run_hold_lifecycle,
    settle_expired_holds,
)
from sentimail_v3.observation.storage import Store
from sentimail_v3.judgment.verdict_engine import (
    JudgmentContradiction,
    _validate_final_judgment,
    waiting_judgment,
)
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


class StructuralContradictionTests(unittest.TestCase):
    def _dossier(self, **rules: object) -> dict[str, object]:
        return {
            "judgment_rules": {
                "verdict_is_final": True,
                "confidence_required": 0.9,
                "deep_execution_complete": True,
                "static_investigation_complete": True,
                "material_danger_evidence": [],
                "authenticated_sender_policy": "none",
                **rules,
            }
        }

    def _judgment(self) -> dict[str, object]:
        return {
            "delivery_decision": "deliver",
            "classification": "legitimate",
            "confidence": 0.95,
            "verdict_doubt": False,
            "uncertainties": [],
        }

    def test_an_incomplete_analysis_is_a_structural_contradiction(self) -> None:
        with self.assertRaises(JudgmentContradiction) as raised:
            _validate_final_judgment(
                self._judgment(), self._dossier(deep_execution_complete=False)
            )
        self.assertTrue(raised.exception.structural)
        self.assertIn("deep_execution_incomplete", raised.exception.contradictions)

    def test_a_confidence_below_the_threshold_is_not_structural(self) -> None:
        judgment = {**self._judgment(), "confidence": 0.5}
        with self.assertRaises(JudgmentContradiction) as raised:
            _validate_final_judgment(judgment, self._dossier())
        self.assertFalse(raised.exception.structural)

    def test_a_rejected_judgment_becomes_a_request_for_advice(self) -> None:
        with self.assertRaises(JudgmentContradiction) as raised:
            _validate_final_judgment(
                self._judgment(), self._dossier(material_danger_evidence=[{"x": 1}])
            )
        waiting = waiting_judgment(raised.exception)
        self.assertEqual(waiting["delivery_decision"], "ask_user")
        self.assertTrue(waiting["verdict_doubt"])
        self.assertNotEqual(waiting["classification"], "legitimate")
        self.assertIn("material_danger_unresolved", waiting["uncertainties"])
        # Le jugement d'attente doit lui-même être valide.
        _validate_final_judgment(
            waiting, self._dossier(material_danger_evidence=[{"x": 1}])
        )


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class HoldLifecycleIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        self.created: list[str] = []
        self.settings = SimpleNamespace(
            hold_lifecycle_enabled=True,
            hold_reminder_after_days=3,
            hold_decision_after_days=7,
            assistant_sender="MAIA <maia@example.org>",
            action_address="maia@example.org",
            action_aliases=(),
            probe_recipient="",
            authorized_user_address="user@example.org",
            assistant_token_secret="x" * 32,
            relay_host="relay.invalid",
            relay_port=25,
        )

    async def asyncTearDown(self) -> None:
        await self.pool.execute(
            "DELETE FROM messages WHERE id = ANY($1::uuid[])", self.created
        )
        await self.pool.close()

    async def _held_case(
        self, age_days: int, classification: str, participant: str | None = None
    ) -> str:
        participant = participant or f"hold-{age_days}-{classification}@example.org"
        # Un Message-ID par dossier : la capture reconnaît un même message
        # reçu deux fois pour le même destinataire et rend le dossier existant.
        raw = RAW.replace(
            b"<sample@sender.example>", f"<{uuid.uuid4()}@sender.example>".encode()
        )
        result = await Store(self.pool).capture(
            raw, "bounce@sender.example", [participant], SMTP
        )
        self.created.append(result.message_id)
        await self.pool.execute(
            """
            UPDATE messages SET delivery_status='held',
                captured_at=now() - ($2 * interval '1 day')
            WHERE id=$1::uuid
            """,
            result.message_id,
            age_days,
        )
        case_id = await self.pool.fetchval(
            """
            UPDATE delivery_cases SET state='awaiting_reply',
                original_delivery_allowed=false, binding=true
            WHERE message_id=$1::uuid RETURNING id
            """,
            result.message_id,
        )
        await self.pool.execute(
            """
            INSERT INTO conversations (case_id, participant_email, status)
            VALUES ($1,$2,'awaiting_user')
            """,
            case_id,
            participant,
        )
        await self.pool.execute(
            """
            INSERT INTO verdict_runs (
                investigation_id, engine, model_name, prompt_version, status,
                response, completed_at
            )
            SELECT id,'llm','test','test','complete',
                   jsonb_build_object('verdict',
                       jsonb_build_object('classification',$2::text)), now()
            FROM investigations WHERE message_id=$1::uuid
            """,
            result.message_id,
            classification,
        )
        return result.message_id

    async def test_a_forgotten_hold_is_reminded_once_per_window(self) -> None:
        message_id = await self._held_case(5, "suspect")
        self.assertEqual(await remind_stale_holds(self.pool, self.settings), 1)
        self.assertEqual(await remind_stale_holds(self.pool, self.settings), 0)
        queued = await self.pool.fetchval(
            """
            SELECT count(*) FROM assistant_outbox ao
            JOIN smtp_actions sa ON sa.id=ao.action_id
            JOIN delivery_cases dc ON dc.id=sa.case_id
            WHERE dc.message_id=$1::uuid
            """,
            message_id,
        )
        self.assertEqual(queued, 1)
        self.assertEqual(
            await self.pool.fetchval(
                "SELECT delivery_status FROM messages WHERE id=$1::uuid", message_id
            ),
            "held",
        )

    async def _courriers(self, message_ids: list[str]) -> list[int]:
        return [
            int(await self.pool.fetchval(
                """
                SELECT count(*) FROM assistant_outbox ao
                JOIN smtp_actions sa ON sa.id=ao.action_id
                JOIN delivery_cases dc ON dc.id=sa.case_id
                WHERE dc.message_id=$1::uuid
                """,
                message_id,
            ))
            for message_id in message_ids
        ]

    async def test_trois_retenues_font_trois_courriers(self) -> None:
        """Décision du 15 octobre 2026 : jamais un bulletin pour plusieurs messages."""
        participant = "trois-retenues@example.org"
        ids = [await self._held_case(5, "suspect", participant) for _ in range(3)]
        settings = SimpleNamespace(**vars(self.settings), digest_enabled=False)
        await run_hold_lifecycle(self.pool, settings)
        self.assertEqual(await self._courriers(ids), [1, 1, 1])

    async def test_un_destinataire_qui_refuse_les_relances_n_en_recoit_aucune(self) -> None:
        participant = "sans-relance@example.org"
        message_id = await self._held_case(5, "suspect", participant)
        await self.pool.execute(
            """
            INSERT INTO participant_preferences (participant_email, name, value)
            VALUES ($1, 'hold_reminders_enabled', 'false'::jsonb)
            ON CONFLICT (participant_email, name) DO UPDATE SET value='false'::jsonb
            """,
            participant,
        )
        try:
            await remind_stale_holds(self.pool, self.settings)
            self.assertEqual(await self._courriers([message_id]), [0])
        finally:
            await self.pool.execute(
                "DELETE FROM participant_preferences WHERE participant_email=$1",
                participant,
            )

    async def test_vider_la_file_d_un_destinataire_abandonne_sans_courrier(self) -> None:
        participant = "file-videe@example.org"
        siens = [await self._held_case(age, "suspect", participant) for age in (0, 4)]
        autre = await self._held_case(4, "suspect", "autre-file@example.org")
        self.assertEqual(
            await abandon_participant_holds(self.pool, "File-Videe@example.org"), 2
        )
        for message_id in siens:
            etat = await self._etat(message_id)
            self.assertEqual(etat["state"], "ignored")
            self.assertEqual(etat["delivery_status"], "held")
        self.assertEqual((await self._etat(autre))["state"], "awaiting_reply")
        self.assertEqual(await self._courriers(siens), [0, 0])
        raisons = await self.pool.fetch(
            """
            SELECT payload->>'reason' AS reason FROM audit_log
            WHERE action='hold.ignored_without_reply'
              AND payload->>'message_id' = ANY($1::text[])
            """,
            siens,
        )
        self.assertEqual({row["reason"] for row in raisons}, {"operator_cleared_queue"})

    async def test_a_recent_hold_is_left_alone(self) -> None:
        await self._held_case(1, "suspect")
        self.assertEqual(await remind_stale_holds(self.pool, self.settings), 0)

    async def test_an_old_exchange_does_not_freeze_a_hold_forever(self) -> None:
        message_id = await self._held_case(9, "suspect")
        conversation_id = await self.pool.fetchval(
            """
            SELECT c.id FROM conversations c
            JOIN delivery_cases dc ON dc.id=c.case_id
            WHERE dc.message_id=$1::uuid
            """,
            message_id,
        )
        await self.pool.execute(
            """
            INSERT INTO conversation_messages (
                conversation_id, direction, body_text, user_text,
                processing_status, created_at
            ) VALUES ($1,'inbound','ancienne question','C ?', 'complete',
                      now()-interval '8 days')
            """,
            conversation_id,
        )
        self.assertEqual(await remind_stale_holds(self.pool, self.settings), 1)

    async def test_a_fresh_reply_suspends_the_reminder(self) -> None:
        message_id = await self._held_case(9, "suspect")
        conversation_id = await self.pool.fetchval(
            """
            SELECT c.id FROM conversations c
            JOIN delivery_cases dc ON dc.id=c.case_id
            WHERE dc.message_id=$1::uuid
            """,
            message_id,
        )
        await self.pool.execute(
            """
            INSERT INTO conversation_messages (
                conversation_id, direction, body_text, user_text, processing_status
            ) VALUES ($1,'inbound','je regarde','C je regarde','complete')
            """,
            conversation_id,
        )
        self.assertEqual(await remind_stale_holds(self.pool, self.settings), 0)

    async def _etat(self, message_id: str) -> asyncpg.Record:
        return await self.pool.fetchrow(
            """
            SELECT m.delivery_status, dc.state, dc.original_delivery_allowed
            FROM messages m JOIN delivery_cases dc ON dc.message_id=m.id
            WHERE m.id=$1::uuid
            """,
            message_id,
        )

    async def test_a_dangerous_hold_expires_without_delivery(self) -> None:
        message_id = await self._held_case(10, "dangerous")
        self.assertEqual(await settle_expired_holds(self.pool, self.settings), 1)
        row = await self._etat(message_id)
        self.assertEqual(row["delivery_status"], "held")
        self.assertEqual(row["state"], "ignored")
        self.assertFalse(row["original_delivery_allowed"])

    async def test_a_suspect_hold_is_never_delivered_by_silence(self) -> None:
        """Le cœur de la règle : ne pas répondre n'autorise rien.

        L'échéance livrait tout ce qui n'était pas dangereux. Un faux CIC ou
        un faux OVHcloud que personne n'avait réclamé finissait donc dans la
        boîte, par le seul effet du temps qui passe.
        """
        message_id = await self._held_case(10, "suspect")
        self.assertEqual(await settle_expired_holds(self.pool, self.settings), 1)
        row = await self._etat(message_id)
        self.assertEqual(row["delivery_status"], "held")
        self.assertEqual(row["state"], "ignored")
        self.assertFalse(row["original_delivery_allowed"])

    async def test_an_ignored_hold_teaches_nothing(self) -> None:
        """Un silence n'est pas un avis : il ne qualifie ni n'entraîne rien."""
        message_id = await self._held_case(10, "suspect")
        await settle_expired_holds(self.pool, self.settings)
        for table, colonne in (
            ("labels", "message_id"),
            ("training_samples", "message_id"),
        ):
            with self.subTest(table=table):
                self.assertEqual(
                    await self.pool.fetchval(
                        f"SELECT count(*) FROM {table} WHERE {colonne}=$1::uuid",
                        message_id,
                    ),
                    0,
                )
        self.assertEqual(
            await self.pool.fetchval(
                """
                SELECT count(*) FROM sender_policies
                WHERE source LIKE '%hold%' OR source LIKE '%expired%'
                """
            ),
            0,
        )

    async def test_the_abandonment_is_traced(self) -> None:
        message_id = await self._held_case(10, "suspect")
        await settle_expired_holds(self.pool, self.settings)
        raison = await self.pool.fetchval(
            """
            SELECT payload->>'reason' FROM audit_log
            WHERE action='hold.ignored_without_reply'
              AND payload->>'message_id'=$1
            ORDER BY id DESC LIMIT 1
            """,
            message_id,
        )
        self.assertEqual(raison, "no_human_reply_is_not_a_signal")

    async def test_no_letter_announces_a_decision_nobody_took(self) -> None:
        """Plus de courrier d'arbitrage : il annonçait une livraison abolie."""
        message_id = await self._held_case(10, "suspect")
        await settle_expired_holds(self.pool, self.settings)
        self.assertEqual(
            await self.pool.fetchval(
                """
                SELECT count(*) FROM assistant_outbox ao
                JOIN smtp_actions sa ON sa.id=ao.action_id
                JOIN delivery_cases dc ON dc.id=sa.case_id
                WHERE dc.message_id=$1::uuid
                """,
                message_id,
            ),
            0,
        )

    async def test_a_hold_within_the_window_is_left_alone(self) -> None:
        message_id = await self._held_case(3, "suspect")
        self.assertEqual(await settle_expired_holds(self.pool, self.settings), 0)
        self.assertEqual((await self._etat(message_id))["state"], "awaiting_reply")

    async def test_an_ignored_case_keeps_its_unlabelled_solicitation(self) -> None:
        """Le silence ne retire pas un avis envoyé et ne crée aucun label."""
        from sentimail_v3.supervision.evaluation_report import collect

        message_id = await self._held_case(10, "suspect")
        await self.pool.execute(
            """INSERT INTO delivery_events(case_id,event_type)
               SELECT id,'review_notice_delivered' FROM delivery_cases
               WHERE message_id=$1::uuid""", message_id,
        )
        avant = await collect(self.pool)
        self.assertGreaterEqual(
            sum(ligne["total"] for ligne in avant["coverage"].values()),
            1,
            "le dossier doit d'abord être compté, sinon le test ne prouve rien",
        )
        await settle_expired_holds(self.pool, self.settings)
        apres = await collect(self.pool)
        def total(rapport: dict) -> int:
            return sum(
                ligne["total"] for ligne in rapport["coverage"].values()
            )

        self.assertEqual(total(apres), total(avant), message_id)
        self.assertEqual(apres["matrix"]["rows"]["ask_user"]["labelled"],
                         avant["matrix"]["rows"]["ask_user"]["labelled"])
        self.assertEqual(apres["population"]["ignored_with_notice"],
                         avant["population"]["ignored_with_notice"] + 1)


if __name__ == "__main__":
    unittest.main()
