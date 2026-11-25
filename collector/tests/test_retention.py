from __future__ import annotations

import asyncio
import os
import unittest
from types import SimpleNamespace

import asyncpg
from sentimail_v3.execution.retention import (
    delete_expired,
    redact_expired,
    redact_expired_conversations,
    validate_windows,
)
from sentimail_v3.code.rulebook import render_rulebook
from sentimail_v3.observation.storage import Store
from test_parser import RAW

SMTP = {
    "peer_ip": "172.20.0.9",
    "peer_port": 25,
    "helo": "mx.example",
    "protocol": "ESMTP",
    "tls": {},
    "authenticated": False,
    "mail_options": [],
    "rcpt_options": {},
}


class RetentionWindowTests(unittest.TestCase):
    def _settings(self, redact: int, delete: int) -> SimpleNamespace:
        return SimpleNamespace(
            retention_redact_after_days=redact,
            retention_delete_after_days=delete,
        )

    def test_default_windows_are_accepted(self) -> None:
        validate_windows(self._settings(30, 180))

    def test_a_too_short_window_is_refused_before_any_write(self) -> None:
        with self.assertRaises(ValueError):
            validate_windows(self._settings(1, 180))

    def test_deletion_may_not_precede_redaction(self) -> None:
        with self.assertRaises(ValueError):
            validate_windows(self._settings(30, 10))


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class RetentionIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        self.created_messages: list[str] = []
        self.created_conversations: list[str] = []

    async def asyncTearDown(self) -> None:
        # Les autres tests d'intégration comptent les lignes : la rétention ne
        # doit rien laisser derrière elle.
        await self.pool.execute(
            "DELETE FROM labels WHERE participant_email LIKE 'retention-%'"
        )
        await self.pool.execute(
            "DELETE FROM messages WHERE id = ANY($1::uuid[])", self.created_messages
        )
        await self.pool.execute(
            "DELETE FROM conversations WHERE id = ANY($1::uuid[])",
            self.created_conversations,
        )
        await self.pool.close()

    async def _aged_message(self, days: int, status: str) -> str:
        store = Store(self.pool)
        recipient = f"retention-{days}-{status}@example.org"
        result = await store.capture(
            RAW, "bounce@sender.example", [recipient], SMTP
        )
        await self.pool.execute(
            """
            UPDATE messages
            SET captured_at = now() - ($2 * interval '1 day'), delivery_status=$3
            WHERE id=$1::uuid
            """,
            result.message_id,
            days,
            status,
        )
        self.created_messages.append(result.message_id)
        return result.message_id

    async def test_an_encrypted_original_is_stored_and_read_back(self) -> None:
        from sentimail_v3.crypto import encrypt, is_encrypted

        key = bytes(range(32))
        store = Store(self.pool, key)
        result = await store.capture(
            RAW, "bounce@sender.example", ["retention-crypto@example.org"], SMTP
        )
        self.created_messages.append(result.message_id)
        row = await self.pool.fetchrow(
            "SELECT raw_eml, raw_eml_encryption, raw_sha256 FROM messages WHERE id=$1::uuid",
            result.message_id,
        )
        self.assertTrue(is_encrypted(bytes(row["raw_eml"])))
        self.assertEqual(row["raw_eml_encryption"], "aes-256-gcm-v1")
        # L'empreinte reste celle du message original, pas du chiffré.
        import hashlib

        self.assertEqual(row["raw_sha256"], hashlib.sha256(RAW).hexdigest())
        self.assertNotIn(b"Subject", bytes(row["raw_eml"]))
        self.assertTrue(await store.reinvestigate(result.message_id))
        self.assertNotEqual(encrypt(RAW, key), bytes(row["raw_eml"]))

    async def test_open_cases_keep_their_original_content(self) -> None:
        message_id = await self._aged_message(400, "held")
        await redact_expired(self.pool, 30, 100)
        row = await self.pool.fetchrow(
            "SELECT raw_eml, redacted_at FROM messages WHERE id=$1::uuid",
            message_id,
        )
        self.assertIsNotNone(row["raw_eml"])
        self.assertIsNone(row["redacted_at"])

    async def test_un_abandon_est_purge_sans_toucher_une_retenue_active(self) -> None:
        from sentimail_v3.execution.retention import OPEN_STATUSES, RETENTION_ELIGIBLE_SQL

        abandon = await self._aged_message(400, "held")
        actif = await self._aged_message(401, "held")
        await self.pool.execute(
            "UPDATE delivery_cases SET state='ignored' WHERE message_id=$1::uuid",
            abandon,
        )
        await self.pool.execute(
            "UPDATE delivery_cases SET state='awaiting_reply' WHERE message_id=$1::uuid",
            actif,
        )
        # La sonde et la purge partagent exactement les mêmes dossiers éligibles.
        overdue = await self.pool.fetchval(
            f"""SELECT count(*) FROM messages m
                WHERE m.id=ANY($3::uuid[]) AND m.redacted_at IS NULL
                  AND m.captured_at < now()-(($1+2)*interval '1 day')
                  AND {RETENTION_ELIGIBLE_SQL}""",
            30, OPEN_STATUSES, [abandon, actif],
        )
        self.assertEqual(overdue, 1)
        await redact_expired(self.pool, 30, 100)
        self.assertIsNone(await self.pool.fetchval(
            "SELECT raw_eml FROM messages WHERE id=$1::uuid", abandon
        ))
        self.assertIsNotNone(await self.pool.fetchval(
            "SELECT raw_eml FROM messages WHERE id=$1::uuid", actif
        ))
        await delete_expired(self.pool, 180, 100)
        self.assertFalse(await self.pool.fetchval(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE id=$1::uuid)", abandon
        ))
        self.assertTrue(await self.pool.fetchval(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE id=$1::uuid)", actif
        ))

    async def test_une_liberation_reservee_conserve_son_original(self) -> None:
        message = await self._aged_message(400, "held")
        await self.pool.execute(
            "UPDATE delivery_cases SET state='ignored' WHERE message_id=$1::uuid", message
        )
        async with self.pool.acquire() as release_connection, release_connection.transaction():
            # Même réservation que release_original, gardée ouverte pendant la
            # passe de rétention pour exposer l'ancien état encore visible.
            await release_connection.fetchrow(
                """SELECT m.id FROM messages m
                   JOIN delivery_cases dc ON dc.message_id=m.id
                   WHERE m.id=$1::uuid FOR UPDATE OF m,dc""", message
            )
            await release_connection.execute(
                "UPDATE messages SET delivery_status='release_pending' WHERE id=$1::uuid", message
            )
            await release_connection.execute(
                "UPDATE delivery_cases SET state='release_requested' WHERE message_id=$1::uuid", message
            )
            await asyncio.wait_for(redact_expired(self.pool, 30, 100), timeout=2)
        row = await self.pool.fetchrow(
            "SELECT raw_eml,redacted_at,delivery_status FROM messages WHERE id=$1::uuid", message
        )
        self.assertEqual(row["delivery_status"], "release_pending")
        self.assertIsNotNone(row["raw_eml"])
        self.assertIsNone(row["redacted_at"])

    async def test_un_dossier_verrouille_ne_cree_pas_de_cycle_de_verrous(self) -> None:
        message = await self._aged_message(400, "held")
        await self.pool.execute(
            "UPDATE delivery_cases SET state='ignored' WHERE message_id=$1::uuid", message
        )
        case_reserved = asyncio.Event()
        retention_finished = asyncio.Event()

        async def reserve_release() -> None:
            async with self.pool.acquire() as connection, connection.transaction():
                # Un autre chemin peut modifier le dossier avant le message.
                # La rétention doit le sauter, sans attendre son second verrou.
                await connection.execute(
                    "UPDATE delivery_cases SET state='release_requested' WHERE message_id=$1::uuid", message
                )
                case_reserved.set()
                await retention_finished.wait()
                await connection.execute(
                    "UPDATE messages SET delivery_status='release_pending' WHERE id=$1::uuid", message
                )

        release = asyncio.create_task(reserve_release())
        try:
            await asyncio.wait_for(case_reserved.wait(), timeout=2)
            await asyncio.wait_for(redact_expired(self.pool, 30, 100), timeout=2)
        finally:
            retention_finished.set()
            await asyncio.wait_for(release, timeout=2)
        row = await self.pool.fetchrow(
            "SELECT raw_eml,redacted_at,delivery_status FROM messages WHERE id=$1::uuid", message
        )
        self.assertEqual(row["delivery_status"], "release_pending")
        self.assertIsNotNone(row["raw_eml"])
        self.assertIsNone(row["redacted_at"])

    async def test_un_message_termine_sans_dossier_reste_purgeable(self) -> None:
        message = await self._aged_message(400, "delivered")
        await self.pool.execute(
            "DELETE FROM delivery_cases WHERE message_id=$1::uuid", message
        )
        await redact_expired(self.pool, 30, 100)
        self.assertIsNone(await self.pool.fetchval(
            "SELECT raw_eml FROM messages WHERE id=$1::uuid", message
        ))
        await delete_expired(self.pool, 180, 100)
        self.assertFalse(await self.pool.fetchval(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE id=$1::uuid)", message
        ))

    async def test_toutes_les_copies_envoyees_sont_purgees_pas_les_avis_a_envoyer(self) -> None:
        conversation = await self.pool.fetchval(
            """INSERT INTO conversations(participant_email,status)
               VALUES('retention-outbox@example.org','closed') RETURNING id::text"""
        )
        self.created_conversations.append(conversation)
        ids = []
        for statut in ("sent", "pending"):
            ids.append(await self.pool.fetchval(
                """INSERT INTO assistant_outbox(
                     conversation_id,recipient,sender,reply_to,subject,body_text,
                     body_html,attachment_content,inline_content,status,created_at)
                   VALUES($1::uuid,'recipient@example.org','maia@example.org',
                     'maia@example.org','Avis','', '<p>Copie du message</p>',
                     NULL,$2,$3,now()-interval '40 days') RETURNING id""",
                conversation, b"miniature", statut,
            ))
        await redact_expired_conversations(self.pool, 30)
        for identifiant, envoye in zip(ids, (True, False)):
            row = await self.pool.fetchrow(
                "SELECT body_html,inline_content FROM assistant_outbox WHERE id=$1",
                identifiant,
            )
            self.assertEqual(row["body_html"] is None, envoye)
            self.assertEqual(row["inline_content"] is None, envoye)
        # Même une ancienne ligne dont le texte et l'annexe étaient déjà vides
        # doit être dégonflée. Le second passage ne doit plus la modifier.
        counts = await redact_expired_conversations(self.pool, 30)
        self.assertEqual(counts["assistant_outbox"], 0)

    async def test_content_is_redacted_then_deleted_while_the_rule_survives(
        self,
    ) -> None:
        message_id = await self._aged_message(400, "delivered")
        participant = await self.pool.fetchval(
            "SELECT envelope_recipients[1] FROM messages WHERE id=$1::uuid",
            message_id,
        )
        await self.pool.execute(
            """
            INSERT INTO labels (
                message_id, source, label, confidence, is_ground_truth,
                context, sender_normalized, participant_email, subject
            ) VALUES (
                $1::uuid,'smtp_feedback_user','spam',1,true,'{}'::jsonb,
                'bounce@sender.example',$2,'Objet témoin'
            )
            """,
            message_id,
            participant,
        )

        await redact_expired(self.pool, 30, 100)
        row = await self.pool.fetchrow(
            """
            SELECT raw_eml, body_text, body_html, redacted_at FROM messages
            WHERE id=$1::uuid
            """,
            message_id,
        )
        self.assertIsNone(row["raw_eml"])
        self.assertIsNone(row["body_text"])
        self.assertIsNone(row["body_html"])
        self.assertIsNotNone(row["redacted_at"])

        await delete_expired(self.pool, 180, 100)
        self.assertIsNone(
            await self.pool.fetchval(
                "SELECT id FROM messages WHERE id=$1::uuid", message_id
            )
        )
        label = await self.pool.fetchrow(
            """
            SELECT message_id, sender_normalized, subject, active FROM labels
            WHERE participant_email=$1 AND source='smtp_feedback_user'
            ORDER BY id DESC LIMIT 1
            """,
            participant,
        )
        self.assertIsNone(label["message_id"])
        self.assertEqual(label["sender_normalized"], "bounce@sender.example")
        self.assertEqual(label["subject"], "Objet témoin")

        rulebook = await render_rulebook(self.pool, participant)
        self.assertIn("bounce@sender.example", rulebook.body)
        self.assertNotIn("adresse effacée", rulebook.body)

    async def test_operational_history_is_purged_with_the_same_window(self) -> None:
        await self.pool.execute(
            """
            INSERT INTO operational_events (component, status, reasons, observed_at)
            VALUES ('sentimail-v3','degraded','["test"]'::jsonb,
                    now()-interval '400 days')
            """
        )
        before = await self.pool.fetchval(
            "SELECT count(*) FROM operational_events WHERE observed_at < now()-interval '200 days'"
        )
        self.assertGreater(before, 0)
        counts = await delete_expired(self.pool, 180, 100)
        self.assertGreaterEqual(counts["operational_events"], 1)
        self.assertEqual(
            await self.pool.fetchval(
                "SELECT count(*) FROM operational_events WHERE observed_at < now()-interval '200 days'"
            ),
            0,
        )

    async def test_conversation_bodies_are_cleared_but_directives_remain(self) -> None:
        conversation_id = await self.pool.fetchval(
            """
            INSERT INTO conversations (participant_email, status)
            VALUES ('retention-directive@example.org','closed') RETURNING id::text
            """
        )
        self.created_conversations.append(conversation_id)
        message_id = await self.pool.fetchval(
            """
            INSERT INTO conversation_messages (
                conversation_id, direction, body_text, user_text, created_at
            ) VALUES (
                $1::uuid,'inbound','texte complet cité','B', now()-interval '400 days'
            ) RETURNING id::text
            """,
            conversation_id,
        )
        await redact_expired_conversations(self.pool, 30)
        row = await self.pool.fetchrow(
            "SELECT body_text, user_text FROM conversation_messages WHERE id=$1::uuid",
            message_id,
        )
        self.assertIsNone(row["body_text"])
        self.assertEqual(row["user_text"], "B")


if __name__ == "__main__":
    unittest.main()
