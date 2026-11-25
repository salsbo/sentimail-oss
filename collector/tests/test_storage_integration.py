from __future__ import annotations

import hashlib
import io
import os
import unittest
from dataclasses import replace
from email.message import EmailMessage
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import asyncpg
import pyzipper
from sentimail_v3.config import load_settings
from sentimail_v3.conversation.confirmation_code import extract_code
from sentimail_v3.conversation.conversation import ConversationStore
from sentimail_v3.observation.deep_analysis import _history
from sentimail_v3.observation.dossier.pipeline import build_hooks
from sentimail_v3.execution.outbox import queue_response as _queue_response
from sentimail_v3.execution.delivery import suppress_original
from sentimail_v3.conversation.provider_setup import ProviderSetup
from sentimail_v3.code.rulebook import (
    apply_rule_request,
    render_rulebook,
    validate_rule_request,
)
from sentimail_v3.observation.storage import Store
from sentimail_v3.observation.enricher import _save as save_enrichment
from sentimail_v3.code.tenancy import forget_cache
from sentimail_v3.code.reference import reference
from sentimail_v3.judgment.verdict_engine import _claim
from test_parser import RAW


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class StorageIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        # Sans domaine enrôlé, SentiMail ne protège personne : le scénario
        # d'intégration commence donc par activer le domaine des destinataires.
        await self.pool.execute(
            """
            INSERT INTO domains (fqdn, status, admin_email, verified_at)
            VALUES ('example.org','active','user@example.org',now())
            ON CONFLICT (fqdn) DO UPDATE SET status='active'
            """
        )
        forget_cache()

    async def asyncTearDown(self) -> None:
        await self.pool.close()

    async def test_capture_url_longue_et_rattachement_enrichissement(self) -> None:
        # Un jeton peu compressible reproduit le dépassement réel du B-tree,
        # contrairement à une simple répétition du même caractère.
        token = "".join(hashlib.sha256(str(i).encode()).hexdigest() for i in range(180))
        url = f"https://suivi.example.net/clic?token={token}"
        raw = (
            "From: contact@sender.example\r\n"
            "To: user@example.org\r\n"
            "Subject: Lien long\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\n"
            f"{url}\r\n"
        ).encode()
        store = Store(self.pool)
        smtp = {"peer_ip": "127.0.0.1", "protocol": "ESMTP"}
        first = await store.capture(
            raw, "contact@sender.example", ["user@example.org"], smtp
        )
        try:
            second = await store.capture(
                raw, "contact@sender.example", ["user@example.org"], smtp
            )
            self.assertFalse(second.inserted)
            self.assertEqual(first.message_id, second.message_id)
            self.assertEqual(
                await self.pool.fetchval(
                    "SELECT value_normalized FROM entities "
                    "WHERE message_id=$1::uuid AND entity_type='url' LIMIT 1",
                    first.message_id,
                ),
                url,
            )
            await save_enrichment(self.pool, "domain", "suivi.example.net", "ok", {})
            rows = await self.pool.fetch(
                "SELECT entity_type, value_normalized, enrichment_id FROM entities "
                "WHERE message_id=$1::uuid",
                first.message_id,
            )
            target = [
                r for r in rows if r["entity_type"] == "domain"
                and r["value_normalized"] == "suivi.example.net"
            ]
            self.assertTrue(target)
            self.assertTrue(all(r["enrichment_id"] is not None for r in target))
            self.assertTrue(
                all(r["enrichment_id"] is None for r in rows if r not in target)
            )
        finally:
            await self.pool.execute(
                "DELETE FROM messages WHERE id=$1::uuid", first.message_id
            )

    async def test_reponse_sans_bouton_se_rattache_au_message_livre(self) -> None:
        store = Store(self.pool)
        smtp = {
            "peer_ip": "172.20.0.8",
            "peer_port": 25,
            "helo": "mx.example",
            "protocol": "ESMTP",
            "tls": {},
            "authenticated": False,
            "mail_options": [],
            "rcpt_options": {},
        }
        livre = await store.capture(
            b"From: Offres <offres@vendeur.example>\r\n"
            b"To: autre@example.org\r\n"
            b"Subject: Offre du jour\r\n"
            b"Message-ID: <Offre-1@vendeur.example>\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Bonjour\r\n",
            "offres@vendeur.example",
            ["autre@example.org"],
            smtp,
        )
        await store.mark_delivered(livre.message_id)
        conversations = ConversationStore(
            self.pool,
            "kitt@sentinel.example",
            "KITT Sentinel <kitt@sentinel.example>",
        )
        # Un tiers qui cite le même identifiant n'ouvre rien : il n'est pas
        # protégé, et le message ne lui a pas été livré.
        tiers = await store.capture(
            b"From: Offres <offres@vendeur.example>\r\n"
            b"To: KITT <kitt@sentinel.example>\r\n"
            b"Subject: Re: Offre du jour\r\n"
            b"Message-ID: <tiers-1@vendeur.example>\r\n"
            b"In-Reply-To: <Offre-1@vendeur.example>\r\n\r\n"
            b"B\r\n",
            "offres@vendeur.example",
            ["kitt@sentinel.example"],
            smtp,
        )
        self.assertEqual(
            await conversations.record_inbound(tiers.message_id), "rejected_sender"
        )
        reponse = await store.capture(
            b"From: Autre <autre@example.org>\r\n"
            b"To: KITT <kitt@sentinel.example>\r\n"
            b"Subject: Re: Offre du jour\r\n"
            b"Message-ID: <reponse-1@example.org>\r\n"
            b"In-Reply-To: offre-1@vendeur.example\r\n"
            b"References: <Offre-1@vendeur.example>\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"B\r\n\r\n> S3-ACTION:ancien-jeton-cite-1234567890abcdef\r\n"
            b"> S3-ACTION:autre-jeton-cite-1234567890abcdef\r\n",
            "autre@example.org",
            ["kitt@sentinel.example"],
            smtp,
        )
        self.assertEqual(
            await conversations.record_inbound(reponse.message_id),
            "confirmation_sent",
        )
        rattachement = await self.pool.fetchrow(
            """
            SELECT c.case_id, dc.message_id::text AS cible, c.participant_email
            FROM conversation_messages cm
            JOIN conversations c ON c.id=cm.conversation_id
            JOIN delivery_cases dc ON dc.id=c.case_id
            WHERE cm.message_id=$1::uuid
            """,
            reponse.message_id,
        )
        self.assertIsNotNone(rattachement)
        self.assertEqual(rattachement["cible"], livre.message_id)
        courrier = await self.pool.fetchval(
            """
            SELECT ao.body_text FROM assistant_outbox ao
            JOIN smtp_actions sa ON sa.id=ao.action_id
            WHERE sa.context->>'confirm_message_id' IN (
                SELECT id::text FROM conversation_messages WHERE message_id=$1::uuid
            )
            """,
            reponse.message_id,
        )
        self.assertIn("« Offre du jour »", str(courrier))

    async def test_capture_is_complete_and_idempotent(self) -> None:
        store = Store(self.pool)
        smtp = {
            "peer_ip": "172.20.0.8",
            "peer_port": 25,
            "helo": "mx.example",
            "protocol": "ESMTP",
            "tls": {},
            "authenticated": False,
            "mail_options": [],
            "rcpt_options": {},
        }
        first = await store.capture(
            RAW, "bounce@sender.example", ["user@example.org"], smtp
        )
        second = await store.capture(
            RAW, "bounce@sender.example", ["user@example.org"], smtp
        )
        self.assertTrue(first.inserted)
        self.assertFalse(second.inserted)
        self.assertEqual(first.message_id, second.message_id)
        await store.mark_delivered(first.message_id)

        counts = await self.pool.fetchrow(
            """
            SELECT
              (SELECT count(*) FROM messages WHERE id=$1::uuid) AS messages,
              (SELECT count(*) FROM headers WHERE message_id=$1::uuid) AS headers,
              (SELECT count(*) FROM mime_parts WHERE message_id=$1::uuid) AS parts,
              (SELECT count(*) FROM entities WHERE message_id=$1::uuid) AS entities,
              (SELECT count(*) FROM investigations WHERE message_id=$1::uuid)
                AS investigations,
              (SELECT count(*) FROM hook_runs hr JOIN investigations i
                 ON i.id=hr.investigation_id WHERE i.message_id=$1::uuid) AS hook_runs,
              (SELECT count(*) FROM clues c JOIN investigations i
                 ON i.id=c.investigation_id WHERE i.message_id=$1::uuid) AS clues,
              (SELECT count(*) FROM verdicts v JOIN investigations i
                 ON i.id=v.investigation_id WHERE i.message_id=$1::uuid) AS verdicts,
              (SELECT count(*) FROM delivery_cases WHERE message_id=$1::uuid)
                AS delivery_cases,
              (SELECT count(*) FROM delivery_events de JOIN delivery_cases dc
                 ON dc.id=de.case_id WHERE dc.message_id=$1::uuid) AS delivery_events
            """,
            first.message_id,
        )
        self.assertEqual(counts["messages"], 1)
        self.assertGreater(counts["headers"], 8)
        self.assertEqual(counts["parts"], 3)
        self.assertGreater(counts["entities"], 10)
        self.assertEqual(counts["investigations"], 1)
        self.assertEqual(counts["hook_runs"], len(build_hooks()))
        self.assertGreater(counts["clues"], 2)
        self.assertEqual(counts["verdicts"], 1)
        self.assertEqual(counts["delivery_cases"], 1)
        self.assertEqual(counts["delivery_events"], 1)
        case = await self.pool.fetchrow(
            "SELECT state, binding FROM delivery_cases WHERE message_id=$1::uuid",
            first.message_id,
        )
        self.assertEqual(case["state"], "original_delivered")
        self.assertFalse(case["binding"])
        history = await _history(self.pool, first.message_id)
        self.assertEqual(history["previous_message_count"], 0)
        self.assertFalse(history["persistent_hold"])

        conversations = ConversationStore(
            self.pool,
            "kitt@sentinel.example",
            "KITT Sentinel <kitt@sentinel.example>",
            render_sandbox_url="http://renderer.invalid",
        )
        self.assertTrue(await conversations.queue_invitation(first.message_id))
        notice = await self.pool.fetchrow(
            """SELECT rn.preview_kind,rn.preview_sha256 FROM review_notices rn
               JOIN delivery_cases dc ON dc.id=rn.case_id
               WHERE dc.message_id=$1::uuid ORDER BY rn.created_at DESC LIMIT 1""",
            first.message_id,
        )
        self.assertEqual(notice["preview_kind"], "text")
        self.assertIsNone(notice["preview_sha256"])
        invitation = await self.pool.fetchrow(
            """
            SELECT ao.body_text,ao.body_html,ao.attachment_content,ao.inline_content
            FROM assistant_outbox ao
            JOIN smtp_actions sa ON sa.id=ao.action_id
            JOIN delivery_cases dc ON dc.id=sa.case_id
            WHERE dc.message_id=$1::uuid
              AND ao.subject LIKE '[SentiMail] Ton avis sur :%'
            ORDER BY ao.created_at DESC LIMIT 1
            """,
            first.message_id,
        )
        # Le corps commence par la fiche utile et ne transporte plus la photo.
        self.assertIn("Écarts relevés", invitation["body_text"])
        self.assertIn("Que veux-tu faire ?", invitation["body_text"])
        self.assertIn("Écarts relevés", invitation["body_html"])
        self.assertNotIn("Objet :", invitation["body_text"])
        self.assertNotIn("De :", invitation["body_text"])
        self.assertNotIn("capture-email-neutralisee", invitation["body_html"])
        self.assertIsNone(invitation["attachment_content"])
        self.assertIsNone(invitation["inline_content"])
        for forbidden in (
            "PROCUREUR",
            "AVOCAT",
            "JUGE",
            "ÉLÉMENTS DÉFAVORABLES",
            "Verdict MAIA",
            "Confiance",
        ):
            self.assertNotIn(forbidden, invitation["body_text"])
        self.assertNotRegex(invitation["body_text"], r"\b\d{1,3}\s*/\s*100\b")
        # La référence lisible fait partie de l'avis. Quand son hexadécimal
        # ne contient que des chiffres, l'interdiction des codes techniques
        # la prenait à tort pour un code interne et échouait au hasard.
        dossier_reference = reference("M", first.message_id)
        self.assertIn(f"Dossier {dossier_reference}", invitation["body_text"])
        self.assertNotRegex(
            invitation["body_text"].replace(dossier_reference, ""),
            r"\b[A-Z][A-Z0-9]*(?:[-_.][A-Z0-9_]+)+\b",
        )
        action = await self.pool.fetchrow(
            """SELECT sa.id,sa.case_id,sa.context->>'conversation_id' AS conversation_id
               FROM smtp_actions sa JOIN delivery_cases dc ON dc.id=sa.case_id
               WHERE dc.message_id=$1::uuid AND sa.status='pending'""",
            first.message_id,
        )
        token = "integration-action-token-1234567890"
        await self.pool.execute(
            "UPDATE smtp_actions SET token_hash=$2 WHERE id=$1",
            action["id"],
            hashlib.sha256(token.encode()).hexdigest(),
        )
        reply = (
            b"From: User <user@example.org>\r\n"
            b"To: KITT <kitt@sentinel.example>\r\n"
            b"Subject: Re: dossier\r\n"
            b"Message-ID: <reply@example.org>\r\n"
            b"In-Reply-To: <s3.integration-action-token-1234567890@sentinel.example>\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"C'est legitime, c'est mon fournisseur.\r\n"
        )
        reply_capture = await store.capture(
            reply, "user@example.org", ["kitt@sentinel.example"], smtp
        )
        self.assertEqual(
            await conversations.record_inbound(reply_capture.message_id), "queued"
        )
        inbound = await self.pool.fetchrow(
            """
            SELECT cm.user_text, cm.processing_status, m.delivery_status
            FROM conversation_messages cm
            JOIN messages m ON m.id=cm.message_id
            WHERE cm.direction='inbound' AND cm.message_id=$1::uuid
            """,
            reply_capture.message_id,
        )
        self.assertIn("fournisseur", inbound["user_text"])
        self.assertEqual(inbound["processing_status"], "pending")
        self.assertEqual(inbound["delivery_status"], "consumed")

        footer_token = "footer-action-token-12345678901234567890"
        await self.pool.execute(
            """
            INSERT INTO smtp_actions (
                case_id,action,token_hash,reply_address,expires_at,context
            ) VALUES ($1,'report_spam',$2,'kitt@sentinel.example',
                      now()+interval '30 days',$3::jsonb)
            """,
            action["case_id"],
            hashlib.sha256(footer_token.encode()).hexdigest(),
            '{"conversation_id":"' + action["conversation_id"] + '",'
            '"purpose":"delivered_feedback","binding":true}',
        )
        footer_reply = (
            b"From: User <user@example.org>\r\n"
            b"To: KITT <kitt@sentinel.example>\r\n"
            b"Subject: [SentiMail] Non sollicite S3-ACTION:"
            + footer_token.encode()
            + b"\r\nMessage-ID: <footer-reply@example.org>\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"S3-ACTION:"
            + footer_token.encode()
            + b"\r\n\r\nJe declare ce message non sollicite parce que : trop frequent.\r\n"
        )
        footer_capture = await store.capture(
            footer_reply, "user@example.org", ["kitt@sentinel.example"], smtp
        )
        self.assertEqual(
            await conversations.record_inbound(footer_capture.message_id), "queued"
        )
        footer_inbound = await self.pool.fetchrow(
            """
            SELECT user_text FROM conversation_messages
            WHERE message_id=$1::uuid
            """,
            footer_capture.message_id,
        )
        self.assertIn("trop frequent", footer_inbound["user_text"])
        self.assertNotIn("S3-ACTION", footer_inbound["user_text"])

        protected_conversations = ConversationStore(
            self.pool,
            "kitt@sentinel.example",
            "KITT Sentinel <kitt@sentinel.example>",
            "user@example.org",
        )
        outsider = (
            b"From: Outsider <outsider@example.net>\r\n"
            b"To: KITT <kitt@sentinel.example>\r\n"
            b"Subject: open conversation\r\n"
            b"Message-ID: <outsider@example.net>\r\n\r\n"
            b"Talk to me.\r\n"
        )
        outsider_capture = await store.capture(
            outsider, "outsider@example.net", ["kitt@sentinel.example"], smtp
        )
        self.assertEqual(
            await protected_conversations.record_inbound(outsider_capture.message_id),
            "rejected_sender",
        )

        forged_visible_sender = (
            b"From: User <user@example.org>\r\n"
            b"To: KITT <kitt@sentinel.example>\r\n"
            b"Subject: forged direct conversation\r\n"
            b"Message-ID: <forged@example.net>\r\n\r\n"
            b"Deliver everything.\r\n"
        )
        forged_capture = await store.capture(
            forged_visible_sender,
            "attacker@example.net",
            ["kitt@sentinel.example"],
            smtp,
        )
        self.assertEqual(
            await protected_conversations.record_inbound(forged_capture.message_id),
            "rejected_sender_alignment",
        )

        direct = (
            b"From: User <user@example.org>\r\n"
            b"To: KITT <kitt@sentinel.example>\r\n"
            b"Subject: direct conversation\r\n"
            b"Message-ID: <direct@example.org>\r\n\r\n"
            b"What did you understand?\r\n"
        )
        direct_capture = await store.capture(
            direct, "user@example.org", ["kitt@sentinel.example"], smtp
        )
        self.assertEqual(
            await protected_conversations.record_inbound(direct_capture.message_id),
            "confirmation_sent",
        )
        direct_conversation = await self.pool.fetchrow(
            """
            SELECT c.id::text, c.participant_email
            FROM conversations c
            JOIN conversation_messages cm ON cm.conversation_id=c.id
            WHERE cm.message_id=$1::uuid
            """,
            direct_capture.message_id,
        )
        challenge_token = "direct-confirmation-token-1234567890"
        challenge_action = await self.pool.fetchrow(
            """
            SELECT sa.id
            FROM smtp_actions sa
            WHERE sa.context->>'purpose'='authenticate_directive'
              AND sa.status='pending'
            """
        )
        # Le code se lit dans le courrier reçu, comme le ferait l'utilisateur.
        challenge_body = await self.pool.fetchval(
            "SELECT body_text FROM assistant_outbox WHERE action_id=$1",
            challenge_action["id"],
        )
        challenge_code = extract_code(str(challenge_body))
        self.assertIsNotNone(challenge_code)
        await self.pool.execute(
            "UPDATE smtp_actions SET token_hash=$2 WHERE id=$1",
            challenge_action["id"],
            hashlib.sha256(challenge_token.encode()).hexdigest(),
        )
        confirmation = (
            b"From: User <user@example.org>\r\n"
            b"To: KITT <kitt@sentinel.example>\r\n"
            b"Subject: Re: confirmation\r\n"
            b"Message-ID: <confirmation@example.org>\r\n"
            b"In-Reply-To: <s3.direct-confirmation-token-1234567890@sentinel.example>\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        ) + f"CONFIRME KITT {challenge_code}\r\n".encode()
        confirmation_capture = await store.capture(
            confirmation, "user@example.org", ["kitt@sentinel.example"], smtp
        )
        self.assertEqual(
            await protected_conversations.record_inbound(
                confirmation_capture.message_id
            ),
            "queued_confirmed",
        )
        confirmed_message = await self.pool.fetchrow(
            """
            SELECT processing_status FROM conversation_messages
            WHERE message_id=$1::uuid
            """,
            direct_capture.message_id,
        )
        self.assertEqual(confirmed_message["processing_status"], "pending")
        async with self.pool.acquire() as connection, connection.transaction():
            await _queue_response(
                connection,
                direct_conversation["id"],
                None,
                direct_conversation["participant_email"],
                "KITT <kitt@sentinel.example>",
                "kitt@sentinel.example",
                "Re: direct conversation",
                "I understood.",
            )
        threaded_action = await self.pool.fetchrow(
            """
            SELECT sa.case_id, sa.context->>'conversation_id' AS conversation_id
            FROM smtp_actions sa
            JOIN assistant_outbox ao ON ao.action_id=sa.id
            WHERE ao.conversation_id=$1::uuid
              AND sa.context->>'purpose' IS NULL
            """,
            direct_conversation["id"],
        )
        self.assertIsNone(threaded_action["case_id"])
        self.assertEqual(
            threaded_action["conversation_id"], direct_conversation["id"]
        )

        settings = replace(
            load_settings(),
            verdict_not_before="2000-01-01T00:00:00Z",
            deepseek_verdict_model="deepseek-v4-pro",
        )
        run = await _claim(self.pool, settings)
        self.assertIsNotNone(run)
        self.assertEqual(run["status"], "running")

    async def test_action_reply_accepts_same_mailbox_on_another_client_domain(
        self,
    ) -> None:
        await self.pool.execute(
            """
            INSERT INTO domains(fqdn,status,admin_email,verified_at)
            VALUES ('alias.example.net','active','user@alias.example.net',now())
            ON CONFLICT (fqdn) DO UPDATE SET status='active',verified_at=now()
            """
        )
        await self.pool.execute(
            """
            UPDATE domains alias_domain SET client_id=main_domain.client_id
            FROM domains main_domain
            WHERE alias_domain.fqdn='alias.example.net'
              AND main_domain.fqdn='example.org'
            """
        )
        forget_cache()
        store = Store(self.pool)
        smtp = {
            "peer_ip": "172.20.0.8",
            "peer_port": 25,
            "helo": "mx.example",
            "protocol": "ESMTP",
            "tls": {},
            "authenticated": False,
            "mail_options": [],
            "rcpt_options": {},
        }
        original = await store.capture(
            b"From: sender@remote.test\r\nTo: user@example.org\r\n"
            b"Subject: alias action\r\nMessage-ID: <alias-action@remote.test>\r\n\r\nbody\r\n",
            "sender@remote.test",
            ["user@example.org"],
            smtp,
        )
        case_id = await self.pool.fetchval(
            "SELECT id FROM delivery_cases WHERE message_id=$1::uuid",
            original.message_id,
        )
        conversation_id = await self.pool.fetchval(
            """
            INSERT INTO conversations(case_id,participant_email,status)
            VALUES ($1,'user@example.org','awaiting_user') RETURNING id
            """,
            case_id,
        )
        token = "same-client-alias-action-token-123456"
        await self.pool.execute(
            """
            INSERT INTO smtp_actions(
                case_id,action,token_hash,reply_address,expires_at,context
            ) VALUES ($1,'release_original',$2,'maia@example.org',
                      now()+interval '1 day',$3::jsonb)
            """,
            case_id,
            hashlib.sha256(token.encode()).hexdigest(),
            '{"conversation_id":"' + str(conversation_id) + '"}',
        )
        reply = await store.capture(
            b"From: User <user@alias.example.net>\r\n"
            b"To: MAIA <maia@example.org>\r\nSubject: Re: alias action\r\n"
            b"In-Reply-To: <s3."
            + token.encode()
            + b"@sentinel.example>\r\nMessage-ID: <alias-reply@example.net>\r\n\r\nA\r\n",
            "user@alias.example.net",
            ["maia@example.org"],
            smtp,
        )
        conversations = ConversationStore(
            self.pool,
            "maia@example.org",
            "MAIA <maia@example.org>",
        )
        self.assertEqual(await conversations.record_inbound(reply.message_id), "queued")
        self.assertEqual(
            await self.pool.fetchval(
                """
                SELECT count(*) FROM audit_log
                WHERE action='smtp_reply.accepted_client_alias'
                  AND payload->>'message_id'=$1
                """,
                reply.message_id,
            ),
            1,
        )

    async def test_authenticated_suppression_is_terminal_audited_and_idempotent(
        self,
    ) -> None:
        store = Store(self.pool)
        captured = await store.capture(
            b"From: blocked@remote.test\r\nTo: user@example.org\r\n"
            b"Subject: blocked\r\nMessage-ID: <suppressed@remote.test>\r\n\r\nbody\r\n",
            "blocked@remote.test",
            ["user@example.org"],
            {
                "peer_ip": "172.20.0.8",
                "peer_port": 25,
                "helo": "mx.example",
                "protocol": "ESMTP",
                "tls": {},
                "authenticated": False,
                "mail_options": [],
                "rcpt_options": {},
            },
        )
        self.assertEqual(
            await suppress_original(
                self.pool,
                captured.message_id,
                reason="authenticated_sender_policy_hold",
            ),
            "suppressed",
        )
        state = await self.pool.fetchrow(
            """
            SELECT m.delivery_status,dc.state,dc.original_delivery_allowed,
                   count(de.id) FILTER (
                     WHERE de.event_type='policy_suppressed'
                   ) OVER () AS events
            FROM messages m JOIN delivery_cases dc ON dc.message_id=m.id
            LEFT JOIN delivery_events de ON de.case_id=dc.id
            WHERE m.id=$1::uuid
            """,
            captured.message_id,
        )
        self.assertEqual(state["delivery_status"], "suppressed")
        self.assertEqual(state["state"], "policy_suppressed")
        self.assertFalse(state["original_delivery_allowed"])
        self.assertEqual(state["events"], 1)
        self.assertEqual(
            await suppress_original(
                self.pool,
                captured.message_id,
                reason="authenticated_sender_policy_hold",
            ),
            "already_suppressed",
        )
    async def test_provider_bootstrap_and_sensitive_replies_bypass_mail_storage(
        self,
    ) -> None:
        with TemporaryDirectory() as secret_directory:
            settings = replace(
                load_settings(),
                action_address="maia@sentinel.example",
                action_aliases=("kitt@sentinel.example",),
                assistant_sender="MAIA Sentinel <maia@sentinel.example>",
                operator_address="user@example.org",
                provider_secrets_dir=secret_directory,
            )
            setup = ProviderSetup(self.pool, settings)
            self.assertTrue(await setup.ensure_bootstrap())
            bootstrap = await self.pool.fetchrow(
                """SELECT sa.id,ao.attachment_filename,ao.attachment_content
                   FROM smtp_actions sa JOIN assistant_outbox ao ON ao.action_id=sa.id
                   WHERE sa.context->>'purpose'='bootstrap_provider'"""
            )
            self.assertEqual(bootstrap["attachment_filename"], "cle-api.txt")
            self.assertEqual(bytes(bootstrap["attachment_content"]), b"\n")
            zip_token = "provider-zip-token-12345678901234567890"
            await self.pool.execute(
                "UPDATE smtp_actions SET token_hash=$2 WHERE id=$1",
                bootstrap["id"],
                hashlib.sha256(zip_token.encode()).hexdigest(),
            )
            archive_bytes = io.BytesIO()
            with pyzipper.AESZipFile(
                archive_bytes,
                "w",
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as archive:
                archive.setpassword(b"test-password")
                archive.writestr("cle-api.txt", "sk-ant-test-12345678901234567890")
            upload = EmailMessage()
            upload["From"] = "User <user@example.org>"
            upload["To"] = "MAIA <maia@sentinel.example>"
            upload["References"] = f"<s3.{zip_token}@sentinel.example>"
            upload.set_content("Je choisis Claude")
            upload.add_attachment(
                archive_bytes.getvalue(),
                maintype="application",
                subtype="zip",
                filename="maia.zip",
            )
            count_before = await self.pool.fetchval("SELECT count(*) FROM messages")
            self.assertEqual(
                await setup.handle(upload.as_bytes(), "user@example.org"),
                "credential_zip_accepted",
            )
            password_action = await self.pool.fetchrow(
                """SELECT id FROM smtp_actions
                   WHERE context->>'purpose'='credential_password' AND status='pending'"""
            )
            password_token = "provider-password-token-123456789012345"
            await self.pool.execute(
                "UPDATE smtp_actions SET token_hash=$2 WHERE id=$1",
                password_action["id"],
                hashlib.sha256(password_token.encode()).hexdigest(),
            )
            password = EmailMessage()
            password["From"] = "User <user@example.org>"
            password["To"] = "MAIA <maia@sentinel.example>"
            password["References"] = f"<s3.{password_token}@sentinel.example>"
            password.set_content("test-password")
            with patch(
                "sentimail_v3.conversation.provider_setup.validate_api_key",
                new=AsyncMock(return_value=None),
            ):
                self.assertEqual(
                    await setup.handle(password.as_bytes(), "user@example.org"),
                    "credential_provider_activated",
                )
            self.assertEqual(
                await self.pool.fetchval("SELECT count(*) FROM messages"), count_before
            )
            provider = await self.pool.fetchrow(
                "SELECT provider,model_name FROM llm_role_providers WHERE role='verdict'"
            )
            self.assertEqual(provider["provider"], "anthropic")
            self.assertTrue(str(provider["model_name"]).startswith("claude-"))
            conversation_role = await self.pool.fetchrow(
                "SELECT provider,model_name FROM llm_role_providers WHERE role='conversation'"
            )
            self.assertEqual(conversation_role["provider"], "anthropic")
            self.assertTrue(str(conversation_role["model_name"]).startswith("claude-"))
            self.assertIsNone(
                await self.pool.fetchval(
                    "SELECT encrypted_zip FROM llm_provider_setup_sessions WHERE state='complete'"
                )
            )

    async def test_sender_learning_is_shared_by_client_and_isolated_between_clients(
        self,
    ) -> None:
        store = Store(self.pool)
        smtp = {
            "peer_ip": "172.20.0.8",
            "peer_port": 25,
            "helo": "mx.example",
            "protocol": "ESMTP",
            "tls": {},
            "authenticated": False,
            "mail_options": [],
            "rcpt_options": {},
        }
        first = await store.capture(
            RAW, "same@sender.example", ["one@example.org"], smtp
        )
        await self.pool.execute(
            """
            INSERT INTO labels(message_id,source,label,confidence,is_ground_truth)
            VALUES ($1::uuid,'test','legitimate',1,true)
            """,
            first.message_id,
        )
        second = await store.capture(
            RAW, "same@sender.example", ["two@example.org"], smtp
        )
        history = await _history(self.pool, second.message_id)
        self.assertEqual(history["participant_email"], "two@example.org")
        self.assertGreaterEqual(history["previous_message_count"], 1)
        self.assertGreaterEqual(history["ground_truth_labels"].get("legitimate", 0), 1)

        await self.pool.execute(
            """
            INSERT INTO domains(fqdn,status,verified_at)
            VALUES ('isolated.feedback.test','active',now())
            ON CONFLICT (fqdn) DO UPDATE SET status='active',verified_at=now()
            """
        )
        third = await store.capture(
            RAW,
            "same@sender.example",
            ["three@isolated.feedback.test"],
            smtp,
        )
        isolated = await _history(self.pool, third.message_id)
        self.assertEqual(isolated["previous_message_count"], 0)
        self.assertEqual(isolated["ground_truth_labels"], {})

    async def test_rulebook_exports_corrects_and_soft_deletes_feedback(self) -> None:
        store = Store(self.pool)
        smtp = {
            "peer_ip": "172.20.0.8",
            "peer_port": 25,
            "helo": "mx.example",
            "protocol": "ESMTP",
            "tls": {},
            "authenticated": False,
            "mail_options": [],
            "rcpt_options": {},
        }
        captured = await store.capture(
            RAW,
            "trusted@sender.example",
            ["rules@example.org"],
            smtp,
        )
        feedback_id = await self.pool.fetchval(
            """
            INSERT INTO labels(message_id,source,label,confidence,is_ground_truth)
            VALUES ($1::uuid,'smtp_feedback_user','spam',1,true)
            RETURNING id
            """,
            captured.message_id,
        )
        report = await render_rulebook(self.pool, "rules@example.org")
        self.assertIn(f"F-{feedback_id}", report.body)
        self.assertEqual(report.attachment_name, "regles-maia.csv")
        self.assertIn(b"rule_id", bytes(report.attachment_content or b""))

        import_message = EmailMessage()
        import_message["From"] = "rules@example.org"
        import_message["To"] = "maia@sentinel.example"
        import_message.set_content("Importe les listes jointes")
        import_message.add_attachment(
            b"email,liste\nfriend@sender.example,liste_blanche\nspam@sender.example,liste_noire\n",
            maintype="text",
            subtype="csv",
            filename="listes.csv",
        )
        import_gate = validate_rule_request(
            "Importe les listes jointes",
            {"requested_action": "import_rules", "rule_list": "mixed"},
        )
        self.assertTrue(import_gate.allowed)
        imported = await apply_rule_request(
            self.pool,
            "rules@example.org",
            "import_rules",
            import_gate,
            raw_message=import_message.as_bytes(),
        )
        self.assertTrue(imported.applied)
        policies = await self.pool.fetch(
            """
            SELECT value_normalized,action,active FROM sender_policies
            WHERE participant_email='rules@example.org' ORDER BY value_normalized
            """
        )
        self.assertEqual(
            [(row["value_normalized"], row["action"], row["active"]) for row in policies],
            [
                ("friend@sender.example", "allow", True),
                ("spam@sender.example", "hold", True),
            ],
        )
        updated_report = await render_rulebook(self.pool, "rules@example.org")
        self.assertIn("Liste blanche active", updated_report.body)
        self.assertIn("friend@sender.example", updated_report.body)
        self.assertIn("Liste noire active", updated_report.body)
        self.assertIn("spam@sender.example", updated_report.body)
        allowed_message = await store.capture(
            b"From: Friend <friend@sender.example>\r\n"
            b"To: Rules <rules@example.org>\r\n"
            b"Subject: hello\r\n\r\nbody\r\n",
            "friend@sender.example",
            ["Rules@Example.org"],
            smtp,
        )
        allowed_history = await _history(self.pool, allowed_message.message_id)
        self.assertTrue(allowed_history["persistent_allow"])
        self.assertFalse(allowed_history["persistent_hold"])
        direct_gate = validate_rule_request(
            "Ajoute manual@sender.example à la liste noire",
            {
                "requested_action": "set_sender_rule",
                "rule_list": "hold",
                "rule_email": "manual@sender.example",
            },
        )
        direct_response = await apply_rule_request(
            self.pool,
            "rules@example.org",
            "set_sender_rule",
            direct_gate,
        )
        self.assertTrue(direct_response.applied)
        self.assertEqual(
            await self.pool.fetchval(
                """
                SELECT action FROM sender_policies
                WHERE participant_email='rules@example.org'
                  AND value_normalized='manual@sender.example' AND active=true
                """
            ),
            "hold",
        )

        result = {
            "requested_action": "update_rule",
            "rule_id": f"F-{feedback_id}",
            "rule_classification": "legitimate",
        }
        correction = validate_rule_request(
            f"Corrige F-{feedback_id} en légitime",
            result,
        )
        self.assertTrue(correction.allowed)
        await apply_rule_request(
            self.pool,
            "rules@example.org",
            "update_rule",
            correction,
        )
        self.assertEqual(
            await self.pool.fetchval("SELECT label FROM labels WHERE id=$1", feedback_id),
            "legitimate",
        )

        disable = validate_rule_request(
            f"Désactive F-{feedback_id}",
            {"requested_action": "disable_rule", "rule_id": f"F-{feedback_id}"},
        )
        self.assertTrue(disable.allowed)
        await apply_rule_request(
            self.pool,
            "rules@example.org",
            "disable_rule",
            disable,
        )
        self.assertFalse(
            await self.pool.fetchval("SELECT active FROM labels WHERE id=$1", feedback_id)
        )
        history = await _history(self.pool, captured.message_id)
        self.assertEqual(history["ground_truth_labels"], {})


if __name__ == "__main__":
    unittest.main()
