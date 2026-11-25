"""Le journal compte les vraies tentatives sans enregistrer le courrier."""

from __future__ import annotations

import asyncio
import json
import os
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import asyncpg
import httpx

from sentimail_v3 import llm
from sentimail_v3.conversation.agent_loop import answer_question
from sentimail_v3.conversation.assistant import _reservation_with_first, _reserve_llm_call
from sentimail_v3.llm_accounting import LlmQuotaExceeded, llm_scope, token_counts

DSN = os.environ.get("LLM_TEST_DATABASE_URL", os.environ.get("ENRICHER_TEST_DATABASE_URL", ""))
BODY = "CONTENU_CONFIDENTIEL_A_NE_PAS_JOURNALISER"
SECRET = "SECRET_A_NE_PAS_JOURNALISER"


def _settings():
    return SimpleNamespace(local_llm_url="https://local.test", remote_llm_deadline_seconds=1,
                           assistant_question_deadline_seconds=1,
                           assistant_llm_conversation_limit=20,
                           assistant_llm_hourly_limit=30, assistant_llm_daily_limit=100,
                           verdict_llm_hourly_limit=100, verdict_llm_daily_limit=500)


class TokenCountsTests(unittest.TestCase):
    def test_les_caches_ne_sont_pas_additionnes_deux_fois(self):
        cases = [
            ({"prompt_tokens": 100, "completion_tokens": 8, "prompt_tokens_details": {"cached_tokens": 70}}, (100, 8, 70, None)),
            ({"prompt_tokens": 100, "completion_tokens": 8, "prompt_cache_hit_tokens": 60}, (100, 8, 60, None)),
            ({"input_tokens": 10, "output_tokens": 8, "cache_read_input_tokens": 70, "cache_creation_input_tokens": 20}, (100, 8, 70, 20)),
            ({"prompt_eval_count": 100, "eval_count": 8}, (100, 8, None, None)),
            ({"prompt_tokens": BODY, "completion_tokens": -1, "cache_read_input_tokens": True}, (None, None, None, None)),
        ]
        for usage, expected in cases:
            with self.subTest(usage=usage):
                self.assertEqual(token_counts(usage), expected)


class ReservationTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_budget_deja_depense_ne_contacte_personne(self):
        with patch("sentimail_v3.conversation.agent_loop.provider_chat_json", AsyncMock()) as provider:
            answer = await answer_question(None, None, _settings(), BODY,
                participant="participant@example.org", deadline_seconds=0)
        self.assertTrue(answer.truncated)
        provider.assert_not_awaited()

    async def test_la_reservation_initiale_n_est_pas_comptee_deux_fois(self):
        reserve = _reservation_with_first(None, None, "conversation", "participant", 40)
        with patch("sentimail_v3.conversation.assistant._reserve_llm_call", AsyncMock(return_value=(41, None))) as extra:
            self.assertEqual(await reserve(), (40, None))
            extra.assert_not_awaited()
            self.assertEqual(await reserve(), (41, None))
            extra.assert_awaited_once()

    async def test_une_panne_du_journal_ne_change_pas_la_reponse(self):
        pool = AsyncMock()
        pool.fetchval.side_effect = RuntimeError(SECRET)
        pool.execute.side_effect = RuntimeError(BODY)
        route = llm.ProviderRoute("openai_compatible", "https://modele.test", "modele-test", SECRET, "max_tokens")
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(
            200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}]}
        ))) as client:
            with self.assertLogs("sentimail-v3-llm-accounting", level="WARNING") as logs, patch.object(llm, "active_provider", AsyncMock(return_value=route)):
                content, _ = await llm.provider_chat_json(pool, client, _settings(),
                    messages=[{"role": "user", "content": BODY}], max_tokens=20, allow_local=False)
        self.assertIn("ok", content)
        self.assertNotIn(SECRET, str(logs.output))
        self.assertNotIn(BODY, str(logs.output))


@unittest.skipUnless(DSN, "base PostgreSQL locale jetable requise")
class AccountingPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.assertEqual(urlsplit(DSN).hostname, "127.0.0.1")
        self.assertTrue(urlsplit(DSN).path.endswith("_test"))
        self.connection = await asyncpg.connect(DSN)
        self.transaction = self.connection.transaction()
        await self.transaction.start()
        self.settings = _settings()
        self.route = llm.ProviderRoute("openai_compatible", "https://distant.test", "modele-distant", SECRET, "max_tokens")
        self.conversation = str(uuid.uuid4())
        self.scope = llm_scope(conversation_id=self.conversation)
        self.scope.__enter__()

    async def asyncTearDown(self):
        try:
            await self.transaction.rollback()
            await self.connection.close()
        finally:
            self.scope.__exit__(None, None, None)

    async def rows(self):
        return await self.connection.fetch("SELECT * FROM llm_attempt_events WHERE conversation_id=$1::uuid ORDER BY id", self.conversation)

    async def call(self, handler, *, local=False, reserve=None):
        with patch.object(llm, "active_provider", AsyncMock(return_value=self.route)), patch.object(
            llm, "local_route", AsyncMock(return_value=("modele-local", True) if local else None)
        ), llm_scope(reserve_call=reserve):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await llm.provider_chat_json(self.connection, client, self.settings,
                    messages=[{"role": "user", "content": BODY}], max_tokens=100, role="conversation")

    async def test_le_repli_a_deux_lignes_et_ne_conserve_que_les_compteurs(self):
        calls = []
        reservations = []
        def handler(request):
            calls.append(request.url.host)
            if request.url.host == "local.test":
                return httpx.Response(503, json={"error": BODY})
            return httpx.Response(200, json={"choices": [{"message": {"content": '{"answer":"ok"}'}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 8, "prompt_cache_hit_tokens": 70, "arbitrary": BODY}})

        async def reserve():
            reservations.append(1)
            return None, None

        message, run = [str(uuid.uuid4()) for _ in range(2)]
        with llm_scope(message_id=message, verdict_run_id=run, purpose="test"):
            _, metadata = await self.call(handler, local=True, reserve=reserve)
        rows = await self.rows()
        self.assertEqual(len(reservations), 2)
        self.assertEqual(metadata["attempt_count"], 2)
        self.assertEqual(calls, ["local.test", "distant.test"])
        self.assertEqual([r["status"] for r in rows], ["error", "complete"])
        self.assertEqual([r["is_fallback"] for r in rows], [False, True])
        self.assertEqual([r["http_status"] for r in rows], [503, 200])
        self.assertTrue(all(str(r["message_id"]) == message and str(r["verdict_run_id"]) == run for r in rows))
        self.assertEqual((rows[1]["input_tokens"], rows[1]["output_tokens"], rows[1]["cache_read_tokens"]), (100, 8, 70))
        self.assertTrue(all(r["duration_ms"] >= 0 and r["completed_at"] is not None for r in rows))
        text = str([dict(r) for r in rows])
        for forbidden in (BODY, SECRET, "https://", "distant.test", "arbitrary"):
            self.assertNotIn(forbidden, text)

    async def test_un_quota_refuse_ne_contacte_pas_le_repli(self):
        calls = []
        async def reserve():
            return (None, None) if not calls else (None, "domain_hourly")
        def handler(request):
            calls.append(request.url.host)
            return httpx.Response(503)
        with self.assertRaises(LlmQuotaExceeded):
            await self.call(handler, local=True, reserve=reserve)
        self.assertEqual(calls, ["local.test"])
        self.assertEqual(len(await self.rows()), 1)

    async def test_la_borne_absolue_annule_la_requete_et_rend_une_reponse(self):
        started = asyncio.Event()
        async def handler(request):
            started.set()
            await asyncio.Event().wait()
        reserve = AsyncMock(return_value=(None, None))
        with patch.object(llm, "active_provider", AsyncMock(return_value=self.route)), patch.object(
            llm, "local_route", AsyncMock(return_value=None)
        ):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                answer = await answer_question(self.connection, client, self.settings, BODY,
                    participant="participant@example.org", reserve_call=reserve, deadline_seconds=0.03)
        self.assertTrue(started.is_set())
        self.assertTrue(answer.truncated)
        reserve.assert_awaited_once()
        rows = await self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "cancelled")

    async def test_la_question_reserve_chaque_tour_et_borne_aussi_les_replis(self):
        calls = []
        def handler(request):
            calls.append(request.url.host)
            if request.url.host == "local.test":
                return httpx.Response(503)
            return httpx.Response(200, json={"choices": [{"message": {"content": '{"tool":"recent_messages","arguments":{}}'}}]})
        reserve = AsyncMock(return_value=(None, None))
        with patch.object(llm, "active_provider", AsyncMock(return_value=self.route)), patch.object(
            llm, "local_route", AsyncMock(return_value=("modele-local", True))
        ), patch("sentimail_v3.conversation.agent_loop.run_tool", AsyncMock(return_value={})):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                answer = await answer_question(self.connection, client, self.settings, BODY,
                    participant="participant@example.org", reserve_call=reserve, max_calls=3)
        self.assertTrue(answer.truncated)
        self.assertEqual(calls, ["local.test", "distant.test", "local.test"])
        self.assertEqual(reserve.await_count, 3)
        self.assertEqual(len(await self.rows()), 3)

    async def test_les_scopes_imbriques_restaurent_le_parent(self):
        # Deux contextes imbriqués restaurent leur parent, y compris après erreur.
        first, second = str(uuid.uuid4()), str(uuid.uuid4())
        def handler(request):
            return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})
        with llm_scope(message_id=first):
            await self.call(handler)
            with llm_scope(message_id=second):
                await self.call(handler)
            await self.call(handler)
        await self.call(handler)
        self.assertEqual([str(r["message_id"]) if r["message_id"] else None for r in await self.rows()], [first, second, first, None])

    async def test_deux_requetes_concurrentes_gardent_chacune_leur_message(self):
        pool = await asyncpg.create_pool(DSN, min_size=1, max_size=2)
        ready = asyncio.Event()
        entered = []
        first, second = str(uuid.uuid4()), str(uuid.uuid4())

        async def handler(request):
            entered.append(1)
            if len(entered) == 2:
                ready.set()
            await ready.wait()
            return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

        async def request(client, message_id):
            with llm_scope(message_id=message_id):
                await llm.provider_chat_json(pool, client, self.settings,
                    messages=[{"role": "user", "content": BODY}], max_tokens=10, allow_local=False)

        try:
            with patch.object(llm, "active_provider", AsyncMock(return_value=self.route)):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    async with asyncio.TaskGroup() as group:
                        group.create_task(request(client, first))
                        group.create_task(request(client, second))
            self.assertEqual({str(row["message_id"]) for row in await self.rows()}, {first, second})
        finally:
            await pool.execute("DELETE FROM llm_attempt_events WHERE conversation_id=$1::uuid", self.conversation)
            await pool.close()

    async def test_une_reponse_vide_reste_une_depense_mesuree(self):
        def handler(request):
            return httpx.Response(200, json={"choices": [{"message": {"content": " "}}],
                "usage": {"prompt_tokens": 40, "completion_tokens": 9}})
        with self.assertRaises(llm.LlmError):
            await self.call(handler)
        row = (await self.rows())[0]
        self.assertEqual((row["status"], row["input_tokens"], row["output_tokens"]), ("error", 40, 9))

    async def test_six_requetes_produisent_six_reservations_reelles(self):
        pool = await asyncpg.create_pool(DSN, min_size=1, max_size=2)
        participant = f"quota-{uuid.uuid4().hex}@example.org"
        calls = []
        await pool.execute("INSERT INTO conversations(id,participant_email) VALUES($1::uuid,$2)",
                           self.conversation, participant)

        def handler(request):
            calls.append(1)
            result = {"answer": "Résultat."} if len(calls) == 6 else {"tool": "recent_messages", "arguments": {}}
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(result)}}]})

        async def reserve():
            return await _reserve_llm_call(pool, self.settings, self.conversation, participant)

        try:
            initial, reason = await reserve()
            self.assertIsNone(reason)
            with patch.object(llm, "active_provider", AsyncMock(return_value=self.route)), patch.object(
                llm, "local_route", AsyncMock(return_value=None)
            ), patch("sentimail_v3.conversation.agent_loop.run_tool", AsyncMock(return_value={})):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    with llm_scope(reserve_call=_reservation_with_first(pool, self.settings, self.conversation, participant, initial)):
                        await llm.provider_chat_json(pool, client, self.settings,
                            messages=[{"role": "user", "content": BODY}], max_tokens=10, role="conversation")
                    answer = await answer_question(pool, client, self.settings, BODY,
                        participant=participant, reserve_call=reserve, deadline_seconds=2)
            self.assertEqual(answer.text, "Résultat.")
            self.assertEqual(len(calls), 6)
            self.assertEqual(await pool.fetchval("SELECT count(*) FROM llm_call_events WHERE conversation_id=$1::uuid", self.conversation), 6)
            rows = await self.rows()
            self.assertEqual(len(rows), 6)
            self.assertEqual(len({r["quota_event_id"] for r in rows}), 6)
        finally:
            await pool.execute("DELETE FROM llm_attempt_events WHERE conversation_id=$1::uuid", self.conversation)
            await pool.execute("DELETE FROM conversations WHERE id=$1::uuid", self.conversation)
            await pool.close()
