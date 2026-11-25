from __future__ import annotations

import asyncio
import os
import unittest
from contextlib import suppress
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import asyncpg

from sentimail_v3.conversation import assistant


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        assistant_interval_seconds=0.001,
        hold_lifecycle_interval_seconds=3600,
        conversation_enabled=True,
        assistant_token_secret="s" * 32,
        database_url="postgresql://test-local",
        deepseek_assistant_model="modele-simule",
        deepseek_timeout_seconds=30,
    )


class AssistantWorkersTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_entrant_lent_ne_retarde_pas_un_avis(self) -> None:
        entered = asyncio.Event()
        sent = asyncio.Event()
        cancelled = asyncio.Event()

        async def inbound(*args):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        async def outbox(*args):
            await entered.wait()
            sent.set()
            await asyncio.Event().wait()

        with patch.object(assistant, "_process_inbound", inbound), patch.object(
            assistant, "_send_outbox", outbox
        ), patch.object(assistant, "pulse"):
            task = asyncio.create_task(assistant._run_workers(None, None, _settings()))
            try:
                await asyncio.wait_for(sent.wait(), timeout=1)
                self.assertFalse(cancelled.is_set())
            finally:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
            self.assertTrue(cancelled.is_set())

    async def test_un_cycle_de_retenues_lent_ne_retarde_pas_un_avis(self) -> None:
        lifecycle_started = asyncio.Event()
        sent = asyncio.Event()

        async def lifecycle(*args):
            lifecycle_started.set()
            await asyncio.Event().wait()

        async def outbox(*args):
            await lifecycle_started.wait()
            sent.set()
            await asyncio.Event().wait()

        with patch.object(assistant, "_process_inbound", AsyncMock(return_value=False)), patch.object(
            assistant, "run_hold_lifecycle", lifecycle
        ), patch.object(assistant, "_send_outbox", outbox), patch.object(assistant, "pulse"):
            task = asyncio.create_task(assistant._run_workers(None, None, _settings()))
            try:
                await asyncio.wait_for(sent.wait(), timeout=1)
            finally:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

    async def test_le_battement_exige_la_progression_des_deux_boucles(self) -> None:
        allow_inbound = asyncio.Event()
        allow_outbox = asyncio.Event()
        inbound_next = asyncio.Event()
        outbox_next = asyncio.Event()
        outbox_third = asyncio.Event()

        async def inbound(*args):
            if inbound_next.is_set():
                await asyncio.Event().wait()
            await allow_inbound.wait()
            inbound_next.set()
            return False

        async def outbox(*args):
            if not outbox_next.is_set():
                outbox_next.set()
                return True
            if outbox_third.is_set():
                await asyncio.Event().wait()
            await allow_outbox.wait()
            outbox_third.set()
            return False

        with patch.object(assistant, "_process_inbound", inbound), patch.object(
            assistant, "_send_outbox", outbox
        ), patch.object(assistant, "run_hold_lifecycle", AsyncMock()), patch.object(
            assistant, "pulse"
        ) as pulse:
            task = asyncio.create_task(assistant._run_workers(None, None, _settings()))
            try:
                await asyncio.wait_for(outbox_next.wait(), timeout=1)
                self.assertEqual(pulse.call_count, 1)
                allow_inbound.set()
                await asyncio.wait_for(inbound_next.wait(), timeout=1)
                self.assertEqual(pulse.call_count, 2)
                allow_outbox.set()
                await asyncio.wait_for(outbox_third.wait(), timeout=1)
                self.assertEqual(pulse.call_count, 2)
            finally:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

    async def test_la_panne_d_une_boucle_annule_la_tache_soeur(self) -> None:
        outbox_started = asyncio.Event()
        outbox_cancelled = asyncio.Event()

        async def inbound(*args):
            await outbox_started.wait()
            raise RuntimeError("panne simulée")

        async def outbox(*args):
            outbox_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                outbox_cancelled.set()

        with patch.object(assistant, "_process_inbound", inbound), patch.object(
            assistant, "_send_outbox", outbox
        ), patch.object(assistant, "pulse"):
            with self.assertRaises(ExceptionGroup) as raised:
                await asyncio.wait_for(assistant._run_workers(None, None, _settings()), timeout=1)
        self.assertTrue(outbox_cancelled.is_set())
        self.assertEqual(len(raised.exception.exceptions), 1)
        self.assertIsInstance(raised.exception.exceptions[0], RuntimeError)

    async def test_l_arret_ferme_le_client_et_le_pool(self) -> None:
        pool = SimpleNamespace(execute=AsyncMock(), close=AsyncMock())
        client = AsyncMock()
        client.__aenter__.return_value = client
        with patch.object(assistant, "load_settings", return_value=_settings()), patch.object(
            assistant.asyncpg, "create_pool", AsyncMock(return_value=pool)
        ) as create_pool, patch.object(assistant.httpx, "AsyncClient", return_value=client), patch.object(
            assistant, "_run_workers", AsyncMock(side_effect=asyncio.CancelledError)
        ):
            with self.assertRaises(asyncio.CancelledError):
                await assistant.main()
        create_pool.assert_awaited_once_with(_settings().database_url, min_size=1, max_size=4)
        client.__aexit__.assert_awaited_once()
        pool.close.assert_awaited_once()

    async def test_une_panne_d_initialisation_ferme_aussi_le_pool(self) -> None:
        pool = SimpleNamespace(execute=AsyncMock(side_effect=RuntimeError("base indisponible")), close=AsyncMock())
        with patch.object(assistant, "load_settings", return_value=_settings()), patch.object(
            assistant.asyncpg, "create_pool", AsyncMock(return_value=pool)
        ):
            with self.assertRaisesRegex(RuntimeError, "base indisponible"):
                await assistant.main()
        pool.close.assert_awaited_once()


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class OutboxRetrySpacingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.connection = await asyncpg.connect(os.environ["DATABASE_URL"])
        await self.connection.execute("""CREATE TEMP TABLE assistant_outbox (
            id bigserial PRIMARY KEY, status text NOT NULL DEFAULT 'pending',
            attempts integer NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now(),
            last_attempt_at timestamptz
        )""")

    async def asyncTearDown(self) -> None:
        await self.connection.close()

    async def test_un_ancien_avis_attend_depuis_sa_derniere_tentative(self) -> None:
        await self.connection.execute("""INSERT INTO assistant_outbox
            (status,attempts,created_at,last_attempt_at)
            VALUES ('error',1,now()-interval '10 days',now())""")
        self.assertIsNone(await assistant._claim_outbox(self.connection))
        await self.connection.execute("""UPDATE assistant_outbox
            SET last_attempt_at=now()-interval '11 seconds'""")
        row = await assistant._claim_outbox(self.connection)
        self.assertEqual(row["attempts"], 2)
        await self.connection.execute("UPDATE assistant_outbox SET status='error'")
        self.assertIsNone(await assistant._claim_outbox(self.connection))

    async def test_le_premier_essai_est_immediat_et_le_cinquieme_reste_le_dernier(self) -> None:
        await self.connection.execute("INSERT INTO assistant_outbox DEFAULT VALUES")
        for attempt in range(1, 6):
            row = await assistant._claim_outbox(self.connection)
            self.assertIsNotNone(row)
            self.assertEqual(row["attempts"], attempt)
            await self.connection.execute("UPDATE assistant_outbox SET status='error'")
            self.assertIsNone(await assistant._claim_outbox(self.connection))
            await self.connection.execute("UPDATE assistant_outbox SET last_attempt_at=now()-interval '1 hour'")
        self.assertIsNone(await assistant._claim_outbox(self.connection))

    async def test_un_ancien_essai_sans_horodatage_reste_recuperable(self) -> None:
        await self.connection.execute("""INSERT INTO assistant_outbox
            (status,attempts,created_at) VALUES ('error',1,now()-interval '10 days')""")
        row = await assistant._claim_outbox(self.connection)
        self.assertEqual(row["attempts"], 2)
        self.assertIsNotNone(row["last_attempt_at"])
        await self.connection.execute("UPDATE assistant_outbox SET status='error'")
        self.assertIsNone(await assistant._claim_outbox(self.connection))


if __name__ == "__main__":
    unittest.main()
