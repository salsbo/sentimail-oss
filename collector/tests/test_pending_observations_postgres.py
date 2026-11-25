"""Les constats en attente se reprennent ; ceux d'un verdict accepté sont figés."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import os
import unittest
from urllib.parse import urlsplit
import uuid

import asyncpg

from sentimail_v3.execution.retention import delete_expired, redact_expired
from sentimail_v3.observation.deep_analysis import persist_signals
from sentimail_v3.observation.storage import Store

DSN = os.environ.get("OBSERVATION_CACHE_TEST_DATABASE_URL", os.environ.get("ENRICHER_TEST_DATABASE_URL", ""))


class _PinnedPool:
    """Garde les écritures du scénario dans sa transaction annulée à la fin."""
    def __init__(self, connection):
        self.connection = connection

    def __getattr__(self, name):
        return getattr(self.connection, name)

    @asynccontextmanager
    async def acquire(self):
        yield self.connection


def analysis(*, complete):
    signal = {
        "article_code": "DEEP-019", "clue_code": "SENDER_ACTIVITY_INCOHERENT",
        "direction": "adverse", "strength": 55, "confidence": 0.9,
        "statement": "Le propos ne correspond pas à l'activité publiée.",
        "facts": {"coherent": False},
    }
    return {
        "complete": complete,
        "signals": [signal] if complete else [{"article_code": "POLICY-001"}],
        "deep_hook_runs": [{
            "hook_name": "sender_activity", "hook_version": "test", "run_order": 200,
            "status": "ok" if complete else "error", "duration_ms": 1.0,
            "facts": {"observed": True} if complete else {"failure_types": ["TimeoutError"]},
            "error_type": None if complete else "TimeoutError",
            "error_detail": None if complete else "Source temporairement absente",
        }],
    }


@unittest.skipUnless(DSN, "PostgreSQL local jetable requis")
class PendingObservationsPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        self.connection = await asyncpg.connect(DSN)
        self.transaction = self.connection.transaction()
        await self.transaction.start()
        self.pool = _PinnedPool(self.connection)
        self.message = None
        raw = (f"From: contact@pending.example\r\nTo: recipient@example.org\r\n"
               f"Message-ID: <{uuid.uuid4()}@test.example>\r\n"
               "Subject: Constat en attente\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
               "Message de test sans accès extérieur.").encode()
        captured = await Store(self.pool).capture(raw, "contact@pending.example", ["recipient@example.org"], {})
        self.message = captured.message_id
        self.investigation = await self.pool.fetchval(
            "SELECT id::text FROM investigations WHERE message_id=$1::uuid", self.message)

    async def asyncTearDown(self):
        try:
            if self.transaction is not None:
                await self.transaction.rollback()
            else:
                # Le test de concurrence rend sa fixture visible aux deux
                # connexions, puis ne retire que ses propres traces.
                await self.connection.execute("DELETE FROM audit_log WHERE payload->>'message_id'=$1 OR payload->>'investigation_id'=$2",
                                              self.message, self.investigation)
                await self.connection.execute("DELETE FROM messages WHERE id=$1::uuid", self.message)
        finally:
            await self.connection.close()

    async def state(self):
        counters = await self.pool.fetchrow("""SELECT favorable_points,adverse_points,neutral_clues,
            summary->>'deep_analysis_complete' AS complete FROM investigations WHERE id=$1::uuid""", self.investigation)
        actual = await self.pool.fetchrow("""SELECT
            coalesce(sum(strength) FILTER(WHERE direction='favorable'),0) AS favorable_points,
            coalesce(sum(strength) FILTER(WHERE direction='adverse'),0) AS adverse_points,
            count(*) FILTER(WHERE direction='neutral') AS neutral_clues
            FROM clues WHERE investigation_id=$1::uuid""", self.investigation)
        self.assertEqual({key: counters[key] for key in actual.keys()}, dict(actual))
        hooks = await self.pool.fetch("""SELECT hook_name,run_order,status,error_type FROM hook_runs
            WHERE investigation_id=$1::uuid ORDER BY run_order""", self.investigation)
        clues = await self.pool.fetch("""SELECT clue_code,direction,strength FROM clues
            WHERE investigation_id=$1::uuid ORDER BY clue_code,strength""", self.investigation)
        return dict(counters), [dict(row) for row in hooks], [dict(row) for row in clues]

    async def evidence_hash(self):
        snapshot = await self.pool.fetchval("""SELECT jsonb_build_object(
            'hooks',(SELECT jsonb_agg(to_jsonb(h) ORDER BY h.id) FROM hook_runs h WHERE h.investigation_id=$1::uuid),
            'clues',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.id) FROM clues c WHERE c.investigation_id=$1::uuid),
            'investigation',(SELECT to_jsonb(i) FROM investigations i WHERE i.id=$1::uuid))::text""", self.investigation)
        return hashlib.sha256(snapshot.encode()).hexdigest()

    async def test_reprise_remplace_le_manque_sans_doubler_les_comptes_et_le_verdict_fixe_la_preuve(self):
        await persist_signals(self.pool, self.investigation, analysis(complete=False))
        first = await self.state()
        self.assertEqual(first[0]["complete"], "false")
        self.assertIn("EVIDENCE_INCOMPLETE", {row["clue_code"] for row in first[2]})
        await persist_signals(self.pool, self.investigation, analysis(complete=True))
        second = await self.state()
        self.assertEqual(second[0]["complete"], "true")
        codes = [row["clue_code"] for row in second[2]]
        self.assertEqual(codes.count("SENDER_ACTIVITY_INCOHERENT"), 1)
        self.assertNotIn("EVIDENCE_INCOMPLETE", codes)
        deep_hooks = [row for row in second[1] if row["run_order"] >= 100]
        self.assertEqual([row["hook_name"] for row in deep_hooks], ["deep_evidence", "sender_activity"])
        self.assertTrue(all(row["status"] == "ok" and row["error_type"] is None for row in deep_hooks))
        await persist_signals(self.pool, self.investigation, analysis(complete=True))
        self.assertEqual(await self.state(), second)

        await self.pool.execute("""INSERT INTO verdicts(investigation_id,classification,source,confidence,rationale,is_binding)
            VALUES($1::uuid,'suspect','test',0.9,'Verdict accepté de test',true)""", self.investigation)
        frozen = await self.evidence_hash()
        await persist_signals(self.pool, self.investigation, analysis(complete=False))
        self.assertEqual(await self.evidence_hash(), frozen)

    async def test_deux_premiers_passages_attendent_le_verrou_avant_de_decider_de_remplacer(self):
        await self.transaction.commit()
        self.transaction = None
        marker = "pending-observations-" + uuid.uuid4().hex
        pool = await asyncpg.create_pool(DSN, min_size=2, max_size=2,
                                        server_settings={"application_name": marker})
        blocker = self.connection.transaction()
        await blocker.start()
        await self.connection.execute("SELECT id FROM investigations WHERE id=$1::uuid FOR UPDATE", self.investigation)
        tasks = [asyncio.create_task(persist_signals(pool, self.investigation, analysis(complete=True))) for _ in range(2)]
        try:
            # Les deux transactions doivent atteindre le verrou détenu ici.
            # Avant le correctif, elles avaient déjà lu toutes deux EXISTS=false.
            async with asyncio.timeout(2):
                while await self.connection.fetchval("""SELECT count(*) FROM pg_stat_activity
                        WHERE application_name=$1 AND wait_event_type='Lock'""", marker) < 2:
                    await asyncio.sleep(0.005)
            await blocker.commit()
            blocker = None
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=2)
            state = await self.state()
            self.assertEqual([r["clue_code"] for r in state[2]].count("SENDER_ACTIVITY_INCOHERENT"), 1)
            self.assertEqual(len([r for r in state[1] if r["run_order"] >= 100]), 2)
        finally:
            if blocker is not None:
                await blocker.rollback()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await pool.close()

    async def test_la_retention_efface_la_vue_le_cache_et_les_anciennes_tentatives(self):
        self.assertTrue(await self.pool.fetchval("SELECT facts ? 'visible_content' FROM messages WHERE id=$1::uuid", self.message))
        await self.pool.execute("""UPDATE messages SET captured_at=now()-interval '40 days',delivery_status='delivered',
            facts=facts || '{"preserved":true}'::jsonb WHERE id=$1::uuid""", self.message)
        await self.pool.execute("""INSERT INTO observation_cache(message_id,stage,fingerprint,result,expires_at)
            VALUES($1::uuid,'test',$2,'{"observed":true}',now()+interval '1 day')""", self.message, "a"*64)
        ids = []
        for days in (200, 10):
            ids.append(await self.pool.fetchval("""INSERT INTO llm_attempt_events(message_id,purpose,created_at)
                VALUES($1::uuid,'retention_test',now()-($2*interval '1 day')) RETURNING id""", self.message, days))
        await redact_expired(self.pool, 30, 100)
        row = await self.pool.fetchrow("SELECT raw_eml,facts FROM messages WHERE id=$1::uuid", self.message)
        facts = json.loads(row["facts"])
        self.assertIsNone(row["raw_eml"])
        self.assertNotIn("visible_content", facts)
        self.assertTrue(facts["preserved"])
        self.assertEqual(await self.pool.fetchval("SELECT count(*) FROM observation_cache WHERE message_id=$1::uuid", self.message), 0)
        await delete_expired(self.pool, 180, 100)
        self.assertFalse(await self.pool.fetchval("SELECT EXISTS(SELECT 1 FROM llm_attempt_events WHERE id=$1)", ids[0]))
        self.assertTrue(await self.pool.fetchval("SELECT EXISTS(SELECT 1 FROM llm_attempt_events WHERE id=$1)", ids[1]))
        self.assertTrue(await self.pool.fetchval("SELECT EXISTS(SELECT 1 FROM messages WHERE id=$1::uuid)", self.message))
