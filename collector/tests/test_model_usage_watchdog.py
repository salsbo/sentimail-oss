"""La consommation inclut tous les rôles sans confondre messages et tentatives."""

import json
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlsplit

import asyncpg

from sentimail_v3.supervision.watchdog import _model_usage_24h

DSN = os.environ.get("WATCHDOG_TEST_DATABASE_URL", "")


class ConsommationFailSoftTests(unittest.IsolatedAsyncioTestCase):
    async def test_erreur_de_journal_ne_casse_pas_la_supervision_ni_ne_fuit_son_message(self):
        pool = SimpleNamespace(fetchval=AsyncMock(side_effect=RuntimeError("contenu confidentiel")))
        result = await _model_usage_24h(pool)
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["error_type"], "RuntimeError")
        self.assertNotIn("confidentiel", json.dumps(result))


@unittest.skipUnless(DSN, "base PostgreSQL locale jetable requise")
class ConsommationPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def test_fenetre_24h_groupes_et_denominateur_global_deduplice(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        connection = await asyncpg.connect(DSN)
        try:
            await connection.execute("CREATE TEMP TABLE llm_attempt_events (LIKE public.llm_attempt_events INCLUDING ALL)")
            end = datetime(2026, 10, 30, 12, 30, tzinfo=timezone.utc)
            first, second = uuid.uuid4(), uuid.uuid4()
            rows = [
                (first, "analysis", "flash", "complete", 10, 2, 3, None, end-timedelta(hours=2)),
                (first, "verdict", "pro", "complete", 20, 3, 6, 4, end-timedelta(hours=1)),
                (None, "analysis", "flash", "error", None, None, None, None, end-timedelta(minutes=50)),
                (second, "verdict", "pro", "cancelled", 5, None, None, None, end-timedelta(minutes=40)),
                (second, "verdict", "pro", "started", None, None, None, None, end-timedelta(minutes=30)),
                (first, "analysis", "flash", "complete", 999, 99, None, None, end-timedelta(hours=25)),
                (first, "analysis", "flash", "complete", 888, 88, None, None, end),
            ]
            await connection.executemany("""INSERT INTO llm_attempt_events
                (message_id,role,model_name,status,input_tokens,output_tokens,cache_read_tokens,cache_creation_tokens,created_at,provider)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'openai_compatible')""", rows)
            result = await _model_usage_24h(connection, as_of=end)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["window_start_utc"], (end-timedelta(hours=24)).isoformat())
            self.assertEqual(result["window_end_utc"], end.isoformat())
            self.assertEqual((result["attempts"], result["distinct_messages"], result["unattributed_attempts"]), (5, 2, 1))
            self.assertEqual(result["usage_reported"], 3)
            self.assertEqual(sum(g["distinct_messages"] for g in result["groups"]), 3)
            self.assertEqual(sum(g["input_tokens"] for g in result["groups"]), 35)
            self.assertEqual(sum(g["output_tokens"] for g in result["groups"]), 5)
            self.assertEqual(sum(g["cache_read_tokens"] for g in result["groups"]), 9)
            self.assertEqual(sum(g["cache_creation_tokens"] for g in result["groups"]), 4)
            self.assertEqual({key: sum(g[key] for g in result["groups"]) for key in ("complete","error","cancelled","started")},
                             {"complete": 2, "error": 1, "cancelled": 1, "started": 1})
        finally:
            await connection.close()
