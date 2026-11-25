"""Portée et plans du superviseur sur PostgreSQL local, données synthétiques."""
from __future__ import annotations

import json
import os
import unittest
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import asyncpg
from sentimail_v3.supervision import watchdog
from test_watchdog import _FreshBackup, _SnapshotPool, _snapshot_settings

DSN = os.environ.get("WATCHDOG_TEST_DATABASE_URL", "")


class _Requetes(_SnapshotPool):
    def __init__(self):
        super().__init__()
        self.queries = []

    async def fetchrow(self, query, *args):
        self.queries.append((query, args))
        return await super().fetchrow(query, *args)

    async def fetchval(self, query, *args):
        self.queries.append((query, args))
        return await super().fetchval(query, *args)


@unittest.skipUnless(DSN, "base PostgreSQL locale jetable requise")
class SupervisionSQLPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        self.connection = await asyncpg.connect(DSN)
        await self.connection.execute("""
            CREATE TEMP TABLE messages(id uuid,captured_at timestamptz,delivery_status text,from_header text);
            CREATE TEMP TABLE investigations(id uuid,message_id uuid,status text,started_at timestamptz);
            CREATE TEMP TABLE delivery_cases(id uuid,message_id uuid,investigation_id uuid,
                binding boolean,original_delivery_allowed boolean,details jsonb,state text);
            CREATE TEMP TABLE verdict_runs(investigation_id uuid,status text,completed_at timestamptz,
                created_at timestamptz,started_at timestamptz,next_attempt_at timestamptz,
                input_snapshot jsonb,response jsonb);
            CREATE TEMP TABLE delivery_events(case_id uuid,event_type text,smtp_queue_id text,created_at timestamptz);
            CREATE TEMP TABLE hook_runs(investigation_id uuid,hook_name text,status text,created_at timestamptz,facts jsonb);
            CREATE TEMP TABLE entities(message_id uuid,entity_type text,role text,enrichment_id bigint);
            CREATE TEMP TABLE enrichments(id bigint,status text);
            CREATE TEMP TABLE external_analyses(message_id uuid,status text,error_type text,
                completed_at timestamptz,started_at timestamptz,subject_kind text);
            CREATE TEMP TABLE conversation_messages(processing_status text,created_at timestamptz);
            CREATE TEMP TABLE smtp_actions(id uuid,case_id uuid,action text);
            CREATE TEMP TABLE assistant_outbox(action_id uuid,status text);
            CREATE TEMP TABLE audit_log(action text,created_at timestamptz);
            CREATE TEMP TABLE verdict_llm_call_events(created_at timestamptz);
        """)
        recorder = _Requetes()
        with patch.object(watchdog, "BACKUP_HEARTBEAT", _FreshBackup()), patch.object(
            watchdog, "classifier_report", AsyncMock(return_value={})
        ):
            await watchdog._snapshot(recorder, _snapshot_settings())
        self.queries = recorder.queries

    async def asyncTearDown(self):
        await self.connection.close()

    def query(self, marker):
        return next((query, args) for query, args in self.queries if marker in query)

    async def test_fenetres_bornees_et_retards_historiques_conserves(self):
        for age, status in ((60, "analyzing"), (60, "release_pending"), (60, "delivered"), (0, "delivered")):
            message, case = uuid.uuid4(), uuid.uuid4()
            await self.connection.execute("""INSERT INTO messages VALUES($1,now()-$2*interval '1 day'
                -interval '20 minutes',$3,'sender@example.org')""", message, age, status)
            await self.connection.execute("INSERT INTO delivery_cases(id,message_id) VALUES($1,$2)", case, message)
        query, args = self.query("AS analysis_backlog")
        result = await self.connection.fetchrow(query, *args)
        self.assertEqual((result["analysis_backlog"], result["delivery_backlog"]), (1, 1))
        query, args = self.query("AS delivered_without_smtp_event")
        result = await self.connection.fetchrow(query, *args)
        self.assertEqual(result["delivered_without_smtp_event"], 1)
        self.assertEqual(result["accepted_without_terminal_outcome"], 0)
        await self.connection.execute("""INSERT INTO verdict_llm_call_events VALUES
            (now()-interval '40 days'),(now()-interval '10 hours'),(now()-interval '30 minutes')""")
        quota, args = self.query("AS hourly")
        result = await self.connection.fetchrow(quota, *args)
        self.assertEqual((result["hourly"], result["daily"]), (1, 2))
        original = quota.replace("\n        WHERE created_at > now()-interval '24 hours'", "")
        self.assertEqual(dict(result), dict(await self.connection.fetchrow(original)))

    async def dossier(self, provider, *, schema="sentimail-authenticated-sender-policy-v1",
                      event=True, binding=True, status="suppressed", case_state=None):
        message, investigation, case = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        decision = "deliver" if provider == "express_path" else "suppress"
        classification = "legitimate" if decision == "deliver" else "undetermined"
        await self.connection.execute("INSERT INTO messages VALUES($1,now()-interval '20 minutes',$2,'sender@example.org')", message, status)
        await self.connection.execute("INSERT INTO investigations VALUES($1,$2,'complete',now()-interval '20 minutes')", investigation, message)
        await self.connection.execute("INSERT INTO delivery_cases VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)",
            case, message, investigation, binding, decision == "deliver",
            json.dumps({"final_judgment": {"delivery_decision": decision}}),
            case_state or ("original_delivered" if decision == "deliver" else "policy_suppressed"))
        await self.connection.execute("""INSERT INTO verdict_runs
            VALUES($1,'complete',now()-interval '15 minutes',now()-interval '20 minutes',
                now()-interval '20 minutes',NULL,$2::jsonb,$3::jsonb)""", investigation,
            json.dumps({"schema": schema}), json.dumps({"api": {"provider": provider},
                "verdict": {"delivery_decision": decision, "classification": classification}}))
        if event:
            await self.connection.execute("INSERT INTO delivery_events VALUES($1,$2,'QUEUE',now()-interval '15 minutes')",
                case, "original_delivered" if decision == "deliver" else "policy_suppressed")
        return investigation

    async def test_exemption_uniquement_si_parcours_rapide_et_execution_prouves(self):
        valid_policy = await self.dossier("authenticated_sender_policy")
        valid_otp = await self.dossier("express_path", status="delivered")
        invalids = [await self.dossier("authenticated_sender_policy", event=False),
            await self.dossier("authenticated_sender_policy", schema="ordinaire"),
            await self.dossier("authenticated_sender_policy", binding=False),
            await self.dossier("authenticated_sender_policy", status="held"),
            await self.dossier("authenticated_sender_policy", case_state="awaiting_reply"),
            await self.dossier("openai_compatible", status="held")]
        for investigation, expected in [(valid_policy, True), (valid_otp, True), *[(value, False) for value in invalids]]:
            with self.subTest(investigation=investigation):
                exempt = await self.connection.fetchval(f"""SELECT {watchdog.DEEP_ANALYSIS_NOT_APPLICABLE_SQL}
                    FROM verdict_runs vr JOIN investigations i ON i.id=vr.investigation_id
                    WHERE i.id=$1""", investigation)
                self.assertEqual(exempt, expected)
        query, args = self.query("AS missing_deep_evidence")
        result = await self.connection.fetchrow(query, *args)
        self.assertEqual(result["missing_deep_evidence"], 6)
        self.assertEqual(result["sender_domain_enrichment_gaps"], 6)
        await self.connection.execute("INSERT INTO audit_log VALUES('code.action_destination_coherence',now()-interval '2 days')")
        for investigation in (valid_policy, valid_otp, *invalids):
            await self.connection.execute("INSERT INTO hook_runs VALUES($1,'deep_evidence','ok',now(),'{}')", investigation)
        query, args = self.query("AS missing_deep_hook_runs")
        self.assertEqual(await self.connection.fetchval(query, *args), 6)
        for investigation in (valid_policy, valid_otp, invalids[-1]):
            await self.connection.execute("INSERT INTO hook_runs VALUES($1,'sender_activity','error',now(),'{}')", investigation)
        query, args = self.query("AS coherence_hook_failures")
        self.assertEqual(await self.connection.fetchval(query, *args), 1)
        for investigation in (valid_policy, valid_otp, invalids[-1]):
            await self.connection.execute("INSERT INTO hook_runs VALUES($1,'sender_relation','skip',now(),'{}')", investigation)
        query, args = self.query("AS sender_relation_silent")
        self.assertEqual(await self.connection.fetchval(query, *args), 1)

    async def test_plans_synthetiques_des_indexes_recents(self):
        await self.connection.execute("""
            INSERT INTO audit_log SELECT CASE WHEN n%100=0 THEN 'classifier.error' ELSE 'autre' END,
                now()-n*interval '1 minute' FROM generate_series(0,59999) n;
            INSERT INTO hook_runs(hook_name,status,created_at,facts)
                SELECT CASE WHEN n%10=0 THEN 'sender_relation' ELSE 'autre' END,
                    CASE WHEN n%50=0 THEN 'error' ELSE 'ok' END,
                    now()-n*interval '1 minute','{}'::jsonb FROM generate_series(0,119999) n;
            ANALYZE audit_log; ANALYZE hook_runs;
        """)
        queries = {
            "audit_recent": "SELECT count(*) FROM audit_log WHERE action='classifier.error' AND created_at>now()-interval '1 hour'",
            "hook_recent": "SELECT count(*) FROM hook_runs WHERE hook_name='sender_relation' AND created_at>now()-interval '1 hour'",
            "hook_error_recent": "SELECT count(*) FROM hook_runs WHERE status='error' AND created_at>now()-interval '1 hour'",
        }
        async def plans():
            result = {}
            for name, query in queries.items():
                value = json.loads(await self.connection.fetchval("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + query))[0]
                plan = value["Plan"]
                result[name] = {"execution_ms": value["Execution Time"],
                    "blocks": sum(plan.get(key, 0) for key in ("Shared Hit Blocks","Shared Read Blocks","Local Hit Blocks","Local Read Blocks")),
                    "plan": plan, "count": await self.connection.fetchval(query)}
            return result
        before = await plans()
        migration = Path(__file__).resolve().parents[2] / "database/init/108_index_supervision.sql"
        await self.connection.execute(migration.read_text())
        await self.connection.execute("ANALYZE audit_log; ANALYZE hook_runs")
        after = await plans()
        report = {"author": "J. Martin", "population": {"audit_rows": 60000, "hook_rows": 120000}, "before": before, "after": after}
        for name in queries:
            with self.subTest(query=name):
                self.assertEqual(before[name]["count"], after[name]["count"])
                self.assertLess(after[name]["blocks"], before[name]["blocks"])
                self.assertIn("Index", json.dumps(after[name]["plan"]))
        if path := os.environ.get("WATCHDOG_PLAN_REPORT_PATH"):
            Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2))
