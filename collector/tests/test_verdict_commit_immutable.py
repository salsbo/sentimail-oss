"""Un échec d'exécution ne rend jamais un jugement accepté rejouable."""

from __future__ import annotations

from contextlib import ExitStack, asynccontextmanager
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit
from uuid import uuid4

import asyncpg

from sentimail_v3.judgment import claims, classifier_runtime, commit, core_compare, workflow
from sentimail_v3.judgment.model_routing import ModelRouting
from sentimail_v3.judgment.response import _judgment_execution, _parse_verdict
from sentimail_v3.llm import LlmError

DSN = os.environ.get("VERDICT_COMMIT_TEST_DATABASE_URL", os.environ.get("ENRICHER_TEST_DATABASE_URL", ""))


def _response():
    return json.dumps({"final_verdict": {"classification": "spam", "delivery_decision": "junk", "confidence": .99,
                                       "rationale": "Constat fictif pour vérifier la reprise."}})


def _dossier():
    return {"schema": "test", "clues": [], "message": {"investigation_status": "complete"},
            "judgment_rules": {"verdict_is_final": True, "confidence_required": .9,
                               "static_investigation_complete": True, "deep_execution_complete": True}}


def _fresh_reference():
    path = Path(__file__).parent / "reference" / "verdict_engine_b07a5ec.py"
    spec = importlib.util.spec_from_file_location("sentimail_postcommit_reference_" + uuid4().hex, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RetryLedgerTests(unittest.IsolatedAsyncioTestCase):
    async def test_les_essais_non_acceptes_gardent_leurs_effets_et_echeances(self):
        for attempts in (1, 2, 3, 4):
            for transient in (False, True):
                with self.subTest(attempts=attempts, transient=transient):
                    result = await core_compare.compare_retry(attempts, transient)
                    self.assertTrue(result["agreement"])
                    self.assertEqual(result["legacy"]["state"], result["candidate"]["state"])

    async def test_la_protection_d_un_accepte_est_un_invariant_corrige_pas_un_faux_accord(self):
        old = _fresh_reference()
        # L'adaptateur legacy et le banc conservent deux fonctions distinctes.
        original = old._mark_error
        with patch.object(core_compare, "reference", return_value=old), \
             patch.object(old, "_process_run", AsyncMock(return_value=True)):
            await core_compare.run_legacy(None, None, None, None, {})
            self.assertIs(old._mark_error, commit._mark_error)
            self.assertIs(old._unadapted_mark_error, original)
            result = await core_compare.compare_retry(1, False, accepted=True)
        self.assertFalse(result["agreement"])
        self.assertEqual(result["legacy"]["state"]["status"], "error")
        self.assertEqual(result["candidate"]["state"]["status"], "complete")
        self.assertEqual(result["candidate"]["plan"]["kind"], "accepted")


class _PinnedPool:
    def __init__(self, connection):
        self.connection = connection

    def __getattr__(self, name):
        return getattr(self.connection, name)

    @asynccontextmanager
    async def acquire(self):
        yield self.connection


@unittest.skipUnless(DSN, "PostgreSQL local jetable requis")
class CommitImmutablePostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        self.connection = await asyncpg.connect(DSN)
        self.transaction = self.connection.transaction()
        await self.transaction.start()
        self.pool = _PinnedPool(self.connection)
        for table in ("messages", "investigations", "verdict_runs", "verdicts", "delivery_cases", "training_samples", "audit_log"):
            await self.connection.execute(f"CREATE TEMP TABLE {table} (LIKE public.{table} INCLUDING ALL)")
        self.settings = SimpleNamespace(decision_mode=True, verdict_not_before=None, analysis_wait_seconds=30,
                                        deepseek_verdict_model="test", auto_delivery_confidence=.9)

    async def asyncTearDown(self):
        await self.transaction.rollback()
        await self.connection.close()

    async def fixture(self, generation="core-v1"):
        message = await self.connection.fetchval("""INSERT INTO messages(
            ingest_key,envelope_from,envelope_recipients,raw_sha256,raw_size_bytes,
            headers_size_bytes,body_size_bytes,line_count,max_line_length,contains_8bit,
            contains_nul,line_ending,root_content_type,parser_version,engine_generation)
            VALUES($1,'sender@example.org','{}',repeat('a',64),1,1,0,1,1,false,false,
                'CRLF','text/plain','test',$2) RETURNING id""", uuid4().hex, generation)
        investigation = await self.connection.fetchval("""INSERT INTO investigations(message_id,edition_id,status,completed_at)
            SELECT $1,id,'complete',now() FROM code_editions WHERE status='active' ORDER BY created_at LIMIT 1 RETURNING id""", message)
        await self.connection.execute("""INSERT INTO delivery_cases(message_id,investigation_id,state)
            VALUES($1,$2,'analysis_pending')""", message, investigation)
        run = await claims._claim(self.pool, self.settings)
        self.assertIsNotNone(run)
        return run

    async def accept(self, run, *, binding=True):
        dossier = _dossier()
        result = _parse_verdict(_response(), dossier)
        await commit._complete(self.pool, run, dossier, result, {"provider": "test", "model": "test"}, 1.,
            binding=binding, original_delivery_allowed=True, judgment=_judgment_execution(result), training_eligible=False)

    async def snapshot(self, run):
        return [await self.connection.fetchval("SELECT to_jsonb(vr)::text FROM verdict_runs vr WHERE id=$1", run["id"]),
                await self.connection.fetchval("SELECT jsonb_agg(to_jsonb(v) ORDER BY id)::text FROM verdicts v WHERE investigation_id=$1", run["investigation_id"])]

    async def test_complete_et_binding_ne_peuvent_pas_etre_rouverts(self):
        for binding in (False, True):
            with self.subTest(binding=binding):
                run = await self.fixture()
                await self.accept(run, binding=binding)
                before = await self.snapshot(run)
                for error in (RuntimeError("échec d'exécution"), LlmError("LLM HTTP 503")):
                    plan = await commit._mark_error(self.pool, run, error)
                    self.assertEqual(plan.kind, "accepted")
                    self.assertFalse(plan.exhausted)
                    self.assertEqual(await self.snapshot(run), before)
                self.assertIsNone(await claims._claim(self.pool, self.settings))
                if binding:
                    # Même une ligne laissée en erreur par l'ancien traitement
                    # ne peut plus rendre le jugement du destinataire rejouable.
                    await self.connection.execute("""UPDATE verdict_runs SET status='error',completed_at=NULL,
                        started_at=now()-interval '1 hour',next_attempt_at=NULL WHERE id=$1""", run["id"])
                    before = await self.snapshot(run)
                    self.assertEqual((await commit._mark_error(self.pool, run, RuntimeError("panne"))).kind, "accepted")
                    self.assertEqual(await self.snapshot(run), before)
                    self.assertIsNone(await claims._claim(self.pool, self.settings))

    async def test_un_echec_avant_acceptation_reste_reprenable(self):
        run = await self.fixture()
        plan = await commit._mark_error(self.pool, run, LlmError("LLM HTTP 503"))
        self.assertEqual(plan.kind, "scheduled")
        self.assertIsNone(await claims._claim(self.pool, self.settings))
        await self.connection.execute("UPDATE verdict_runs SET next_attempt_at=now()-interval '1 second' WHERE id=$1", run["id"])
        resumed = await claims._claim(self.pool, self.settings)
        self.assertEqual((resumed["id"], resumed["attempts"]), (run["id"], 2))

    async def test_panne_postcommit_core_et_legacy_ne_rappelle_ni_juge_ni_smtp(self):
        for generation in ("core-v1", "legacy"):
            with self.subTest(generation=generation):
                run = await self.fixture(generation)
                old = _fresh_reference()
                engine = workflow if generation == "core-v1" else old
                result = _parse_verdict(_response(), _dossier())
                candidate = AsyncMock(return_value=(result, {"provider": "test", "model": "test"}, 1., []))
                model = AsyncMock(return_value=(_response(), {"provider": "test", "model": "test"}, 1.))
                release, review = AsyncMock(), AsyncMock()
                patches = {
                    "read_proven_identity": AsyncMock(return_value=None),
                    "authenticated_hold": AsyncMock(return_value=False), "_express_judgment": AsyncMock(return_value=None),
                    "analyze_message": AsyncMock(return_value={"complete": True}), "persist_signals": AsyncMock(),
                    "load_model_routing": AsyncMock(return_value=ModelRouting("off", "test", "test", 0)),
                    "_build_dossier": AsyncMock(return_value=_dossier()),
                    "choose_candidate": candidate, "_call_verdict_model": model,
                    "_record_model_route": AsyncMock(), "release_original": release,
                    "hold_with_review_or_fail_open": review,
                    "technique_pedagogy": AsyncMock(side_effect=RuntimeError("lecture postcommit indisponible")),
                }
                with ExitStack() as stack:
                    for name, value in patches.items():
                        if hasattr(engine, name):
                            stack.enter_context(patch.object(engine, name, value))
                    stack.enter_context(patch.object(core_compare, "before_commit", AsyncMock()))
                    stack.enter_context(patch.object(core_compare, "before_model", AsyncMock()))
                    stack.enter_context(patch.object(core_compare, "reference", return_value=old))
                    stack.enter_context(patch.object(workflow, "before_commit", AsyncMock()))
                    stack.enter_context(patch.object(workflow, "before_model", AsyncMock()))
                    stack.enter_context(patch.object(classifier_runtime, "attempt", AsyncMock(return_value=None)))
                    stack.enter_context(patch.object(classifier_runtime, "observe", AsyncMock()))
                    if generation == "core-v1":
                        self.assertTrue(await workflow._process_run(self.pool, None, self.settings, None, run))
                    else:
                        self.assertTrue(await core_compare.run_legacy(self.pool, None, self.settings, None, run))
                    self.assertFalse(await workflow._process_one(self.pool, None, self.settings, None))
                self.assertEqual(candidate.await_count if generation == "core-v1" else model.await_count, 1)
                release.assert_not_awaited()
                review.assert_not_awaited()
                self.assertEqual(await self.connection.fetchval("SELECT status FROM verdict_runs WHERE id=$1", run["id"]), "complete")
                self.assertEqual(await self.connection.fetchval("SELECT count(*) FROM verdicts WHERE investigation_id=$1 AND is_binding", run["investigation_id"]), 1)
