"""Contrôle déterministe avant acceptation, sans retenue pour sa seule panne."""
from __future__ import annotations

import os
import unittest
import uuid
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import urlsplit

import asyncpg
from sentimail_v3.judgment import workflow as engine
from sentimail_v3.judgment import model_selection
from sentimail_v3.judgment.model_routing import ModelRouting
from sentimail_v3.judgment.verdict_retry import RetryPlan
from sentimail_v3.llm import LlmError

CONTEXT = {"prompt_version": "prompt", "corpus_sha256": "a"*64, "rules_version": "rules"}
ECONOMY = {"classification": "legitimate", "delivery_decision": "deliver", "confidence": .99,
           "attack": {}, "verdict_doubt": False}
HELD = {"classification": "suspect", "delivery_decision": "ask_user", "confidence": .95,
        "attack": {}, "verdict_doubt": True}
DSN = os.environ.get("MODEL_ROUTING_TEST_DATABASE_URL", "")


def run_id(selected):
    return next(str(uuid.UUID(int=i)) for i in range(1,1000)
                if engine._routing_audit_sample(uuid.UUID(int=i)) == selected)


class ControleContinuTests(unittest.IsolatedAsyncioTestCase):
    async def process(self, *, selected=True, mode="enforced", reference=None, failure=None, confidence=.99, contexts=None, parse_failure=None):
        run = {"id": run_id(selected), "investigation_id": str(uuid.uuid4()), "message_id": str(uuid.uuid4()),
               "model_name": "pro", "attempts": 1, "model_tier": None}
        economy = {**ECONOMY, "confidence": confidence}
        dossier = {"clues": [{"direction": "favorable"}], "judgment_rules": {
            "confidence_required": .9, "static_investigation_complete": True,
            "deep_execution_complete": True, "incomplete_analysis_is_decisive": True}}
        calls, changes = [], []
        async def model(*args, **kwargs):
            calls.append(kwargs)
            if kwargs["stage"] == "premium" and failure:
                raise failure
            return kwargs["stage"], {"provider": "openai_compatible", "model": kwargs["model_name"]}, 1.0
        async def complete(*args, **kwargs):
            changes.append(("accepted", args[3]))
            return run["message_id"]
        async def shadow(*args):
            changes.append(("future_shadow", None))
        def parse_final(*args):
            if parse_failure:
                raise parse_failure
            return reference or dict(ECONOMY), []
        mocks = {
            "move": AsyncMock(), "read_proven_identity": AsyncMock(return_value=None),
            "authenticated_hold": AsyncMock(return_value=False), "_express_judgment": AsyncMock(return_value=None),
            "analyze_message": AsyncMock(return_value={"complete": True}), "persist_signals": AsyncMock(),
            "load_model_routing": AsyncMock(return_value=ModelRouting(mode,"flash","pro",.05)),
            "qualification_context": AsyncMock(side_effect=contexts, return_value=CONTEXT), "_build_dossier": AsyncMock(return_value=dossier),
            "_prepare_for_judgment": lambda d,*_:d, "_authenticated_suppression": lambda _:None,
            "_call_verdict_model": AsyncMock(side_effect=model), "_record_model_route": AsyncMock(),
            "_parse_verdict": lambda *_:economy,
            "_parse_final_response": parse_final,
            "_record_shadow_evaluation": AsyncMock(), "_shadow_after_unsafe_audit": AsyncMock(side_effect=shadow),
            "_complete": AsyncMock(side_effect=complete), "release_original": AsyncMock(return_value="delivered"),
            "hold_with_review_or_fail_open": AsyncMock(return_value="review_notice_queued"),
            "_mark_error": AsyncMock(return_value=RetryPlan("exhausted")), "_log": Mock(),
        }
        pool = SimpleNamespace(fetchval=AsyncMock(return_value=run["message_id"]), execute=AsyncMock())
        with ExitStack() as stack:
            for name, value in mocks.items():
                stack.enter_context(patch.object(engine, name, value))
                if hasattr(model_selection, name):
                    stack.enter_context(patch.object(model_selection, name, value))
            stack.enter_context(patch.object(engine.classifier_runtime, "attempt", AsyncMock(return_value=None)))
            stack.enter_context(patch.object(engine.classifier_runtime, "observe", AsyncMock()))
            self.assertTrue(await engine._process_run(pool,None,SimpleNamespace(decision_mode=True),None,run))
        return mocks, calls, changes

    def test_echantillon_stable_et_independant_des_correspondants(self):
        values = [str(uuid.UUID(int=i)) for i in range(1,1000)]
        selected = {v for v in values if engine._routing_audit_sample(v)}
        self.assertGreater(len(selected), 20)
        self.assertLess(len(selected), 80)
        self.assertEqual(selected, {v for v in values if engine._routing_audit_sample(v)})

    async def test_selection_eligible_compare_et_conserve_flash_si_accord(self):
        mocks, calls, changes = await self.process()
        self.assertEqual([c["stage"] for c in calls], ["economy","premium"])
        mocks["_mark_error"].assert_not_awaited()
        mocks["_shadow_after_unsafe_audit"].assert_not_awaited()
        self.assertEqual(changes[-1][1]["delivery_decision"], "deliver")
        self.assertEqual(mocks["_complete"].await_args.args[4]["model"], "flash")
        self.assertEqual(mocks["_record_shadow_evaluation"].await_args.kwargs["context"], CONTEXT)

    async def test_non_selection_ne_coute_aucune_reference(self):
        mocks, calls, _ = await self.process(selected=False)
        self.assertEqual([c["stage"] for c in calls], ["economy"])
        mocks["_record_shadow_evaluation"].assert_not_awaited()
        mocks["qualification_context"].assert_not_awaited()

    async def test_revision_du_corpus_pendant_reference_conserve_contexte_du_dossier_fige(self):
        mocks, _, _ = await self.process(contexts=[CONTEXT, CONTEXT, {**CONTEXT, "corpus_sha256": "b"*64}])
        self.assertEqual(mocks["_record_shadow_evaluation"].await_args.kwargs["context"], CONTEXT)
        mocks["_mark_error"].assert_not_awaited()
        self.assertIn("verdict.audit_context_changed", [c.args[0] for c in mocks["_log"].call_args_list])

    async def test_proposition_pro_invalide_ne_remplace_jamais_flash_valide(self):
        mocks, _, changes = await self.process(parse_failure=ValueError("référence incohérente"))
        self.assertEqual(changes[-1][1]["delivery_decision"], "deliver")
        self.assertEqual(mocks["_complete"].await_args.args[4]["model"], "flash")
        mocks["_mark_error"].assert_not_awaited()
        mocks["_record_shadow_evaluation"].assert_not_awaited()
        mocks["_shadow_after_unsafe_audit"].assert_not_awaited()

    async def test_reference_indisponible_ou_quota_ne_bloque_pas_flash_valide(self):
        for failure in (LlmError("indisponible"), engine.VerdictQuotaExceeded("global_daily")):
            with self.subTest(failure=failure):
                mocks, _, changes = await self.process(failure=failure)
                mocks["_mark_error"].assert_not_awaited()
                mocks["_record_shadow_evaluation"].assert_not_awaited()
                mocks["_shadow_after_unsafe_audit"].assert_not_awaited()
                self.assertEqual(changes[-1][1]["delivery_decision"], "deliver")
                self.assertIn("verdict.audit_reference_unavailable", [c.args[0] for c in mocks["_log"].call_args_list])

    async def test_divergence_pro_appliquee_avant_acceptation_et_future_config_seule(self):
        mocks, _, changes = await self.process(reference=HELD)
        self.assertEqual([event[0] for event in changes], ["future_shadow","accepted"])
        self.assertEqual(changes[-1][1]["delivery_decision"], "ask_user")
        self.assertEqual(mocks["_complete"].await_count, 1)
        self.assertEqual(mocks["_complete"].await_args.args[4]["model"], "pro")
        mocks["_mark_error"].assert_not_awaited()

    async def test_escalade_reelle_garde_reference_obligatoire(self):
        mocks, calls, changes = await self.process(confidence=.91, failure=LlmError("indisponible"))
        self.assertEqual([c["stage"] for c in calls], ["economy","premium"])
        mocks["_mark_error"].assert_awaited_once()
        mocks["_complete"].assert_not_awaited()
        self.assertEqual(changes, [])

    async def test_mode_off_conserve_appel_historique(self):
        mocks, calls, _ = await self.process(mode="off")
        self.assertEqual([c["stage"] for c in calls], ["single"])
        self.assertTrue(calls[0]["allow_local"])
        mocks["_record_shadow_evaluation"].assert_not_awaited()
        mocks["_shadow_after_unsafe_audit"].assert_not_awaited()
        mocks["qualification_context"].assert_not_awaited()


@unittest.skipUnless(DSN, "base PostgreSQL locale jetable requise")
class RetrogradationPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def test_cas_cible_exacte_audite_une_fois_et_preserve_choix_operateur(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        connection = await asyncpg.connect(DSN)
        try:
            await connection.execute("""CREATE TEMP TABLE verdict_model_routing
                (LIKE public.verdict_model_routing INCLUDING ALL);
                CREATE TEMP TABLE audit_log (LIKE public.audit_log INCLUDING ALL);
                INSERT INTO verdict_model_routing(mode,economy_model_name,premium_model_name,confidence_margin)
                VALUES('enforced','flash','pro',0.05)""")
            run = {"id": str(uuid.uuid4())}
            await engine._shadow_after_unsafe_audit(connection, run, ModelRouting("enforced","flash","pro",.04))
            self.assertEqual(await connection.fetchval("SELECT mode FROM verdict_model_routing"), "enforced")
            await engine._shadow_after_unsafe_audit(connection, run, ModelRouting("enforced","flash","pro",.05))
            self.assertEqual(await connection.fetchval("SELECT mode FROM verdict_model_routing"), "shadow")
            self.assertEqual(await connection.fetchval("SELECT count(*) FROM audit_log"), 1)
            await engine._shadow_after_unsafe_audit(connection, run, ModelRouting("enforced","flash","pro",.05))
            self.assertEqual(await connection.fetchval("SELECT count(*) FROM audit_log"), 1)
            await connection.execute("UPDATE verdict_model_routing SET mode='enforced',premium_model_name='choix-operateur'")
            await engine._shadow_after_unsafe_audit(connection, run, ModelRouting("enforced","flash","pro",.05))
            self.assertEqual(await connection.fetchval("SELECT mode FROM verdict_model_routing"), "enforced")
            self.assertEqual(await connection.fetchval("SELECT count(*) FROM audit_log"), 1)
        finally:
            await connection.close()
