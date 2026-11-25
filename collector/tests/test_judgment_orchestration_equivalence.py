"""Deux moteurs indépendants parcourent les mêmes frontières, sans réseau.

Les adaptateurs d'entrée et de sortie sont simulés. Le choix du modèle,
les réservations, le prompt, le décodage, les barrières et l'ordonnancement
restent ceux de chaque implémentation. La trace compare aussi le contenu
accepté, avant toute action de livraison ou de notification.
"""

from __future__ import annotations

import asyncio
import copy
from contextlib import ExitStack, asynccontextmanager
from functools import lru_cache
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from unittest.mock import AsyncMock
from urllib.parse import urlsplit
from uuid import uuid4

import asyncpg
from sentimail_v3.judgment import claims, classifier_runtime, commit, core_compare, dossier as dossier_module, response as response_module
from sentimail_v3.judgment import model_calls, model_selection, workflow
from sentimail_v3.judgment.core_compare import CoreComparisonError
from sentimail_v3.judgment.model_routing import ModelRouting
from sentimail_v3.llm import LlmError
from sentimail_v3.observation import storage

DSN = os.environ.get("CORE_ORCHESTRATION_TEST_DATABASE_URL", os.environ.get("ENRICHER_TEST_DATABASE_URL", ""))


@lru_cache(maxsize=1)
def _reference():
    path = Path(__file__).parent / "reference" / "verdict_engine_b07a5ec.py"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == "70a94f106b5462813c2742400a4ec90ff9969749e15bf6a35c11b72bddf2781f"
    spec = importlib.util.spec_from_file_location("sentimail_orchestration_reference_b07a5ec", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _response(decision="deliver", classification="legitimate", confidence=.99):
    return json.dumps({"final_verdict": {
        "classification": classification, "confidence": confidence,
        "delivery_decision": decision, "rationale": "Conclusion sur les pièces de test.",
    }}, ensure_ascii=False)


def _frozen(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


class _Bench:
    def __init__(self, case):
        self.case = case
        self.trace = []
        self.accepted = []
        self.run = {
            "id": "00000000-0000-0000-0000-000000000101",
            "investigation_id": "00000000-0000-0000-0000-000000000102",
            "message_id": "00000000-0000-0000-0000-000000000103",
            "model_name": "pro", "attempts": case.get("attempts", 1),
            "model_tier": case.get("model_tier"),
        }
        self.settings = SimpleNamespace(decision_mode=case.get("binding", True),
                                        auto_delivery_confidence=.9,
                                        economy_llm_deadline_seconds=30)
        self.context = {"prompt_version": "test", "corpus_sha256": "a" * 64, "rules_version": "test"}
        self.reservations = 0
        self.provider_calls = 0

    async def execute(self, query, *args):
        if "UPDATE verdict_llm_call_events" in query:
            self.trace.append(("model_event", "error" if "status='error'" in query else "complete", *args))
        elif "UPDATE verdict_runs SET status='error'" in query:
            self.trace.append(("retry", *args))
        elif "UPDATE delivery_cases" in query:
            self.trace.append(("delivery_details", *args))
        else:
            raise AssertionError("Écriture non prévue dans le banc : " + query[:80])
        return "UPDATE 1"

    async def fetch(self, query, *args):
        self.trace.append(("adverse_clues", *args))
        return []

    async def fetchval(self, query, *args):
        if "core_rollout_config" in query:
            return self.case.get("core_mode", "shadow")
        self.trace.append(("resolve_message", *args))
        return self.run["message_id"]

    async def _move(self, *args):
        self.trace.append(("move", args[-1]))

    async def _identity(self, *args):
        self.trace.append(("identity",))
        if self.case.get("identity_error"):
            raise RuntimeError("preuve temporairement absente")
        return None

    async def _hold(self, *args):
        self.trace.append(("policy",))
        return self.case.get("early_b", False)

    async def _express(self, *args):
        self.trace.append(("express",))
        if not self.case.get("otp"):
            return None
        return {"classification": "legitimate", "delivery_decision": "deliver", "confidence": 1.,
                "rationale": "Code à usage unique", "attack": {}, "supporting_clue_codes": [],
                "contradicting_clue_codes": [], "verdict_doubt": False}

    async def _express_dossier(self, *args):
        self.trace.append(("express_dossier",))
        return {"schema": "test-express", "message": {}, "clues": []}

    async def _analyze(self, *args):
        self.trace.append(("deep",))
        if self.case.get("deep_error"):
            raise RuntimeError("analyse indisponible")
        return {"complete": not self.case.get("incomplete"),
                "attachments_complete": not self.case.get("incomplete"),
                "history": {"persistent_hold": self.case.get("late_b", False)}}

    async def _persist(self, *args):
        self.trace.append(("persist_signals",))
        if self.case.get("persist_error"):
            raise RuntimeError("stockage indisponible")

    async def _routing(self, *args):
        self.trace.append(("routing",))
        return ModelRouting(self.case.get("routing", "off"), "flash", "pro", .05)

    async def _context(self, *args):
        self.trace.append(("context",))
        return dict(self.context)

    async def _dossier(self, *args, **kwargs):
        self.trace.append(("dossier",))
        clues = [{"id": 1, "clue_code": "AUTH_DMARC_PASS", "direction": "favorable", "strength": 20}]
        if self.case.get("mixed"):
            clues.append({"id": 2, "clue_code": "AUTH_DMARC_FAIL", "direction": "adverse", "strength": 20})
        return {"schema": "sentimail-dossier-v3", "message": {"investigation_status": "complete"}, "clues": clues}

    async def _reserve(self, *args, **kwargs):
        self.reservations += 1
        self.trace.append(("reserve", kwargs["model_name"], kwargs["stage"]))
        return self.reservations, None

    async def _provider(self, *args, **kwargs):
        self.provider_calls += 1
        # Les compléments par fournisseur (Claude) ne changent pas l'orchestration :
        # la trace compare l'ordre des appels, pas le texte transmis au transport.
        # Leur transmission est vérifiée dans test_llm.py.
        traced = {key: value for key, value in kwargs.items() if key != "provider_addenda"}
        self.trace.append(("provider", _frozen(traced)))
        if self.case.get("provider_error"):
            raise LlmError("LLM HTTP 503")
        if self.case.get("economy_error") and kwargs["model_override"] == "flash":
            raise LlmError("LLM HTTP 503")
        responses = self.case.get("responses", [_response()])
        content = responses[min(self.provider_calls - 1, len(responses) - 1)]
        return content, {"provider": "openai_compatible", "model": kwargs["model_override"]}

    async def _route(self, *args):
        self.trace.append(("route", *args[-2:]))

    async def _shadow(self, *args, **kwargs):
        self.trace.append(("shadow", _frozen(args[3:]), _frozen(kwargs)))

    async def _downgrade(self, *args):
        self.trace.append(("future_shadow",))

    async def _local(self, pool, run, dossier, parse):
        self.trace.append(("classifier",))
        if not self.case.get("local"):
            return None
        return {"use_local": True, "result": parse(_response(), dossier),
                "metadata": {"provider": "local_classifier", "model": "local-test"},
                "prediction": {"eligible": True}}

    async def _observe(self, *args):
        self.trace.append(("classifier_observe", _frozen(args[4]), _frozen(args[5])))

    async def _complete(self, pool, run, dossier, result, metadata, duration, **kwargs):
        self.trace.append(("commit_attempt",))
        if self.case.get("commit_error"):
            raise RuntimeError("transaction non validée")
        self.accepted.append(copy.deepcopy(result))
        self.trace.append(("accepted", _frozen(dossier), _frozen(result), _frozen(metadata), _frozen(kwargs)))
        return run["message_id"]

    async def _release(self, pool, settings, message_id, **kwargs):
        assert len(self.accepted) == 1, "La livraison exige un jugement unique déjà accepté"
        assert self.accepted[0]["delivery_decision"] in {"deliver", "junk"}
        self.trace.append(("smtp_original", _frozen(kwargs)))
        return "delivered"

    async def _suppress(self, *args, **kwargs):
        assert len(self.accepted) == 1
        assert self.accepted[0]["delivery_decision"] == "suppress"
        self.trace.append(("suppress", _frozen(kwargs)))
        return "suppressed"

    async def _review(self, *args):
        self.trace.append(("smtp_review",))
        return "review_notice_queued"

    async def _invitation(self, *args):
        self.trace.append(("smtp_invitation",))
        return True

    async def _pedagogy(self, *args):
        self.trace.append(("pedagogy",))
        return []

    async def _hostile(self, *args):
        self.trace.append(("hostile",))

    async def _campaign(self, *args):
        self.trace.append(("campaign",))

    async def process(self, engine, *, entry=None):
        patches = {
            "move": self._move, "read_proven_identity": self._identity, "authenticated_hold": self._hold,
            "_express_judgment": self._express, "_express_dossier": self._express_dossier,
            "analyze_message": self._analyze, "persist_signals": self._persist,
            "load_model_routing": self._routing, "qualification_context": self._context,
            "_build_dossier": self._dossier, "_reserve_verdict_call": self._reserve,
            "provider_chat_json": self._provider, "_record_model_route": self._route,
            "_record_shadow_evaluation": self._shadow, "_shadow_after_unsafe_audit": self._downgrade,
            "_routing_audit_sample": lambda _: self.case.get("audit", False),
            "_complete": self._complete, "release_original": self._release, "suppress_original": self._suppress,
            "hold_with_review_or_fail_open": self._review, "technique_pedagogy": self._pedagogy,
            "record_hostile_source": self._hostile, "remember_campaign": self._campaign,
            "_log": lambda *args, **kwargs: None,
        }
        with ExitStack() as stack:
            # Les imports sont résolus là où chaque version consomme l'adaptateur.
            modules = (engine,) if engine is not workflow else (workflow, model_selection, model_calls)
            for module in modules:
                for name, value in patches.items():
                    if hasattr(module, name):
                        stack.enter_context(patch.object(module, name, value))
            stack.enter_context(patch.object(classifier_runtime, "attempt", self._local))
            stack.enter_context(patch.object(classifier_runtime, "observe", self._observe))
            done = await (entry or engine._process_run)(self, None, self.settings,
                                                       SimpleNamespace(queue_invitation=self._invitation), self.run)
        assert done is True
        return self


class OrchestrationEquivalenceTests(unittest.IsolatedAsyncioTestCase):
    async def compare(self, **case):
        old = await _Bench(case).process(_reference())
        new = await _Bench(case).process(workflow)
        self.assertEqual(new.trace, old.trace)
        self.assertEqual(new.accepted, old.accepted)
        self.assertEqual(new.provider_calls, new.reservations)
        self.assertLessEqual(sum(row[0] == "accepted" for row in new.trace), 1)
        self.assertLessEqual(sum(row[0] in {"smtp_original", "smtp_review", "smtp_invitation"} for row in new.trace), 1)
        return new

    async def test_routes_reelles_et_engagement_avant_execution(self):
        cases = [
            ({}, ["pro"], "deliver", "smtp_original"),
            ({"responses": [_response("junk", "spam")]}, ["pro"], "junk", "smtp_original"),
            ({"responses": [_response("junk", "dangerous")]}, ["pro"], "junk", "smtp_original"),
            ({"responses": [_response("ask_user", "suspect")]}, ["pro"], "ask_user", "smtp_review"),
            ({"responses": [_response("ask_user", "undetermined")]}, ["pro"], "ask_user", "smtp_review"),
            ({"routing": "enforced"}, ["flash"], "deliver", "smtp_original"),
            ({"routing": "enforced", "mixed": True}, ["pro"], "deliver", "smtp_original"),
            ({"routing": "enforced", "model_tier": "premium"}, ["pro"], "deliver", "smtp_original"),
            ({"routing": "enforced", "economy_error": True}, ["flash", "pro"], "deliver", "smtp_original"),
            ({"routing": "enforced", "responses": [_response(confidence=.91), _response()]}, ["flash", "pro"], "deliver", "smtp_original"),
            ({"routing": "shadow"}, ["flash", "pro"], "deliver", "smtp_original"),
            ({"routing": "enforced", "audit": True}, ["flash", "pro"], "deliver", "smtp_original"),
            ({"routing": "enforced", "audit": True, "responses": [_response(), _response("ask_user", "suspect")]}, ["flash", "pro"], "ask_user", "smtp_review"),
            ({"local": True}, [], "deliver", "smtp_original"),
            ({"incomplete": True}, ["pro"], "ask_user", "smtp_review"),
            ({"identity_error": True}, ["pro"], "deliver", "smtp_original"),
        ]
        for case, models, decision, action in cases:
            with self.subTest(case=case):
                bench = await self.compare(**case)
                self.assertEqual([row[1] for row in bench.trace if row[0] == "reserve"], models)
                self.assertEqual(bench.accepted[0]["delivery_decision"], decision)
                names = [row[0] for row in bench.trace]
                self.assertLess(names.index("accepted"), names.index(action))
                self.assertNotIn("retry", names)

    async def test_b_et_otp_court_circuitent_analyse_et_modele(self):
        for case, decision, action in [({"early_b": True}, "suppress", "suppress"),
                                       ({"otp": True}, "deliver", "smtp_original"),
                                       ({"late_b": True}, "suppress", "suppress")]:
            with self.subTest(case=case):
                bench = await self.compare(**case)
                names = [row[0] for row in bench.trace]
                self.assertEqual(bench.accepted[0]["delivery_decision"], decision)
                self.assertNotIn("provider", names)
                self.assertNotIn("classifier", names)
                if not case.get("late_b"):
                    self.assertNotIn("deep", names)
                self.assertLess(names.index("accepted"), names.index(action))

    async def test_les_pannes_avant_engagement_ne_livrent_jamais(self):
        cases = [
            {"deep_error": True}, {"persist_error": True}, {"commit_error": True},
            {"provider_error": True}, {"responses": ["{invalid"]},
            {"responses": [_response(confidence=.4)]},
            {"provider_error": True, "attempts": 4},
            {"commit_error": True, "attempts": 3},
        ]
        for case in cases:
            with self.subTest(case=case):
                bench = await self.compare(**case)
                names = [row[0] for row in bench.trace]
                self.assertEqual(bench.accepted, [])
                self.assertNotIn("smtp_original", names)
                self.assertIn("retry", names)
                self.assertEqual("smtp_review" in names, case.get("attempts", 1) >= 3)
                if case.get("persist_error"):
                    self.assertNotIn("provider", names)

    async def test_observation_ne_livre_pas_l_original(self):
        for response, notice in [(_response(), False), (_response("junk", "spam"), True),
                                  (_response("ask_user", "suspect"), True)]:
            with self.subTest(response=response):
                bench = await self.compare(binding=False, responses=[response])
                names = [row[0] for row in bench.trace]
                self.assertNotIn("smtp_original", names)
                self.assertNotIn("smtp_review", names)
                self.assertEqual("smtp_invitation" in names, notice)
                self.assertNotIn("move", names)

    async def test_la_generation_durable_choisit_un_seul_moteur(self):
        for generation, selected in [("legacy", "old"), ("core-v1", "new"), (None, "new")]:
            with self.subTest(generation=generation):
                run = _Bench({}).run
                if generation is not None:
                    run["engine_generation"] = generation
                old, new = AsyncMock(return_value=True), AsyncMock(return_value=True)
                with patch.object(workflow, "_claim", AsyncMock(return_value=run)), \
                     patch.object(workflow, "run_legacy", old), patch.object(workflow, "_process_run", new):
                    self.assertTrue(await workflow._process_one(None, None, None, None))
                self.assertEqual(old.await_count, int(selected == "old"))
                self.assertEqual(new.await_count, int(selected == "new"))

    async def test_une_comparaison_refusee_interdit_la_transaction_d_acceptation(self):
        persist = AsyncMock()
        with patch.object(workflow, "before_commit", AsyncMock(side_effect=CoreComparisonError("désaccord"))), \
             patch.object(workflow, "_persist_complete", persist):
            with self.assertRaises(CoreComparisonError):
                await workflow._complete(None, {}, {}, {})
        persist.assert_not_awaited()

    async def test_preparation_divergente_ou_non_tracee_arrete_avant_modele_et_commit(self):
        prepare = dossier_module._prepare_for_judgment

        def divergent(*args, **kwargs):
            result = prepare(*args, **kwargs)
            result["comparaison_fictive"] = True
            return result

        async def record(*args, **kwargs):
            return {"agreement": kwargs["legacy"] == kwargs["candidate"]}

        for divergence in (True, False):
            with self.subTest(divergence=divergence):
                bench = _Bench({})
                bench.run["engine_generation"] = "core-v1"
                stored = AsyncMock(side_effect=record) if divergence else AsyncMock(return_value=None)
                with patch.object(workflow, "_record_plan", AsyncMock()), \
                     patch.object(core_compare.core_rollout, "record_comparison", stored), \
                     patch.object(dossier_module, "_prepare_for_judgment", divergent if divergence else prepare):
                    await bench.process(workflow)
                stored.assert_awaited_once()
                self.assertEqual(bench.provider_calls, 0)
                self.assertEqual(bench.reservations, 0)
                self.assertEqual(bench.accepted, [])
                names = [row[0] for row in bench.trace]
                self.assertNotIn("commit_attempt", names)
                self.assertNotIn("smtp_original", names)
                self.assertNotIn("smtp_review", names)
                self.assertEqual(next(row[2] for row in bench.trace if row[0] == "retry"), "CoreComparisonError")

    async def test_ombre_legacy_garde_sa_decision_et_libere_le_contexte_de_run(self):
        case = {"responses": [_response("junk", "spam")]}
        baseline = await _Bench(case).process(_reference())
        old = _reference()
        prepare = old._prepare_for_judgment
        bench = _Bench(case)
        bench.run["engine_generation"] = "legacy"
        self.assertIsNone(core_compare._legacy_run.get())
        try:
            with patch.object(core_compare, "reference", return_value=old), \
                 patch.object(core_compare.core_rollout, "record_comparison", AsyncMock(return_value=None)) as record:
                await bench.process(old, entry=core_compare.run_legacy)
            self.assertEqual(record.await_count, 2)
        finally:
            if hasattr(old, "_comparison_installed"):
                del old._comparison_installed
        self.assertIs(old._prepare_for_judgment, prepare)
        self.assertIsNone(core_compare._legacy_run.get())
        self.assertEqual(bench.accepted, baseline.accepted)
        self.assertEqual(bench.provider_calls, 1)
        self.assertEqual(sum(row[0] == "smtp_original" for row in bench.trace), 1)


class _PinnedPool:
    def __init__(self, connection):
        self.connection = connection

    def __getattr__(self, name):
        return getattr(self.connection, name)

    @asynccontextmanager
    async def acquire(self):
        yield self.connection


@unittest.skipUnless(DSN, "PostgreSQL local jetable requis")
class GenerationOrchestrationPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        self.connection = await asyncpg.connect(DSN)
        self.transaction = self.connection.transaction()
        await self.transaction.start()
        self.pool = _PinnedPool(self.connection)
        # Aucune file existante n'est visible par le claim, et aucun message
        # fictif ne peut sortir de cette connexion ou survivre au rollback.
        for table in ("messages", "headers", "mime_parts", "entities", "investigations", "hook_runs", "clues",
                      "verdicts", "delivery_cases", "delivery_events", "verdict_runs", "training_samples", "audit_log",
                      "core_rollout_comparisons"):
            await self.connection.execute(f"CREATE TEMP TABLE {table} (LIKE public.{table} INCLUDING ALL)")
        await self.connection.execute("""
            CREATE TRIGGER messages_generation_fixed BEFORE UPDATE OF engine_generation,engine_generation_assigned_at
                ON messages FOR EACH ROW EXECUTE FUNCTION public.sentimail_generation_fixed();
            CREATE TRIGGER verdict_runs_generation_fixed BEFORE UPDATE OF engine_generation ON verdict_runs
                FOR EACH ROW EXECUTE FUNCTION public.sentimail_generation_fixed();
        """)
        self.settings = SimpleNamespace(verdict_not_before=None, deepseek_verdict_model="pro", decision_mode=True,
                                        analysis_wait_seconds=30, auto_delivery_confidence=.9)
        self.store = storage.Store(self.pool)

    async def asyncTearDown(self):
        await self.transaction.rollback()
        await self.connection.close()

    def raw(self):
        return (f"From: sender@example.org\r\nTo: recipient@example.org\r\nMessage-ID: <{uuid4()}@example.org>\r\n"
                "Subject: Message fictif de reprise\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nTexte de test.\r\n").encode()

    async def capture(self, raw, generation):
        with patch.object(storage, "generation_for_capture", AsyncMock(return_value=generation)):
            return await self.store.capture(raw, "sender@example.org", ["recipient@example.org"], {})

    async def test_capture_doublon_et_nouvelle_capture_suivent_des_generations_distinctes(self):
        raw = self.raw()
        choose = AsyncMock(side_effect=["core-v1", "legacy"])
        with patch.object(storage, "generation_for_capture", choose):
            first = await self.store.capture(raw, "sender@example.org", ["recipient@example.org"], {})
            before = await self.connection.fetchrow("SELECT engine_generation,engine_generation_assigned_at FROM messages WHERE id=$1::uuid", first.message_id)
            duplicate = await self.store.capture(raw, "sender@example.org", ["recipient@example.org"], {})
            later = await self.store.capture(self.raw(), "sender@example.org", ["recipient@example.org"], {})
        after = await self.connection.fetchrow("SELECT engine_generation,engine_generation_assigned_at FROM messages WHERE id=$1::uuid", first.message_id)
        self.assertEqual(before, after)
        self.assertEqual(before["engine_generation"], "core-v1")
        self.assertIsNotNone(before["engine_generation_assigned_at"])
        self.assertEqual(duplicate.message_id, first.message_id)
        self.assertFalse(duplicate.inserted)
        self.assertEqual(choose.await_count, 2)
        self.assertEqual(await self.connection.fetchval("SELECT engine_generation FROM messages WHERE id=$1::uuid", later.message_id), "legacy")
        self.assertEqual(await self.connection.fetchval("SELECT count(*) FROM investigations"), 2)

    async def test_reprise_apres_arret_et_echeance_conserve_le_run_et_la_generation(self):
        await self.capture(self.raw(), "core-v1")
        first = await claims._claim(self.pool, self.settings)
        self.assertIsNotNone(first)
        self.assertEqual(first["engine_generation"], "core-v1")
        await self.connection.execute("UPDATE verdict_runs SET started_at=now()-interval '2 minutes'")
        await claims.resume_interrupted_runs(self.pool)
        resumed = await claims._claim(self.pool, self.settings)
        self.assertEqual((resumed["id"], resumed["attempts"], resumed["engine_generation"]), (first["id"], 2, "core-v1"))
        plan = await commit._mark_error(self.pool, resumed, LlmError("LLM HTTP 503"))
        self.assertEqual(plan.kind, "scheduled")
        self.assertIsNone(await claims._claim(self.pool, self.settings))
        await self.connection.execute("UPDATE verdict_runs SET next_attempt_at=now()-interval '1 second'")
        retried = await claims._claim(self.pool, self.settings)
        self.assertEqual((retried["id"], retried["attempts"], retried["engine_generation"]), (first["id"], 3, "core-v1"))
        self.assertEqual(await self.connection.fetchval("SELECT count(*) FROM verdict_runs"), 1)

    async def test_erreur_sql_du_choix_de_generation_ne_perd_pas_la_capture(self):
        raw = self.raw()

        async def unavailable(connection, message_id):
            await connection.execute("SELECT 1/0")

        with patch.object(storage, "generation_for_capture", unavailable):
            captured = await self.store.capture(raw, "sender@example.org", ["recipient@example.org"], {})
        row = await self.connection.fetchrow("SELECT engine_generation,engine_generation_assigned_at,raw_eml,raw_sha256 FROM messages WHERE id=$1::uuid", captured.message_id)
        self.assertEqual(row["engine_generation"], "legacy")
        self.assertIsNotNone(row["engine_generation_assigned_at"])
        self.assertEqual(row["raw_eml"], raw)
        self.assertEqual(row["raw_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(await self.connection.fetchval("SELECT count(*) FROM investigations"), 1)

    async def test_ancien_accepte_rejeu_et_doublon_ne_modifient_pas_le_jugement(self):
        raw = self.raw()
        captured = await self.capture(raw, "legacy")
        run = await claims._claim(self.pool, self.settings)
        self.assertEqual(run["engine_generation"], "legacy")
        rows = await self.connection.fetch("SELECT id,clue_code,article_code,direction,strength FROM clues WHERE investigation_id=$1", run["investigation_id"])
        dossier = dossier_module._prepare_for_judgment({"schema": "test", "message": {"investigation_status": "complete"},
            "clues": [dict(row) for row in rows]}, {"complete": True}, self.settings)
        result = response_module._parse_verdict(_response("ask_user", "suspect"), dossier)
        await commit._complete(self.pool, run, dossier, result, {"provider": "test", "model": "test"}, 1., binding=True,
                               original_delivery_allowed=False, judgment=response_module._judgment_execution(result), training_eligible=False)

        async def snapshot():
            return [await self.connection.fetchval(f"SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id)::text,'[]') FROM {table} t")
                    for table in ("investigations", "hook_runs", "clues", "verdicts", "verdict_runs")]

        before = await snapshot()
        # La configuration de la capture suivante n'a aucune autorité sur ce
        # dossier ; une nouvelle observation serait un changement rétroactif.
        choose = AsyncMock(return_value="core-v1")
        with patch.object(storage, "generation_for_capture", choose):
            duplicate = await self.store.capture(raw, "sender@example.org", ["recipient@example.org"], {})
            self.assertFalse(await self.store.reinvestigate(captured.message_id))
        choose.assert_not_awaited()
        self.assertEqual(duplicate.message_id, captured.message_id)
        self.assertIsNone(await claims._claim(self.pool, self.settings))
        self.assertEqual(await snapshot(), before)
        self.assertEqual(await self.connection.fetchval("SELECT engine_generation FROM messages"), "legacy")

    async def test_plan_et_comparaison_sont_durables_avant_unique_livraison_otp(self):
        await self.capture(self.raw(), "core-v1")
        run = await claims._claim(self.pool, self.settings)
        dossier = dossier_module._prepare_for_judgment({"schema": "test", "message": {"investigation_status": "complete"},
            "clues": []}, {"complete": True}, self.settings)
        result = response_module._parse_verdict(_response(), dossier)

        async def release(*args, **kwargs):
            self.assertEqual(await self.connection.fetchval("SELECT count(*) FROM verdicts WHERE is_binding"), 1)
            self.assertEqual(await self.connection.fetchval("SELECT status FROM verdict_runs"), "complete")
            self.assertEqual(await self.connection.fetchval("SELECT analysis_plan->>'path' FROM verdict_runs"), "otp")
            self.assertEqual(await self.connection.fetchval("SELECT count(*) FROM core_rollout_comparisons WHERE status='complete' AND agreement"), 1)
            return "delivered"

        smtp, deep, model = AsyncMock(side_effect=release), AsyncMock(), AsyncMock()
        with patch.object(workflow, "read_proven_identity", AsyncMock(return_value=None)), \
             patch.object(workflow, "authenticated_hold", AsyncMock(return_value=False)), \
             patch.object(workflow, "_express_judgment", AsyncMock(return_value=result)), \
             patch.object(workflow, "_express_dossier", AsyncMock(return_value=dossier)), \
             patch.object(workflow, "release_original", smtp), \
             patch.object(workflow, "analyze_message", deep), \
             patch.object(model_calls, "provider_chat_json", model):
            self.assertTrue(await workflow._process_run(self.pool, None, self.settings, None, run))
        smtp.assert_awaited_once()
        deep.assert_not_awaited()
        model.assert_not_awaited()
        self.assertIsNone(await claims._claim(self.pool, self.settings))

    async def test_comparaison_avant_modele_conserve_les_faits_complets_et_ne_stocke_que_les_hashes(self):
        await self.capture(self.raw(), "core-v1")
        run = await claims._claim(self.pool, self.settings)
        private = "contenu-fictif-prive@example.invalid"
        full = {"schema": "test", "message": {"investigation_status": "complete", "body_text": private * 2000},
                "clues": [{"id": i, "clue_code": f"FAIT_FICTIF_{i}", "direction": "neutral", "strength": 0,
                           "statement": "constat" * 500} for i in range(75)]}
        deep = {"complete": True, "history": {"ground_truth_labels": {"legitimate": 3}}}
        before = copy.deepcopy((full, deep, vars(self.settings)))
        await core_compare.before_model(self.pool, run, full, deep, self.settings)
        self.assertEqual((full, deep, vars(self.settings)), before)
        row = await self.connection.fetchrow("SELECT *,to_jsonb(c)::text AS stored FROM core_rollout_comparisons c")
        self.assertTrue(row["agreement"])
        self.assertEqual(row["status"], "complete")
        self.assertEqual(row["source"], "shadow")
        self.assertEqual(row["legacy_sha256"], row["candidate_sha256"])
        self.assertNotIn(private, row["stored"])
        self.assertNotIn("@", row["stored"])
        self.assertEqual(row["dossier_sha256"], core_compare._hash({"stage": "before_model", "dossier": full,
            "deep": deep, "confidence": self.settings.auto_delivery_confidence}))


@unittest.skipUnless(DSN, "PostgreSQL local jetable requis")
class BoundedCapturePostgresTests(unittest.IsolatedAsyncioTestCase):
    async def test_verrou_configuration_expire_sans_perdre_capture_ni_reglages_appelant(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        schema = "capture_deadline_"+uuid4().hex
        operator = await asyncpg.connect(DSN)
        pool = transaction = task = None
        try:
            await operator.execute(f"CREATE SCHEMA {schema}")
            await operator.execute(f"SET search_path={schema},public")
            for table in ("messages", "headers", "mime_parts", "entities", "investigations", "hook_runs", "clues",
                          "verdicts", "delivery_cases", "delivery_events", "verdict_runs", "training_samples",
                          "audit_log", "core_rollout_config"):
                await operator.execute(f"CREATE TABLE {table} (LIKE public.{table} INCLUDING ALL)")
            await operator.execute("""INSERT INTO core_rollout_config(singleton,mode) VALUES(true,'active');
                CREATE TRIGGER messages_generation_fixed BEFORE UPDATE OF engine_generation,engine_generation_assigned_at
                ON messages FOR EACH ROW EXECUTE FUNCTION public.sentimail_generation_fixed();""")

            async def initialize(connection):
                await connection.execute(f"SET search_path={schema},public")
                await connection.execute("SET statement_timeout='17s'; SET lock_timeout='8s'")

            pool = await asyncpg.create_pool(DSN, min_size=1, max_size=1, setup=initialize)
            transaction = operator.transaction()
            await transaction.start()
            await operator.fetchrow("SELECT * FROM core_rollout_config WHERE singleton FOR UPDATE")
            async with pool.acquire() as capture_connection:
                store = storage.Store(_PinnedPool(capture_connection))
                raw = (f"From: sender@example.org\r\nTo: recipient@example.org\r\nMessage-ID: <{uuid4()}@example.org>\r\n"
                       "Subject: Capture sous verrou de configuration\r\n\r\nTexte fictif.\r\n").encode()
                started = asyncio.get_running_loop().time()
                task = asyncio.create_task(store.capture(raw, "sender@example.org", ["recipient@example.org"], {}))
                async with asyncio.timeout(2):
                    while await operator.fetchval("SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1",
                                                  capture_connection.get_server_pid()) != "Lock":
                        await asyncio.sleep(.005)
                self.assertFalse(task.done())
                captured = await asyncio.wait_for(task, timeout=3)
                self.assertLess(asyncio.get_running_loop().time()-started, 3)
                self.assertTrue(operator.is_in_transaction())
                # La deuxième connexion observe le COMMIT alors qu'elle garde
                # le verrou bloquant. Le repli ne se réduit pas à un savepoint.
                row = await operator.fetchrow("""SELECT engine_generation,engine_generation_assigned_at,
                    raw_eml,raw_sha256 FROM messages WHERE id=$1::uuid""", captured.message_id)
                self.assertTrue(captured.inserted)
                self.assertEqual(row["engine_generation"], "legacy")
                self.assertIsNotNone(row["engine_generation_assigned_at"])
                self.assertEqual(row["raw_eml"], raw)
                self.assertEqual(row["raw_sha256"], hashlib.sha256(raw).hexdigest())
                self.assertEqual(await operator.fetchval("SELECT count(*) FROM investigations"), 1)
                audit = json.loads(await operator.fetchval("SELECT payload::text FROM audit_log WHERE action='core.generation_fallback'"))
                self.assertEqual(audit, {"message_id":captured.message_id, "error_type":"TimeoutError"})
                self.assertEqual(await capture_connection.fetchval("SHOW statement_timeout"), "17s")
                self.assertEqual(await capture_connection.fetchval("SHOW lock_timeout"), "8s")
        finally:
            if task is not None and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            if transaction is not None:
                await transaction.rollback()
            if pool is not None:
                await pool.close()
            await operator.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
            await operator.close()
