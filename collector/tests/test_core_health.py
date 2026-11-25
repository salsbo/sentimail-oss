"""La supervision de bascule distingue une absence de preuve d'un feu vert."""

from __future__ import annotations

import asyncio
import copy
import json
import os
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit
from uuid import uuid4

import asyncpg

from sentimail_v3.judgment.claims import ENGINE
from sentimail_v3.judgment.prompt import PROMPT_VERSION
from sentimail_v3.judgment.verdict_retry import ATTEMPTS_CEILING
from sentimail_v3.supervision import core_health, watchdog, watchdog_letter
from test_watchdog import _FreshBackup, _SnapshotPool, _snapshot_settings

DSN = os.environ.get("CORE_HEALTH_TEST_DATABASE_URL", os.environ.get("ENRICHER_TEST_DATABASE_URL", ""))


def _report(*, qualified=True, offline=None, shadow=None, audit_failures=0):
    empty = {"cases": 0, "mismatches": 0, "errors": 0, "excluded": 0}
    return {"eligible": qualified, "blockers": [] if qualified else ["qualification absente"],
            "qualification": {"id": 17} if qualified else None,
            "offline": {**empty, "cases": 25, **(offline or {})},
            "shadow": {**empty, **(shadow or {})}, "audit_failures": audit_failures,
            "context": {"ignored": "corps-et-adresse@example.invalid"}}


class _Pool(_SnapshotPool):
    def __init__(self, *, mode="legacy", qualification_id=17, runs=2, unclaimed=1):
        super().__init__()
        self.config = {"mode": mode, "canary_percent": 5 if mode == "canary" else 0,
                       "qualification_id": qualification_id}
        self.drain = {"legacy_runs_inflight": runs, "legacy_unclaimed": unclaimed}

    async def fetchrow(self, query, *args):
        if "core_rollout_config" in query:
            return dict(self.config)
        if query == core_health.DRAIN_SQL:
            return dict(self.drain)
        return await super().fetchrow(query, *args)


class CoreHealthTests(unittest.IsolatedAsyncioTestCase):
    async def read(self, report=None, **config):
        pool = _Pool(**config)
        with patch.object(core_health.core_rollout, "activation_status", AsyncMock(return_value=report or _report())) as activation:
            result = await core_health.snapshot(pool)
        activation.assert_awaited_once_with(pool, qualification_id=pool.config["qualification_id"])
        return result

    async def test_sain_donne_les_populations_et_ne_restitue_aucun_contenu(self):
        for mode in ("legacy", "shadow", "canary", "active"):
            with self.subTest(mode=mode):
                result = await self.read(mode=mode)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["mode"], mode)
                self.assertEqual(result["qualified_generation"], "core-v1")
                self.assertEqual(result["legacy_inflight"], 3)
                self.assertEqual(result["legacy_runs_inflight"], 2)
                self.assertEqual(result["legacy_unclaimed"], 1)
                self.assertEqual(result["offline"]["cases"], 25)
                self.assertNotIn("@", json.dumps(result))

    async def test_qualification_absente_degrade_seulement_les_modes_actifs(self):
        for mode in ("legacy", "shadow", "canary", "active"):
            with self.subTest(mode=mode):
                result = await self.read(_report(qualified=False), mode=mode, qualification_id=None)
                expected = int(mode in {"canary", "active"})
                self.assertEqual(result["counters"]["core_qualification_lost"], expected)
                self.assertEqual(result["status"], "degraded" if expected else "ok")
                self.assertIsNone(result["qualified_generation"])
        result = await self.read(mode="active", qualification_id=None)
        self.assertEqual(result["counters"]["core_qualification_lost"], 1)

    async def test_une_divergence_ou_une_erreur_degrade_meme_l_ombre(self):
        for report, key, count in [
            (_report(offline={"mismatches": 1}), "core_comparison_mismatches", 1),
            (_report(shadow={"mismatches": 2}), "core_comparison_mismatches", 2),
            (_report(offline={"errors": 1}), "core_comparison_errors", 1),
            (_report(shadow={"errors": 2}), "core_comparison_errors", 2),
            (_report(audit_failures=3), "core_comparison_errors", 3),
        ]:
            with self.subTest(report=report):
                result = await self.read(report, mode="shadow")
                self.assertEqual(result["status"], "degraded")
                self.assertEqual(result["counters"][key], count)

    async def test_panne_de_lecture_visible_sans_recopier_son_detail(self):
        with patch.object(core_health.core_rollout, "activation_status", AsyncMock(side_effect=RuntimeError("secret@example.invalid"))):
            result = await core_health.snapshot(_Pool())
        self.assertEqual(result["counters"]["core_health_unavailable"], 1)
        self.assertEqual(result["error"], "RuntimeError")
        self.assertEqual(result["status"], "degraded")
        self.assertNotIn("@", json.dumps(result))

    async def test_timeout_annule_la_sonde_et_ne_masque_pas_la_panne(self):
        cancelled = asyncio.Event()

        async def suspended(*args, **kwargs):
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        with patch.object(core_health, "TIMEOUT_SECONDS", .02), \
             patch.object(core_health.core_rollout, "activation_status", suspended):
            async with asyncio.timeout(1):
                result = await core_health.snapshot(_Pool())
        self.assertTrue(cancelled.is_set())
        self.assertEqual(result["error"], "TimeoutError")
        self.assertEqual(result["counters"]["core_health_unavailable"], 1)

    async def test_les_compteurs_et_le_detail_atteignent_le_watchdog_et_sa_lettre(self):
        reports = [
            (_report(qualified=False), "active", "core_qualification_lost"),
            (_report(shadow={"mismatches": 1}), "shadow", "core_comparison_mismatches"),
            (_report(audit_failures=1), "shadow", "core_comparison_errors"),
        ]
        for report, mode, reason in reports:
            with self.subTest(reason=reason), \
                 patch.object(core_health.core_rollout, "activation_status", AsyncMock(return_value=copy.deepcopy(report))), \
                 patch.object(watchdog, "BACKUP_HEARTBEAT", _FreshBackup()):
                result = await watchdog._snapshot(_Pool(mode=mode), _snapshot_settings(), previously_observed=frozenset({reason}))
                self.assertEqual(result["status"], "degraded")
                self.assertIn(reason, result["details"]["reasons"])
                self.assertEqual(result["details"]["core_rollout"]["mode"], mode)
                rendered = watchdog_letter.lettre(result["status"], result["details"])
                self.assertNotIn(reason, rendered.text)
                self.assertIn("cœur", rendered.text)
                self.assertIn("supervision.core_rollout --status", rendered.text)


@unittest.skipUnless(DSN, "PostgreSQL local jetable requis")
class CoreDrainPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def test_sonde_complete_lit_qualification_divergence_et_audit_reels(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        connection = await asyncpg.connect(DSN)
        transaction = connection.transaction()
        await transaction.start()
        try:
            for table in ("messages", "investigations", "verdict_runs", "core_rollout_config",
                          "core_rollout_comparisons", "core_rollout_qualifications", "audit_log"):
                await connection.execute(f"CREATE TEMP TABLE {table} (LIKE public.{table} INCLUDING ALL)")
            await connection.execute("""CREATE TEMP TABLE code_articles AS SELECT * FROM public.code_articles;
                CREATE TEMP TABLE code_editions AS SELECT * FROM public.code_editions;
                INSERT INTO core_rollout_config(singleton,mode) VALUES(true,'legacy');""")
            rollout = core_health.core_rollout
            # Les fichiers peuvent être édités en parallèle par un autre lot ;
            # le contexte de ce test reste celui de son unique version fictive.
            with patch.object(rollout, "package_fingerprint", return_value="a" * 64):
                healthy = await core_health.snapshot(connection)
                self.assertEqual(healthy["status"], "ok")
                self.assertFalse(healthy["qualified"])
                self.assertEqual(healthy["legacy_inflight"], 0)
                await connection.execute("UPDATE core_rollout_config SET mode='active'")
                lost = await core_health.snapshot(connection)
                self.assertEqual(lost["counters"]["core_qualification_lost"], 1)
                await connection.execute("UPDATE core_rollout_config SET mode='shadow'")
                await rollout.record_comparison(connection, source="shadow", dossier={"case": "test"},
                    proposed_response={"test": True}, legacy={"delivery": "deliver"}, candidate={"delivery": "ask_user"})
                context = await rollout.qualification_context(connection)
                await connection.execute("""INSERT INTO audit_log(actor,action,payload)
                    VALUES('core_rollout','core.comparison_failed',$1::jsonb)""",
                    json.dumps({"context": context, "error_type": "RuntimeError"}))
                degraded = await core_health.snapshot(connection)
                self.assertEqual(degraded["status"], "degraded")
                self.assertEqual(degraded["shadow"]["cases"], 1)
                self.assertEqual(degraded["counters"]["core_comparison_mismatches"], 1)
                self.assertEqual(degraded["counters"]["core_comparison_errors"], 1)
                self.assertEqual(degraded["audit_failures"], 1)
        finally:
            await transaction.rollback()
            await connection.close()

    async def test_drainage_exclut_les_erreurs_historiques_et_runs_non_eligibles(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        connection = await asyncpg.connect(DSN)
        transaction = connection.transaction()
        await transaction.start()
        try:
            # La requête réelle ne voit que les lignes de ce test.
            await connection.execute("""CREATE TEMP TABLE messages (
                id uuid PRIMARY KEY,engine_generation text,delivery_status text);
                CREATE TEMP TABLE investigations (id uuid PRIMARY KEY,message_id uuid);
                CREATE TEMP TABLE verdict_runs (id uuid PRIMARY KEY,investigation_id uuid,
                    engine text,prompt_version text,status text,attempts integer,completed_at timestamptz);
                CREATE TEMP TABLE verdicts (investigation_id uuid,is_binding boolean);""")

            async def fixture(state="analyzing", generation="legacy", status="running", attempts=1,
                              completed=False, prompt=PROMPT_VERSION, with_run=True, accepted=False):
                message, investigation = uuid4(), uuid4()
                await connection.execute("INSERT INTO messages VALUES($1,$2,$3)", message, generation, state)
                await connection.execute("INSERT INTO investigations VALUES($1,$2)", investigation, message)
                if accepted:
                    await connection.execute("INSERT INTO verdicts VALUES($1,true)", investigation)
                if with_run:
                    await connection.execute("""INSERT INTO verdict_runs VALUES($1,$2,$3,$4,$5,$6,
                        CASE WHEN $7::boolean THEN now() ELSE NULL END)""",
                        uuid4(), investigation, ENGINE, prompt, status, attempts, completed)

            await fixture()  # Un run courant en cours.
            await fixture(status="error")  # Un essai courant reprenable.
            await fixture(state="captured", with_run=False)  # Jamais pris.
            for state in ("held", "delivered", "suppressed", "consumed", "deferred", "release_pending"):
                await fixture(state=state, status="error")
            await fixture(generation="core-v1")
            await fixture(status="complete", completed=True)
            await fixture(status="error", completed=True)
            await fixture(status="error", attempts=ATTEMPTS_CEILING)
            await fixture(status="error", accepted=True)
            # Un ancien prompt n'est pas un run courant ; ce courrier encore
            # capturé attend donc sa première prise par le prompt courant.
            await fixture(state="captured", prompt="ancien-prompt", status="error")
            counts = await connection.fetchrow(core_health.DRAIN_SQL, ENGINE, PROMPT_VERSION, ATTEMPTS_CEILING)
            self.assertEqual(dict(counts), {"legacy_runs_inflight": 2, "legacy_unclaimed": 2})
        finally:
            await transaction.rollback()
            await connection.close()
