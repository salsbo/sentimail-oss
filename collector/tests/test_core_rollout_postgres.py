"""Bascule et preuve de qualification sur un schéma PostgreSQL privé jetable."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit
import uuid

import asyncpg

from sentimail_v3.supervision import core_rollout as rollout

DSN = os.environ.get("CORE_ROLLOUT_TEST_DATABASE_URL", "")


@unittest.skipUnless(DSN, "PostgreSQL local jetable requis")
class CoreRolloutPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        self.schema = "core_rollout_"+uuid.uuid4().hex
        self.admin = await asyncpg.connect(DSN)
        await self.admin.execute(f"CREATE SCHEMA {self.schema}")
        async def initialize(connection):
            await connection.execute(f"SET search_path={self.schema},public")
        self.pool = await asyncpg.create_pool(DSN, min_size=1, max_size=2, setup=initialize)
        await self.pool.execute("""CREATE TABLE messages (LIKE public.messages INCLUDING ALL);
          ALTER TABLE messages DROP COLUMN engine_generation;
          ALTER TABLE messages DROP COLUMN engine_generation_assigned_at;
          CREATE TABLE verdict_runs (LIKE public.verdict_runs INCLUDING ALL);
          ALTER TABLE verdict_runs DROP COLUMN engine_generation;
          ALTER TABLE verdict_runs DROP COLUMN IF EXISTS analysis_plan;
          CREATE TABLE code_articles AS SELECT * FROM public.code_articles;
          CREATE TABLE code_editions AS SELECT * FROM public.code_editions;
          CREATE TABLE investigations (LIKE public.investigations INCLUDING ALL);
          CREATE TABLE verdicts (LIKE public.verdicts INCLUDING ALL);
          CREATE TABLE delivery_cases (LIKE public.delivery_cases INCLUDING ALL);
          CREATE TABLE audit_log (LIKE public.audit_log INCLUDING ALL);""")
        migration = (Path(__file__).parents[2]/"database/init/109_core_rollout.sql").read_text()
        await self.pool.execute(migration)

    async def asyncTearDown(self):
        await self.pool.close()
        await self.admin.execute(f"DROP SCHEMA {self.schema} CASCADE")
        await self.admin.close()

    async def comparison(self, label, *, same=True, **extra):
        return await rollout.record_comparison(self.pool, dossier={"case": label},
            proposed_response={"proposal": label}, legacy={"accepted": True},
            candidate={"accepted": same}, source=extra.pop("source","offline"),
            coverage=extra.pop("coverage",[label]), **extra)

    async def qualify(self):
        for label in sorted(await rollout.required_coverage(self.pool)):
            self.assertIsNotNone(await self.comparison(label))
        result = await rollout.publish_qualification(self.pool, case_set_sha256="a"*64)
        self.assertEqual(result["status"], "complete")
        return result

    async def generation(self, identifier=None):
        async with self.pool.acquire() as connection, connection.transaction():
            return await rollout.generation_for_capture(connection, identifier or str(uuid.uuid4()))

    async def test_defaut_legacy_et_shadow_ne_assignent_jamais_nouveau_moteur(self):
        self.assertEqual(await self.generation(), "legacy")
        await rollout.configure_rollout(self.pool, "shadow")
        self.assertEqual(await self.generation(), "legacy")
        with self.assertRaises(ValueError):
            await rollout.configure_rollout(self.pool, "active")

    async def test_un_seul_cas_et_duplicats_ne_simulent_pas_couverture(self):
        for _ in range(3):
            await rollout.record_comparison(self.pool, dossier={"same": True}, proposed_response="same",
                legacy={},candidate={},source="offline",coverage=rollout.REQUIRED_COVERAGE)
        result = await rollout.publish_qualification(self.pool, case_set_sha256="a"*64)
        self.assertEqual(result["cases"], 1)
        self.assertEqual(len(result["coverage"]), 1)
        self.assertEqual(result["status"], "incomplete")
        with self.assertRaises(ValueError):
            await rollout.configure_rollout(self.pool, "canary", canary_percent=10)
        # Une ligne de rapport gonflée ne dispense pas le garde de recompter
        # les paires et la couverture réellement présentes dans les preuves.
        with self.assertRaises(asyncpg.PostgresError):
            await self.pool.execute("""UPDATE core_rollout_qualifications SET status='complete',
                cases=17,coverage=$1::text[]""", sorted(rollout.REQUIRED_COVERAGE))
        self.assertFalse((await rollout.activation_status(self.pool))["eligible"])

    async def test_capture_qualifiee_ne_relit_pas_les_preuves_historiques(self):
        await self.qualify()
        await rollout.configure_rollout(self.pool, "active")
        with patch.object(rollout, "_comparison_summary", side_effect=AssertionError("relecture SMTP interdite")):
            self.assertEqual(await self.generation(), "core-v1")
        # L'ajout de preuves rend le rapport caduc, même si elles concordent.
        await self.comparison("new_offline_case")
        self.assertEqual(await self.generation(), "legacy")
        await rollout.publish_qualification(self.pool, case_set_sha256="b"*64)
        await rollout.configure_rollout(self.pool, "active")
        self.assertEqual(await self.generation(), "core-v1")
        await self.comparison("runtime_failure", source="shadow", same=False)
        self.assertEqual(await self.generation(), "legacy")

    async def test_preuves_et_qualification_sont_immuables(self):
        await self.qualify()
        for query in (
            "UPDATE core_rollout_comparisons SET agreement=false",
            "DELETE FROM core_rollout_comparisons",
            "UPDATE core_rollout_qualifications SET cases=999999",
            "DELETE FROM core_rollout_qualifications",
        ):
            with self.assertRaises(asyncpg.PostgresError):
                await self.pool.execute(query)

    async def test_qualification_complete_active_et_canary_stable(self):
        result = await self.qualify()
        self.assertEqual(result["cases"], len(await rollout.required_coverage(self.pool)))
        config = await rollout.configure_rollout(self.pool, "canary", canary_percent=25)
        ids = [str(uuid.UUID(int=i)) for i in range(200)]
        expected = [rollout.choose_generation(config, i, qualified=True) for i in ids]
        self.assertIn("legacy", expected)
        self.assertIn("core-v1", expected)
        for identifier in ids[:10]:
            self.assertEqual(await self.generation(identifier), rollout.choose_generation(config, identifier, qualified=True))
        await rollout.configure_rollout(self.pool, "active")
        self.assertEqual(await self.generation(), "core-v1")

    async def test_corpus_et_code_changed_ne_reassignent_que_futures_captures_legacy(self):
        await self.qualify()
        await rollout.configure_rollout(self.pool, "active")
        self.assertEqual(await self.generation(), "core-v1")
        with patch.object(rollout, "package_fingerprint", return_value="b"*64):
            self.assertEqual(await self.generation(), "legacy")
        for field in ("CORE_VERSION", "SUITE_VERSION", "ORACLE_REVISION"):
            with patch.object(rollout, field, "changed-version"):
                self.assertEqual(await self.generation(), "legacy")
        await self.pool.execute("UPDATE code_editions SET version=version||'-changed'")
        self.assertEqual(await self.generation(), "legacy")

    async def test_une_divergence_ombre_et_erreur_oracle_bloquent_activation(self):
        await self.qualify()
        await rollout.record_comparison(self.pool, dossier={"runtime":1}, proposed_response={},
            legacy={"deliver":False},candidate={"deliver":True},source="shadow")
        status = await rollout.activation_status(self.pool)
        self.assertFalse(status["eligible"])
        self.assertIn("divergence observée en ombre", status["blockers"])
        with self.assertRaises(ValueError):
            await rollout.configure_rollout(self.pool, "active")

    async def test_erreur_oracle_hors_ligne_ne_devient_pas_accord(self):
        await self.qualify()
        result = await self.comparison("oracle_error", error_type="OracleFailure")
        self.assertEqual(result["status"], "error")
        self.assertFalse(result["agreement"])
        report = await rollout.publish_qualification(self.pool, case_set_sha256="a"*64)
        self.assertEqual(report["errors"], 1)
        self.assertEqual(report["mismatches"], 0)
        self.assertEqual(report["status"], "incomplete")
        with self.assertRaises(ValueError):
            await rollout.configure_rollout(self.pool, "active")

    async def test_capture_et_configuration_se_serialisent_sur_le_meme_verrou(self):
        await self.qualify()
        await rollout.configure_rollout(self.pool, "active")
        async with self.pool.acquire() as capture, self.pool.acquire() as operator:
            transaction = capture.transaction()
            await transaction.start()
            committed = False
            task = None
            try:
                generation = await rollout.generation_for_capture(capture, str(uuid.uuid4()))
                self.assertEqual(generation, "core-v1")
                @asynccontextmanager
                async def acquire():
                    yield operator
                task = asyncio.create_task(rollout.configure_rollout(SimpleNamespace(acquire=acquire), "legacy"))
                async with asyncio.timeout(2):
                    while await self.admin.fetchval(
                        "SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1",
                        operator.get_server_pid()) != "Lock":
                        await asyncio.sleep(0.005)
                self.assertFalse(task.done())
                await transaction.commit()
                committed = True
                self.assertEqual((await task)["mode"], "legacy")
                # La décision de la capture commencée reste inchangée ; la
                # configuration agit uniquement sur la capture suivante.
                self.assertEqual(generation, "core-v1")
            finally:
                if task is not None and not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                if not committed:
                    await transaction.rollback()
        self.assertEqual(await self.generation(), "legacy")

    async def test_historique_incomplet_est_exclu_et_ne_cree_aucun_accord(self):
        excluded = await self.comparison("snapshot_incomplete", exclusion_reason="IncompleteStoredDossier")
        self.assertEqual(excluded["status"], "excluded")
        self.assertFalse(excluded["agreement"])
        report = await rollout.publish_qualification(self.pool, case_set_sha256="a"*64)
        self.assertEqual(report["cases"], 0)
        self.assertEqual(report["excluded"], 1)
        self.assertEqual(report["status"], "incomplete")

    async def test_generation_message_et_run_deja_assignee_est_immuable(self):
        identifier = str(uuid.uuid4())
        await self.pool.execute("""INSERT INTO messages (
          id,ingest_key,envelope_from,envelope_recipients,raw_sha256,raw_size_bytes,
          headers_size_bytes,body_size_bytes,line_count,max_line_length,contains_8bit,
          contains_nul,line_ending,root_content_type,parser_version)
          VALUES($1::uuid,$1,'sender@example.org',ARRAY['recipient@example.org'],$2,
                 1,1,0,1,1,false,false,'CRLF','text/plain','test')""",identifier,"1"*64)
        self.assertEqual(await self.pool.fetchval("SELECT engine_generation FROM messages"), "legacy")
        await self.pool.execute("UPDATE messages SET engine_generation='core-v1',engine_generation_assigned_at=now()")
        with self.assertRaises(asyncpg.PostgresError):
            await self.pool.execute("UPDATE messages SET engine_generation='legacy'")
        self.assertEqual(await self.pool.fetchval("SELECT engine_generation FROM messages"), "core-v1")
        await self.pool.execute("""INSERT INTO verdict_runs(investigation_id,engine,model_name,prompt_version,engine_generation)
          VALUES(gen_random_uuid(),'test','none','test','core-v1')""")
        with self.assertRaises(asyncpg.PostgresError):
            await self.pool.execute("UPDATE verdict_runs SET engine_generation='legacy'")

    async def test_comparaisons_ne_stockent_aucun_dossier_reponse_ni_message(self):
        await rollout.record_comparison(self.pool, dossier={"body":"private-body@example.invalid"},
            proposed_response={"rationale":"private-rationale"},legacy={"decision":"deliver"},
            candidate={"decision":"deliver"},source="shadow")
        stored = await self.pool.fetchval("SELECT jsonb_agg(to_jsonb(c))::text FROM core_rollout_comparisons c")
        self.assertNotIn("private-", stored)
        self.assertNotIn("@", stored)

    async def test_audit_perdu_trace_type_sans_contenu_et_bloque_cette_version(self):
        await self.qualify()
        self.assertTrue((await rollout.activation_status(self.pool))["eligible"])
        result = await rollout.record_comparison(self.pool,
            dossier={"body": "private-body@example.invalid"}, proposed_response="private-response",
            legacy={}, candidate={}, source="invalid")
        self.assertIsNone(result)
        raw = await self.pool.fetchval("SELECT payload::text FROM audit_log WHERE action='core.comparison_failed'")
        audit = json.loads(raw)
        self.assertEqual(audit["error_type"], "ValueError")
        self.assertEqual(set(audit), {"context", "error_type"})
        self.assertNotIn("private-", raw)
        self.assertNotIn("@", raw)
        report = await rollout.activation_status(self.pool)
        self.assertEqual(report["audit_failures"], 1)
        self.assertFalse(report["eligible"])
        with self.assertRaises(ValueError):
            await rollout.configure_rollout(self.pool, "active")
        # Une autre empreinte doit produire ses propres preuves ; l'incident
        # de l'ancienne empreinte ne se transforme pas en incident nouveau.
        with patch.object(rollout, "package_fingerprint", return_value="b"*64):
            self.assertEqual((await rollout.activation_status(self.pool))["audit_failures"], 0)
            self.assertEqual(await self.generation(), "legacy")

    async def test_impossibilite_tracer_echec_audit_remonte_au_commit_appelant(self):
        pool = SimpleNamespace(execute=AsyncMock(side_effect=ConnectionError("base indisponible")))
        with self.assertRaises(ConnectionError):
            await rollout.record_comparison(pool, dossier={}, proposed_response={},
                legacy={}, candidate={}, source="invalid")

    async def test_plan_analyse_accepte_objet_et_refuse_liste(self):
        await self.pool.execute("""INSERT INTO verdict_runs(investigation_id,engine,model_name,prompt_version)
          VALUES(gen_random_uuid(),'test','none','test')""")
        self.assertEqual(await self.pool.fetchval("SELECT analysis_plan::text FROM verdict_runs"), "{}")
        await self.pool.execute("UPDATE verdict_runs SET analysis_plan=$1::jsonb",
            json.dumps({"version":"core-plan-1", "stages":["judge"]}))
        with self.assertRaises(asyncpg.CheckViolationError):
            await self.pool.execute("UPDATE verdict_runs SET analysis_plan='[]'::jsonb")

    async def test_chaque_article_actif_exige_une_paire_independante(self):
        for label in sorted(rollout.REQUIRED_COVERAGE):
            await self.comparison(label)
        incomplete = await rollout.publish_qualification(self.pool, case_set_sha256="a"*64)
        self.assertEqual(incomplete["status"], "incomplete")
        articles = (await rollout.required_coverage(self.pool))-rollout.REQUIRED_COVERAGE
        self.assertTrue(articles)
        for label in sorted(articles):
            await self.comparison(label)
        complete = await rollout.publish_qualification(self.pool, case_set_sha256="b"*64)
        self.assertEqual(complete["status"], "complete")
        self.assertEqual(set(complete["coverage"]), await rollout.required_coverage(self.pool))
        self.assertEqual(set(complete["required_coverage"]), set(complete["coverage"]))
        # Une étiquette arbitraire ne complète aucun scénario ni article réel.
        await self.comparison("fake", coverage=["article:invalid label", "invented"])
        labels = await self.pool.fetchval("SELECT coverage FROM core_rollout_comparisons ORDER BY id DESC LIMIT 1")
        self.assertEqual(labels, [])

    async def test_cli_status_abandons_fermes_et_runs_non_termines(self):
        identifier = str(uuid.uuid4())
        await self.pool.execute("""INSERT INTO messages (
          id,ingest_key,envelope_from,envelope_recipients,raw_sha256,raw_size_bytes,
          headers_size_bytes,body_size_bytes,line_count,max_line_length,contains_8bit,
          contains_nul,line_ending,root_content_type,parser_version,delivery_status)
          VALUES($1::uuid,$1,'sender@example.org',ARRAY['recipient@example.org'],$2,
                 1,1,0,1,1,false,false,'CRLF','text/plain','test','held')""",identifier,"1"*64)
        await self.pool.execute("INSERT INTO delivery_cases(message_id,state) VALUES($1::uuid,'ignored')",identifier)
        async def status():
            # La CLI ferme son pool ; le substitut garde celui du test ouvert.
            proxy = SimpleNamespace(fetchrow=self.pool.fetchrow, fetch=self.pool.fetch,
                fetchval=self.pool.fetchval, close=AsyncMock())
            with patch("asyncpg.create_pool", new=AsyncMock(return_value=proxy)), \
                 patch("sentimail_v3.config.load_settings", return_value=SimpleNamespace(database_url=DSN)):
                return await rollout._cli(SimpleNamespace(status=True))
        result = await status()
        self.assertTrue(result["legacy_drain_complete"])
        self.assertEqual(result["generations"][0]["open"], 0)
        await self.pool.execute("""INSERT INTO verdict_runs(investigation_id,engine,model_name,prompt_version,status)
          VALUES(gen_random_uuid(),'test','none','test','running')""")
        historical = await status()
        self.assertTrue(historical["legacy_drain_complete"])
        self.assertEqual(historical["historical_unfinished_runs"][0]["runs"], 1)
        # Seul un travail du moteur courant, rattaché à un courrier encore
        # à traiter, doit empêcher de déclarer l'ancien chemin drainé.
        from sentimail_v3.judgment.prompt import PROMPT_VERSION
        investigation_id = await self.pool.fetchval("""INSERT INTO investigations(message_id,edition_id,status)
            SELECT $1::uuid,id,'complete' FROM code_editions WHERE status='active' LIMIT 1 RETURNING id""", identifier)
        await self.pool.execute("UPDATE messages SET delivery_status='captured' WHERE id=$1::uuid", identifier)
        await self.pool.execute("""INSERT INTO verdict_runs(investigation_id,engine,model_name,prompt_version,status)
            VALUES($1,'llm','none',$2,'running')""", investigation_id, PROMPT_VERSION)
        running = await status()
        self.assertFalse(running["legacy_drain_complete"])
        self.assertEqual(running["legacy_engine_jobs_remaining"], 1)
        await self.pool.execute("""UPDATE verdict_runs SET status='complete',completed_at=now()
            WHERE investigation_id=$1""", investigation_id)
        await self.pool.execute("UPDATE messages SET delivery_status='held' WHERE id=$1::uuid", identifier)
        self.assertTrue((await status())["legacy_drain_complete"])


class GenerationForCaptureUnitTests(unittest.IsolatedAsyncioTestCase):
    async def test_capture_ne_pose_pas_de_verrou_de_table_en_chemin_chaud(self) -> None:
        executed: list[str] = []

        class _Connection:
            async def fetchrow(self, query: str, *args):
                executed.append(query)
                return {"mode": "active", "canary_percent": 100, "qualification_id": 42}

            async def execute(self, query: str, *args):
                executed.append(query)
                if "LOCK TABLE" in query.upper():
                    raise AssertionError("LOCK TABLE interdit sur le chemin chaud SMTP")

        with patch.object(rollout, "_capture_qualified", new=AsyncMock(return_value=True)) as qualified:
            generation = await rollout.generation_for_capture(_Connection(), str(uuid.uuid4()))

        self.assertEqual(generation, rollout.GENERATION)
        qualified.assert_awaited_once()
        self.assertTrue(any("FOR SHARE" in query for query in executed))
        self.assertFalse(any("LOCK TABLE" in query.upper() for query in executed))
