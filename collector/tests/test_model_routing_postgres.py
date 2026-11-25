"""Qualification de la cible sur une vraie base locale, en tables temporaires."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from urllib.parse import urlsplit

import asyncpg

from sentimail_v3.supervision.model_routing import _report, _set_mode, qualification_context

DSN = os.environ.get("MODEL_ROUTING_TEST_DATABASE_URL", "")


@unittest.skipUnless(DSN, "base PostgreSQL locale jetable requise")
class QualificationCascadePostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        self.pool = await asyncpg.create_pool(DSN, min_size=1, max_size=1)
        await self.pool.execute("""
            CREATE TEMP TABLE verdict_model_routing (LIKE public.verdict_model_routing INCLUDING ALL);
            CREATE TEMP TABLE verdict_model_routing_evaluations
                (LIKE public.verdict_model_routing_evaluations INCLUDING ALL);
            CREATE TEMP TABLE audit_log (LIKE public.audit_log INCLUDING ALL);
            CREATE TEMP TABLE code_articles (LIKE public.code_articles INCLUDING ALL);
            INSERT INTO code_articles SELECT * FROM public.code_articles;
            INSERT INTO verdict_model_routing
                (mode,economy_model_name,premium_model_name,confidence_margin)
                VALUES ('off','ancien-flash','ancien-pro',0.05);
        """)
        # Le même test tourne avant ou après migration de la base jetable.
        has_columns = await self.pool.fetchval("""SELECT EXISTS(
            SELECT 1 FROM pg_attribute WHERE attrelid='pg_temp.verdict_model_routing_evaluations'::regclass
            AND attname='prompt_version' AND NOT attisdropped)""")
        if not has_columns:
            migration = Path(__file__).resolve().parents[2] / "database/init/106_qualification_cascade.sql"
            await self.pool.execute(migration.read_text())
        self.context = await qualification_context(self.pool)

    async def asyncTearDown(self):
        await self.pool.close()

    async def comparisons(self, *, economy="ancien-flash", premium="ancien-pro", margin=0.05, context=None):
        context = self.context if context is None else context
        await self.pool.executemany("""INSERT INTO verdict_model_routing_evaluations
            (verdict_run_id,attempt,economy_model_name,premium_model_name,economy_valid,
             premium_classification,premium_decision,premium_confidence,agreement,
             unsafe_delivery_divergence,prompt_version,corpus_sha256,rules_version,confidence_margin)
            VALUES (gen_random_uuid(),1,$1,$2,true,'legitimate','deliver',0.99,true,false,$3,$4,$5,$6)
        """, [(economy,premium,context.get("prompt_version"),context.get("corpus_sha256"),
                context.get("rules_version"),margin) for _ in range(50)])

    async def test_historique_sans_versions_ne_qualifie_pas_et_ne_change_rien(self):
        await self.comparisons(context={})
        with self.assertRaisesRegex(ValueError, "échantillon insuffisant"):
            await _set_mode(self.pool, "enforced", None, None, None)
        report = await _report(self.pool)
        self.assertEqual(report["configuration"]["mode"], "off")
        self.assertEqual(report["evaluation"]["samples"], 0)
        self.assertEqual(await self.pool.fetchval("SELECT count(*) FROM audit_log"), 0)

    async def test_ancienne_paire_qualifiee_ne_valide_pas_nouveaux_noms(self):
        await self.comparisons()
        with self.assertRaisesRegex(ValueError, "cible"):
            await _set_mode(self.pool, "enforced", "nouveau-flash", "nouveau-pro", None)
        self.assertEqual((await _report(self.pool))["configuration"]["economy_model_name"], "ancien-flash")
        await _set_mode(self.pool, "enforced", None, None, None)
        self.assertEqual((await _report(self.pool))["configuration"]["mode"], "enforced")
        await self.comparisons(economy="nouveau-flash", premium="nouveau-pro", margin=0.04)
        await _set_mode(self.pool, "enforced", "nouveau-flash", "nouveau-pro", 0.04)
        report = await _report(self.pool)
        self.assertEqual(report["configuration"]["economy_model_name"], "nouveau-flash")
        self.assertEqual(report["evaluation"]["samples"], 50)

    async def test_changement_de_marge_prompt_regles_ou_corpus_invalide_la_qualification(self):
        for field in ("prompt_version", "rules_version", "corpus_sha256"):
            with self.subTest(field=field):
                await self.pool.execute("TRUNCATE verdict_model_routing_evaluations")
                await self.comparisons(context={**self.context, field: "ancien"})
                with self.assertRaises(ValueError):
                    await _set_mode(self.pool, "enforced", None, None, None)
        await self.pool.execute("TRUNCATE verdict_model_routing_evaluations")
        await self.comparisons()
        with self.assertRaises(ValueError):
            await _set_mode(self.pool, "enforced", None, None, 0.04)
        self.assertEqual((await _report(self.pool))["configuration"]["confidence_margin"], 0.05)
        await self.pool.execute("UPDATE code_articles SET principle=principle || ' révisé'")
        with self.assertRaises(ValueError):
            await _set_mode(self.pool, "enforced", None, None, None)

    async def test_passer_en_comparaison_reste_un_choix_explicitement_audite(self):
        await _set_mode(self.pool, "shadow", "nouveau-flash", "nouveau-pro", 0.04)
        report = await _report(self.pool)
        self.assertEqual(report["configuration"]["mode"], "shadow")
        self.assertEqual(report["evaluation"]["samples"], 0)
        self.assertEqual(await self.pool.fetchval("SELECT count(*) FROM audit_log"), 1)
