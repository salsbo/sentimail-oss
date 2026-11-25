"""Bornes d'inspection et raccourcis prouvés, sans réseau extérieur."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit
import uuid

import asyncpg

from sentimail_v3.code.sender_identity import ProvenIdentity
from sentimail_v3.code.sender_policy import authenticated_hold
from sentimail_v3.judgment import workflow as verdict
from sentimail_v3.observation import deep_analysis as deep

DSN = os.environ.get("ENRICHER_TEST_DATABASE_URL", "")


def candidates():
    return [{"url": f"https://{host}/{path}", "role": "html_link", "link_context": "primary",
             "visible_text": f"Document {index}"} for index, (host, path) in enumerate([
                 ("a.exemple.com", "premier"), ("b.exemple.com", "second"),
                 ("autre.net", "troisieme"), ("autre.net", "quatrieme"), ("dernier.org", "cinquieme")])]


class UrlLimitsTests(unittest.IsolatedAsyncioTestCase):
    def patches(self, selected):
        return (
            patch.object(deep, "_message_url_candidates", return_value=(selected, 0)),
            patch.object(deep, "_select_url_candidates", return_value=(selected, {})),
            patch.object(deep, "_message_is_dmarc_aligned", AsyncMock(return_value=False)),
        )

    async def test_cap_global_par_apex_et_ordre_des_resultats_et_profils(self):
        selected = candidates()
        active = maximum = 0
        by_apex = {}
        max_apex = {}
        saved = []
        profiles = []

        async def fetch(client, settings, url, key, **kwargs):
            nonlocal active, maximum
            apex = deep._apex(urlsplit(url).hostname)
            active += 1
            maximum = max(maximum, active)
            by_apex[apex] = by_apex.get(apex, 0) + 1
            max_apex[apex] = max(max_apex.get(apex, 0), by_apex[apex])
            try:
                await asyncio.sleep(0.01 if apex == "exemple.com" else 0.001)
                return {"initial_url": url}, "ok", None
            finally:
                active -= 1
                by_apex[apex] -= 1

        async def save(pool, message, kind, key, source, status, data, *args, **kwargs):
            if "profile_comparison" not in data:
                saved.append(data["initial_url"])

        async def profile(client, settings, url, key, **kwargs):
            self.assertEqual(len(saved), len(selected))
            profiles.append(url)
            return {}, 1.0, None

        p1, p2, p3 = self.patches(selected)
        with p1, p2, p3, patch.object(deep, "fetch_url_analysis_with_retry", fetch), patch.object(
            deep, "_save_analysis", save
        ), patch.object(deep, "_fetch_url_analysis", profile), patch.object(
            deep, "should_compare_profiles", side_effect=lambda data, **kw: kw["deja_compares"] < 3
        ), patch.object(deep, "compare_profiles", return_value={"same": True}):
            results, complete, _ = await deep._analyze_urls(
                SimpleNamespace(fetchrow=AsyncMock(return_value=None), execute=AsyncMock()), None,
                SimpleNamespace(url_analysis_concurrency=2, url_analysis_deadline_seconds=1), "message", b"raw")
        self.assertTrue(complete)
        self.assertEqual(maximum, 2)
        self.assertTrue(all(value == 1 for value in max_apex.values()))
        self.assertEqual([row["initial_url"] for row in results], [c["url"] for c in selected])
        self.assertEqual(profiles, [c["url"] for c in selected[:3]])
        self.assertNotEqual(saved, [c["url"] for c in selected])

    async def test_la_file_compte_dans_le_budget_et_toutes_les_absences_restent_visibles(self):
        selected = candidates()
        started, cancelled, saved = [], [], []

        async def fetch(client, settings, url, key, **kwargs):
            started.append(url)
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.append(url)

        async def save(pool, message, kind, key, source, status, data, *args, **kwargs):
            saved.append((status, data))

        p1, p2, p3 = self.patches(selected)
        with p1, p2, p3, patch.object(deep, "fetch_url_analysis_with_retry", fetch), patch.object(
            deep, "_save_analysis", save
        ), patch.object(deep, "should_compare_profiles", return_value=False):
            results, complete, coverage = await asyncio.wait_for(deep._analyze_urls(
                SimpleNamespace(fetchrow=AsyncMock(return_value=None)), None,
                SimpleNamespace(url_analysis_concurrency=2, url_analysis_deadline_seconds=0.03), "message", b"raw"), timeout=1)
        self.assertFalse(complete)
        self.assertEqual(len(started), 2)
        self.assertCountEqual(started, cancelled)
        self.assertEqual(len(results), 5)
        self.assertEqual(len(saved), 5)
        self.assertTrue(all(status == "error" and data["analysis_incomplete"] for status, data in saved))
        self.assertTrue(coverage["budget_exhausted"])

    async def test_une_panne_sql_annule_les_inspections_soeurs_et_remonte(self):
        selected = [candidates()[0], candidates()[2]]
        sibling_started = asyncio.Event()
        sibling_cancelled = asyncio.Event()

        async def fetch(client, settings, url, key, **kwargs):
            if url == selected[0]["url"]:
                await sibling_started.wait()
                return {"initial_url": url}, "ok", None
            sibling_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                sibling_cancelled.set()

        p1, p2, p3 = self.patches(selected)
        with p1, p2, p3, patch.object(deep, "fetch_url_analysis_with_retry", fetch), patch.object(
            deep, "_save_analysis", AsyncMock(side_effect=RuntimeError("base indisponible"))
        ):
            with self.assertRaisesRegex(RuntimeError, "base indisponible"):
                await asyncio.wait_for(deep._analyze_urls(
                    SimpleNamespace(fetchrow=AsyncMock(return_value=None)), None,
                    SimpleNamespace(url_analysis_concurrency=2, url_analysis_deadline_seconds=1), "message", b"raw"), timeout=1)
        self.assertTrue(sibling_cancelled.is_set())

    async def test_une_comparaison_interrompue_reprend_sans_refaire_le_primaire(self):
        selected = candidates()[:1]
        primary = {"initial_url": selected[0]["url"], "final_apex": "exemple.com",
                   "final_status": 200, "forms": []}
        browser = {"final_apex": "ailleurs.org", "final_status": 200, "forms": [{"action": "/login"}]}
        for interruption in ("sql", "cancel"):
            with self.subTest(interruption=interruption):
                profile_started = asyncio.Event()
                profile_calls = []

                class CachePool:
                    cached = None
                    failed_update = False

                    async def fetchrow(self, *args):
                        return self.cached

                    async def execute(self, query, *args):
                        if interruption == "sql" and not self.failed_update:
                            self.failed_update = True
                            raise RuntimeError("profil non enregistré")
                        self.cached["result"] = json.loads(args[2])

                pool = CachePool()

                async def save(pool, message, kind, key, source, status, data, *args, **kwargs):
                    pool.cached = {"status": status, "result": dict(data)}

                async def profile(*args, **kwargs):
                    profile_calls.append(1)
                    if interruption == "cancel" and len(profile_calls) == 1:
                        profile_started.set()
                        await asyncio.Event().wait()
                    return browser, "ok", None

                fetch = AsyncMock(return_value=(primary, "ok", None))
                p1, p2, p3 = self.patches(selected)
                with p1, p2, p3, patch.object(deep, "fetch_url_analysis_with_retry", fetch), patch.object(
                    deep, "_save_analysis", save
                ), patch.object(deep, "_fetch_url_analysis", profile):
                    async def analyze():
                        return await deep._analyze_urls(pool, None,
                            SimpleNamespace(url_analysis_concurrency=2, url_analysis_deadline_seconds=1), "message", b"raw")

                    if interruption == "sql":
                        with self.assertRaisesRegex(RuntimeError, "profil non enregistré"):
                            await analyze()
                    else:
                        task = asyncio.create_task(analyze())
                        try:
                            await asyncio.wait_for(profile_started.wait(), timeout=1)
                        finally:
                            task.cancel()
                            with self.assertRaises(asyncio.CancelledError):
                                await task
                    self.assertNotIn("profile_comparison", pool.cached["result"])
                    results, complete, _ = await analyze()
                    self.assertTrue(complete)
                    self.assertTrue(results[0]["profiles_compared"])
                    self.assertTrue(results[0]["cloaking_detected"])
                    fetch.assert_awaited_once()
                    self.assertEqual(len(profile_calls), 2)
                    # Un profil déjà complet ne se repaie pas au troisième run.
                    self.assertTrue((await analyze())[0][0]["profiles_compared"])
                    fetch.assert_awaited_once()
                    self.assertEqual(len(profile_calls), 2)

    async def test_les_profils_deja_en_cache_gardent_les_trois_places_de_selection(self):
        selected = candidates()
        cached = {}
        for index, candidate in enumerate(selected):
            data = {"initial_url": candidate["url"]}
            if index < 3:
                data["profile_comparison"] = {"comparison_incomplete": False, "cloaking_detected": False}
            cached[hashlib.sha256(candidate["url"].encode()).hexdigest()] = {"status": "ok", "result": data}

        async def fetchrow(query, message, key):
            return cached[key]

        p1, p2, p3 = self.patches(selected)
        with p1, p2, p3, patch.object(deep, "fetch_url_analysis_with_retry", AsyncMock()) as primary, patch.object(
            deep, "_fetch_url_analysis", AsyncMock()
        ) as secondary:
            results, complete, _ = await deep._analyze_urls(
                SimpleNamespace(fetchrow=fetchrow), None,
                SimpleNamespace(url_analysis_concurrency=2, url_analysis_deadline_seconds=1), "message", b"raw")
        self.assertTrue(complete)
        self.assertEqual([row["profiles_compared"] for row in results], [True, True, True, False, False])
        primary.assert_not_awaited()
        secondary.assert_not_awaited()


class PolicyShortcutTests(unittest.IsolatedAsyncioTestCase):
    def run_record(self):
        return {"id": str(uuid.uuid4()), "message_id": str(uuid.uuid4()),
                "investigation_id": str(uuid.uuid4()), "model_name": "modele-test", "attempts": 1}

    async def test_une_regle_b_prouvee_s_applique_sans_inspection_ni_modele(self):
        run = self.run_record()
        identity = ProvenIdentity(("sender@blocked.com",), ("blocked.com",), ("domain", "blocked.com"))
        with patch.object(verdict, "_claim", AsyncMock(return_value=run)), patch.object(verdict, "move", AsyncMock()), patch.object(
            verdict, "read_proven_identity", AsyncMock(return_value=identity)
        ), patch.object(verdict, "authenticated_hold", AsyncMock(return_value=True)), patch.object(
            verdict, "_express_dossier", AsyncMock(return_value={})
        ), patch.object(verdict, "_express_judgment", AsyncMock()) as express, patch.object(
            verdict, "analyze_message", AsyncMock()
        ) as inspect, patch("sentimail_v3.judgment.model_calls.provider_chat_json", AsyncMock()) as model, patch.object(
            verdict, "_complete", AsyncMock(return_value=run["message_id"])
        ) as complete, patch.object(verdict, "suppress_original", AsyncMock(return_value="suppressed")) as suppress:
            self.assertTrue(await verdict._process_one(None, None, SimpleNamespace(decision_mode=True), None))
        express.assert_not_awaited()
        inspect.assert_not_awaited()
        model.assert_not_awaited()
        suppress.assert_awaited_once()
        self.assertFalse(complete.await_args.kwargs["training_eligible"])
        self.assertEqual(complete.await_args.args[2]["analysis_not_requested_reason"], "authenticated_sender_policy")

    async def test_sans_identite_la_voie_normale_est_conservee(self):
        class NormalPath(BaseException):
            pass

        with patch.object(verdict, "_claim", AsyncMock(return_value=self.run_record())), patch.object(
            verdict, "move", AsyncMock()
        ), patch.object(verdict, "read_proven_identity", AsyncMock(return_value=None)), patch.object(
            verdict, "_express_judgment", AsyncMock(side_effect=NormalPath)
        ) as normal, patch.object(verdict, "_execute_suppression", AsyncMock()) as suppress:
            with self.assertRaises(NormalPath):
                await verdict._process_one(None, None, SimpleNamespace(decision_mode=True), None)
        normal.assert_awaited_once()
        suppress.assert_not_awaited()


class ImportsAndCompactionTests(unittest.TestCase):
    def test_les_imports_froids_ne_dependent_plus_de_leur_ordre(self):
        collector = Path(__file__).resolve().parents[1]
        for module in ("deep_analysis", "message_parts", "dossier.models"):
            name = "sentimail_v3.observation." + module
            with self.subTest(module=name):
                result = subprocess.run([sys.executable, "-c", f"import importlib; importlib.import_module({name!r})"],
                    cwd=collector, env={"PYTHONPATH": str(collector / "src")}, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([sys.executable, "-c", "import sentimail_v3.code.activity_coherence"],
            cwd=collector, env={"PYTHONPATH": str(collector / "src")}, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_jsonb_chaine_et_dict_conservent_la_meme_vue_bornee(self):
        value = {"registered_domain": "exemple.org", "age_days": 10,
                 "dns": {"MX": ["mx.exemple.org"]}, "rdap": {"raw": "A_EXCLURE"}, "arbitrary": "A_EXCLURE"}
        expected = verdict._compact_enrichment("domain", value)
        self.assertEqual(verdict._compact_enrichment("domain", json.dumps(value)), expected)
        self.assertEqual(expected["dns"]["MX"], {"count": 1, "present": True})
        self.assertNotIn("A_EXCLURE", str(expected))
        self.assertNotIn("rdap", expected)
        self.assertEqual(verdict._compact_enrichment("domain", "pas du JSON"), {})
        self.assertEqual(verdict._compact_enrichment("domain", "[]"), {})


@unittest.skipUnless(DSN, "base PostgreSQL locale jetable requise")
class SenderPolicyPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def test_portee_client_preuve_et_frontiere_de_domaine(self):
        self.assertEqual(urlsplit(DSN).hostname, "127.0.0.1")
        self.assertTrue(urlsplit(DSN).path.endswith("_test"))
        connection = await asyncpg.connect(DSN)
        try:
            await connection.execute("""CREATE TEMP TABLE messages(id uuid,envelope_recipients text[]);
                CREATE TEMP TABLE domains(fqdn text,client_id uuid);
                CREATE TEMP TABLE sender_policies(participant_email text,scope text,
                    value_normalized text,action text,active boolean);""")
            message = str(uuid.uuid4())
            owner, other = uuid.uuid4(), uuid.uuid4()
            await connection.executemany("INSERT INTO domains VALUES($1,$2)",
                [("client-a.test", owner), ("client-b.test", owner), ("client-c.test", other)])
            await connection.execute("INSERT INTO messages VALUES($1::uuid,ARRAY['reader@client-b.test'])", message)
            await connection.execute("INSERT INTO sender_policies VALUES('owner@client-a.test','domain','blocked.com','hold',true)")

            def identity(domain):
                return ProvenIdentity((), (domain,), ("domain", domain))

            self.assertTrue(await authenticated_hold(connection, message, identity("blocked.com")))
            self.assertTrue(await authenticated_hold(connection, message, identity("sub.blocked.com")))
            self.assertFalse(await authenticated_hold(connection, message, identity("fakeblocked.com")))
            self.assertFalse(await authenticated_hold(connection, message, identity("blocked.com.attacker.net")))
            self.assertFalse(await authenticated_hold(connection, message, None))
            self.assertFalse(await authenticated_hold(connection, message, ProvenIdentity((), (), None)))
            await connection.execute("UPDATE messages SET envelope_recipients=ARRAY['reader@client-c.test']")
            self.assertFalse(await authenticated_hold(connection, message, identity("blocked.com")))
        finally:
            await connection.close()
