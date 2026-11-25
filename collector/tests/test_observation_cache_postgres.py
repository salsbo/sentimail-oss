"""Cache de travail réel, indépendant des verdicts et des preuves persistées."""

from __future__ import annotations

import asyncio
import copy
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
import uuid

import asyncpg

from sentimail_v3.observation import observation_cache as cache
from sentimail_v3.observation.deep_hooks import DeepHook, run_deep_hooks

DSN = os.environ.get("OBSERVATION_CACHE_TEST_DATABASE_URL", "")


class CountingHook(DeepHook):
    name = "counting"
    version = "1"

    def __init__(self, *, fails=False, facts=None):
        self.calls = 0
        self.fails = fails
        self.facts = facts if facts is not None else {"observed": True}

    async def observe(self, context):
        self.calls += 1
        if self.fails:
            raise RuntimeError("source indisponible")
        return [{"clue_code": "TEST_OBSERVED"}], copy.deepcopy(self.facts)


@unittest.skipUnless(DSN, "PostgreSQL local jetable requis")
class ObservationCachePostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        self.pool = await asyncpg.create_pool(DSN, min_size=1, max_size=1)
        for table in ("messages", "labels", "sender_policies", "participant_preferences",
                      "code_articles", "code_editions", "llm_role_providers",
                      "llm_local_routing", "domains", "organisation_lookups"):
            await self.pool.execute(f"CREATE TEMP TABLE {table} (LIKE public.{table} INCLUDING ALL)")
        await self.pool.execute("INSERT INTO code_articles SELECT * FROM public.code_articles")
        await self.pool.execute("INSERT INTO code_editions SELECT * FROM public.code_editions")
        migration = (Path(__file__).parents[2]/"database/init/107_cache_observations.sql").read_text()
        await self.pool.execute(migration.replace("CREATE TABLE observation_cache", "CREATE TEMP TABLE observation_cache"))
        self.message_id = str(uuid.uuid4())
        await self.pool.execute("""INSERT INTO messages (
          id,ingest_key,envelope_from,envelope_recipients,raw_sha256,raw_size_bytes,
          headers_size_bytes,body_size_bytes,line_count,max_line_length,contains_8bit,
          contains_nul,line_ending,root_content_type,parser_version)
          VALUES($1::uuid,$1,'sender@example.org',ARRAY['recipient@example.org'],$2,
                 1,1,0,1,1,false,false,'CRLF','text/plain','test')""", self.message_id, "1"*64)
        self.settings = SimpleNamespace(deepseek_verdict_model="model-one", search_api_key="synthetic")

    async def asyncTearDown(self):
        await self.pool.close()

    async def fingerprint(self):
        result = await cache.observation_fingerprint(self.pool, self.message_id, self.settings)
        self.assertIsNotNone(result)
        return result

    async def test_revisions_code_corpus_raw_et_parametres_invalident(self):
        original = await self.fingerprint()
        with patch.object(cache, "package_fingerprint", return_value="another-installed-code"):
            self.assertNotEqual(await self.fingerprint(), original)
        self.assertEqual(await self.fingerprint(), original)
        self.settings.deepseek_verdict_model = "model-two"
        second = await self.fingerprint()
        self.assertNotEqual(second, original)
        self.settings.search_api_key = "rotated-secret-never-in-fingerprint"
        self.assertEqual(await self.fingerprint(), second)
        await self.pool.execute("UPDATE code_articles SET enabled=NOT enabled WHERE id=(SELECT id FROM code_articles LIMIT 1)")
        third = await self.fingerprint()
        self.assertNotEqual(second, third)
        await self.pool.execute("UPDATE messages SET raw_sha256=$1 WHERE id=$2::uuid", "2"*64, self.message_id)
        self.assertNotEqual(await self.fingerprint(), third)

    async def test_feedback_activation_et_politique_invalident_meme_sans_nouvelle_date(self):
        original = await self.fingerprint()
        await self.pool.execute("""INSERT INTO labels(message_id,source,label,is_ground_truth)
            VALUES($1::uuid,'test','legitimate',true)""", self.message_id)
        labelled = await self.fingerprint()
        self.assertNotEqual(original, labelled)
        await self.pool.execute("UPDATE labels SET active=false")
        inactive = await self.fingerprint()
        self.assertNotEqual(labelled, inactive)
        await self.pool.execute("""INSERT INTO sender_policies(participant_email,scope,value_normalized,action)
            VALUES('recipient@example.org','sender','sender@example.org','hold')""")
        policy = await self.fingerprint()
        self.assertNotEqual(inactive, policy)
        await self.pool.execute("UPDATE sender_policies SET active=false")
        self.assertNotEqual(await self.fingerprint(), policy)

    async def test_fournisseur_et_preferences_invalident_sans_lire_les_secrets(self):
        original = await self.fingerprint()
        await self.pool.execute("""INSERT INTO llm_role_providers(
          role,provider,base_url,model_name,secret_filename,validated_at,configured_by)
          VALUES('verdict','openai_compatible','https://example.invalid','model',
                 'synthetic_secret',now(),'test')""")
        provider = await self.fingerprint()
        self.assertNotEqual(provider, original)
        await self.pool.execute("UPDATE llm_role_providers SET model_name='new-model'")
        changed = await self.fingerprint()
        self.assertNotEqual(changed, provider)
        await self.pool.execute("""INSERT INTO participant_preferences(participant_email,name,value)
          VALUES('recipient@example.org','ask_only_on_real_doubt','true')""")
        self.assertNotEqual(await self.fingerprint(), changed)

    async def test_expiration_cle_et_preuve_existante_ne_sont_pas_recrites(self):
        key = await self.fingerprint()
        result = {"text": "constat abouti"}
        self.assertTrue(await cache.save_observation(self.pool, self.message_id, "site", key, result))
        self.assertEqual(await cache.load_observation(self.pool, self.message_id, "site", key), result)
        self.assertFalse(await cache.save_observation(self.pool, self.message_id, "site", key, {"text": "remplacement"}))
        self.assertEqual(await cache.load_observation(self.pool, self.message_id, "site", key), result)
        self.assertIsNone(await cache.load_observation(self.pool, self.message_id, "site", "x"*64))
        await self.pool.execute("UPDATE observation_cache SET expires_at=now()-interval '1 second'")
        self.assertIsNone(await cache.load_observation(self.pool, self.message_id, "site", key))
        self.assertEqual(await self.pool.fetchval("SELECT result->>'text' FROM observation_cache"), "constat abouti")
        renewed = {"text": "nouvelle observation aboutie"}
        self.assertTrue(await cache.save_observation(self.pool, self.message_id, "site", key, renewed))
        self.assertEqual(await cache.load_observation(self.pool, self.message_id, "site", key), renewed)

    async def test_redaction_et_suppression_ne_servent_plus_de_contenu(self):
        key = await self.fingerprint()
        await cache.save_observation(self.pool, self.message_id, "site", key, {"text": "contenu temporaire"})
        await self.pool.execute("UPDATE messages SET redacted_at=now()")
        self.assertIsNone(await cache.load_observation(self.pool, self.message_id, "site", key))
        self.assertFalse(await cache.save_observation(self.pool, self.message_id, "new", key, {"text": "tardif"}))
        self.assertIsNone(await cache.observation_fingerprint(self.pool, self.message_id, self.settings))
        await self.pool.execute("DELETE FROM messages")
        self.assertEqual(await self.pool.fetchval("SELECT count(*) FROM observation_cache"), 0)

    async def test_reprise_ne_repaye_pas_un_hook_reussi_si_suivant_echoue(self):
        key = await self.fingerprint()
        context = SimpleNamespace(pool=self.pool, message_id=self.message_id, settings=self.settings,
                                  clue_codes=set(), observation_fingerprint=key)
        success, failure = CountingHook(), CountingHook(fails=True)
        failure.name = "failed"
        first = await run_deep_hooks([success, failure], context)
        second = await run_deep_hooks([success, failure], context)
        self.assertEqual(success.calls, 1)
        self.assertEqual(failure.calls, 2)
        self.assertEqual([r.status for r in second], ["ok", "error"])
        self.assertTrue(second[0].cache_reused)
        self.assertEqual(second[0].clues, first[0].clues)
        self.assertEqual(second[1].clues, [])
        context.url_analyses = [{"final_apex": "changed.example"}]
        await run_deep_hooks([success], context)
        self.assertEqual(success.calls, 2)

    async def test_faits_partiels_ne_bloquent_jamais_un_nouvel_essai(self):
        key = await self.fingerprint()
        context = SimpleNamespace(pool=self.pool, message_id=self.message_id, settings=self.settings,
                                  clue_codes=set(), observation_fingerprint=key)
        for facts in ({"nested": {"error": "Timeout"}}, {"parsed": False},
                      {"nested": [{"search_unavailable": True}]}, {"analysis_incomplete": True}):
            hook = CountingHook(facts=facts)
            await run_deep_hooks([hook], context)
            await run_deep_hooks([hook], context)
            self.assertEqual(hook.calls, 2)
        self.assertEqual(await self.pool.fetchval("SELECT count(*) FROM observation_cache"), 0)

    async def test_skip_abouti_reutilise_sans_creer_indice(self):
        class Skip(CountingHook):
            async def observe(self, context):
                self.calls += 1
                return [], {"compared": 0}
        hook = Skip()
        context = SimpleNamespace(pool=self.pool, message_id=self.message_id, settings=self.settings,
                                  clue_codes=set(), observation_fingerprint=await self.fingerprint())
        await run_deep_hooks([hook], context)
        second = await run_deep_hooks([hook], context)
        self.assertEqual(hook.calls, 1)
        self.assertEqual(second[0].status, "skip")
        self.assertEqual(second[0].clues, [])

    async def test_entree_site_indices_et_version_hook_invalident(self):
        hook = CountingHook()
        context = SimpleNamespace(pool=self.pool, message_id=self.message_id, settings=self.settings,
                                  clue_codes=set(), observation_fingerprint=await self.fingerprint())
        await run_deep_hooks([hook], context)
        await run_deep_hooks([hook], context)
        self.assertEqual(hook.calls, 1)
        context.sender_site = {"apex": "example.org", "text": "activité nouvelle"}
        await run_deep_hooks([hook], context)
        self.assertEqual(hook.calls, 2)
        context.clue_codes.add("CHANGED_EVIDENCE")
        await run_deep_hooks([hook], context)
        self.assertEqual(hook.calls, 3)
        hook.version = "2"
        await run_deep_hooks([hook], context)
        self.assertEqual(hook.calls, 4)

    async def test_memoire_du_hook_precedent_est_vue_avant_cache_cousin(self):
        hook = CountingHook()
        hook.name = "cousin_domain"
        context = SimpleNamespace(pool=self.pool, message_id=self.message_id, settings=self.settings,
                                  clue_codes=set(), observation_fingerprint=await self.fingerprint())
        await run_deep_hooks([hook], context)
        await run_deep_hooks([hook], context)
        self.assertEqual(hook.calls, 1)
        await self.pool.execute("""INSERT INTO organisation_lookups(organisation,apexes,source)
            VALUES('organisation de test',ARRAY['new.example.org'],'test')""")
        await run_deep_hooks([hook], context)
        self.assertEqual(hook.calls, 2)
