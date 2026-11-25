"""Un enquêteur suspendu expire sans accuser le message ni arrêter les autres."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import AsyncMock, patch

from sentimail_v3.observation.deep_hooks import DeepHook, run_deep_hooks
from sentimail_v3.observation import observation_cache as cache


class Slow(DeepHook):
    name = "slow"
    version = "1"

    def __init__(self):
        self.cancelled = False

    async def observe(self, context):
        try:
            await asyncio.sleep(10)
        finally:
            self.cancelled = True


class Fast(DeepHook):
    name = "fast"
    version = "1"

    def __init__(self):
        self.calls = 0

    async def observe(self, context):
        self.calls += 1
        return [], {"observed": True}


def context(**values):
    return SimpleNamespace(pool=None, message_id="message", settings=SimpleNamespace(
        deep_hook_deadline_seconds=0.02), **values)


class DeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_deadline_annule_hook_sans_indice_et_le_suivant_continue(self):
        slow, fast = Slow(), Fast()
        results = await run_deep_hooks([slow, fast], context(analysis_deadline=time.monotonic()+1))
        self.assertEqual([r.status for r in results], ["error", "skip"])
        self.assertEqual(results[0].error_type, "TimeoutError")
        self.assertEqual(results[0].clues, [])
        self.assertTrue(slow.cancelled)
        self.assertEqual(fast.calls, 1)

    async def test_budget_total_epuise_trace_chaque_hook_sans_nouvel_appel(self):
        first, second = Fast(), Fast()
        results = await run_deep_hooks([first, second], context(analysis_deadline=time.monotonic()-1))
        self.assertEqual(first.calls+second.calls, 0)
        self.assertTrue(all(r.status == "error" and r.error_type == "TimeoutError" for r in results))
        self.assertTrue(all(r.clues == [] for r in results))

    async def test_budget_total_plus_court_que_delai_hook_reste_effectif(self):
        ctx = context(analysis_deadline=time.monotonic()+0.02)
        ctx.settings.deep_hook_deadline_seconds = 10
        slow = Slow()
        result = (await run_deep_hooks([slow], ctx))[0]
        self.assertEqual(result.error_type, "TimeoutError")
        self.assertTrue(slow.cancelled)

    async def test_annulation_appelante_n_est_pas_transformee_en_constat(self):
        slow = Slow()
        task = asyncio.create_task(run_deep_hooks([slow], context()))
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(slow.cancelled)

    async def test_cache_indisponible_ne_fabrique_pas_de_resultat(self):
        failed_pool = SimpleNamespace(fetchrow=AsyncMock(side_effect=RuntimeError("offline")),
                                      fetchval=AsyncMock(side_effect=RuntimeError("offline")))
        self.assertIsNone(await cache.observation_fingerprint(failed_pool, "message", None))
        self.assertIsNone(await cache.load_observation(failed_pool, "message", "stage", "a"*64))
        self.assertFalse(await cache.save_observation(failed_pool, "message", "stage", "a"*64, {"observed": True}))
        ctx = context(observation_fingerprint="a"*64)
        ctx.pool = failed_pool
        result = (await run_deep_hooks([Fast()], ctx))[0]
        self.assertEqual(result.status, "skip")
        self.assertEqual(result.clues, [])


class CachePredicateTests(unittest.TestCase):
    def test_erreurs_imbriquees_et_parse_incomplet_sont_refuses(self):
        for value in ({"parsed": False}, {"nested": [{"error": "Timeout"}]},
                      {"state": {"analysis_incomplete": True}}, {"status": "error"},
                      {"reason": "search_unavailable"}, {"failures": ["Timeout"]}):
            self.assertTrue(cache.observation_failed(value), value)
        self.assertFalse(cache.observation_failed({"error": None, "analysis_incomplete": False,
                                                   "complete": True, "parsed": True}))
        recursive = {}
        recursive["cycle"] = recursive
        self.assertTrue(cache.observation_failed(recursive))

    def test_empreinte_code_ne_relit_pas_les_sources_a_chaque_reprise(self):
        first = cache.package_fingerprint()
        self.assertEqual(len(first), 64)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("aucune relecture")):
            self.assertEqual(cache.package_fingerprint(), first)
