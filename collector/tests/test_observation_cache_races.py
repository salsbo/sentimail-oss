"""Deux connexions PostgreSQL réelles : la purge et le cache se sérialisent."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import unittest
from urllib.parse import urlsplit
import uuid

import asyncpg

from sentimail_v3.observation.observation_cache import save_observation

DSN = os.environ.get("OBSERVATION_CACHE_TEST_DATABASE_URL", "")


@unittest.skipUnless(DSN, "PostgreSQL local jetable requis")
class ObservationCachePurgeRaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        self.schema = "cache_race_"+uuid.uuid4().hex
        self.first = await asyncpg.connect(DSN)
        self.second = await asyncpg.connect(DSN)
        self.tasks = []
        await self.first.execute(f"CREATE SCHEMA {self.schema}")
        for connection in (self.first, self.second):
            await connection.execute(f"SET search_path={self.schema},public")
        await self.first.execute("CREATE TABLE messages (LIKE public.messages INCLUDING ALL)")
        migration = (Path(__file__).parents[2]/"database/init/107_cache_observations.sql").read_text()
        await self.first.execute(migration)
        self.message_id = str(uuid.uuid4())
        await self.first.execute("""INSERT INTO messages (
          id,ingest_key,envelope_from,envelope_recipients,raw_sha256,raw_size_bytes,
          headers_size_bytes,body_size_bytes,line_count,max_line_length,contains_8bit,
          contains_nul,line_ending,root_content_type,parser_version)
          VALUES($1::uuid,$1,'sender@example.org',ARRAY['recipient@example.org'],$2,
                 1,1,0,1,1,false,false,'CRLF','text/plain','test')""", self.message_id, "1"*64)

    async def asyncTearDown(self):
        for task in self.tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.second.close()
        # Une assertion peut laisser une transaction ouverte : sa fermeture
        # libère les verrous avant la suppression du schéma privé de ce test.
        await self.first.close()
        cleanup = await asyncpg.connect(DSN)
        try:
            await cleanup.execute(f"DROP SCHEMA {self.schema} CASCADE")
        finally:
            await cleanup.close()

    async def wait_for_row_lock(self, connection):
        async with asyncio.timeout(1):
            while True:
                await self.first.execute("SELECT pg_stat_clear_snapshot()")
                wait = await self.first.fetchval(
                    "SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1",
                    connection.get_server_pid())
                if wait == "Lock":
                    return
                await asyncio.sleep(0.005)

    async def test_purge_gagnante_refuse_ecriture_reprise_apres_attente(self):
        transaction = self.first.transaction()
        await transaction.start()
        await self.first.fetchval("SELECT id FROM messages WHERE id=$1::uuid FOR UPDATE", self.message_id)
        await self.first.execute("UPDATE messages SET redacted_at=now() WHERE id=$1::uuid", self.message_id)
        await self.first.execute("DELETE FROM observation_cache WHERE message_id=$1::uuid", self.message_id)
        task = asyncio.create_task(save_observation(
            self.second, self.message_id, "site", "a"*64, {"text": "résultat tardif"}))
        self.tasks.append(task)
        await self.wait_for_row_lock(self.second)
        await transaction.commit()
        self.assertFalse(await task)
        self.assertEqual(await self.first.fetchval("SELECT count(*) FROM observation_cache"), 0)
        self.assertTrue(await self.first.fetchval("SELECT redacted_at IS NOT NULL FROM messages"))

    async def test_cache_gagnant_est_efface_par_purge_qui_attend_le_verrou(self):
        transaction = self.first.transaction()
        await transaction.start()
        self.assertTrue(await save_observation(
            self.first, self.message_id, "site", "a"*64, {"text": "résultat temporaire"}))

        async def purge():
            async with self.second.transaction():
                await self.second.fetchval("SELECT id FROM messages WHERE id=$1::uuid FOR UPDATE", self.message_id)
                await self.second.execute("UPDATE messages SET redacted_at=now() WHERE id=$1::uuid", self.message_id)
                await self.second.execute("DELETE FROM observation_cache WHERE message_id=$1::uuid", self.message_id)

        task = asyncio.create_task(purge())
        self.tasks.append(task)
        await self.wait_for_row_lock(self.second)
        await transaction.commit()
        await task
        self.assertEqual(await self.first.fetchval("SELECT count(*) FROM observation_cache"), 0)
        self.assertTrue(await self.first.fetchval("SELECT redacted_at IS NOT NULL FROM messages"))
