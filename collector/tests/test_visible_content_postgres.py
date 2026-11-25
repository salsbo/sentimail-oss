"""Capture et rejeu conservent la provenance sans réécrire un verdict accepté."""

import json
import os
import unittest
import uuid
from urllib.parse import urlsplit

import asyncpg

from sentimail_v3.observation.storage import Store
from sentimail_v3.observation.visible_content import build_visible_content

DSN = os.environ.get("VISIBLE_CONTENT_TEST_DATABASE_URL", "")


@unittest.skipUnless(DSN, "base PostgreSQL locale jetable requise")
class CaptureVisiblePostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        self.pool = await asyncpg.create_pool(DSN, min_size=1, max_size=2)
        self.ids = []

    async def asyncTearDown(self):
        await self.pool.execute("DELETE FROM messages WHERE id=ANY($1::uuid[])", self.ids)
        await self.pool.close()

    async def capture(self):
        raw = (f"From: sender@example.org\r\nTo: recipient@example.org\r\n"
               f"Message-ID: <{uuid.uuid4()}@test.example>\r\n"
               "Subject: Vue visible\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
               "Message de test").encode()
        store = Store(self.pool)
        result = await store.capture(raw, "sender@example.org", ["recipient@example.org"], {})
        self.ids.append(uuid.UUID(result.message_id))
        return store, result, raw

    async def test_capture_persistante_et_doublon_ne_recrit_pas_la_vue(self):
        store, result, raw = await self.capture()
        view = json.loads(await self.pool.fetchval("SELECT facts FROM messages WHERE id=$1::uuid", result.message_id))["visible_content"]
        self.assertEqual(view, build_visible_content("Message de test", None))
        await self.pool.execute("UPDATE messages SET facts=facts || '{\"marque\":true}'::jsonb WHERE id=$1::uuid", result.message_id)
        duplicate = await store.capture(raw, "sender@example.org", ["recipient@example.org"], {})
        self.assertFalse(duplicate.inserted)
        facts = json.loads(await self.pool.fetchval("SELECT facts FROM messages WHERE id=$1::uuid", result.message_id))
        self.assertTrue(facts["marque"])
        self.assertEqual(facts["visible_content"], view)

    async def test_entete_adresse_inachevee_ne_bloque_pas_capture_postgresql(self):
        raw = (f"From: sender@[\r\nTo: recipient@example.org\r\n"
               f"Message-ID: <{uuid.uuid4()}@test.example>\r\n"
               "Subject: Adresse synthétique\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
               "Corps synthétique conservé.").encode()
        result = await Store(self.pool).capture(raw, "sender@example.org", ["recipient@example.org"], {})
        self.ids.append(uuid.UUID(result.message_id))
        row = await self.pool.fetchrow(
            "SELECT raw_eml,from_header,body_text,parser_defects,facts FROM messages WHERE id=$1::uuid",
            result.message_id,
        )
        self.assertTrue(result.inserted)
        self.assertEqual(bytes(row["raw_eml"]), raw)
        self.assertEqual(row["from_header"], "sender@[")
        self.assertEqual(row["body_text"], "Corps synthétique conservé.")
        self.assertIn("InvalidHeaderDefect", json.loads(row["parser_defects"]))
        self.assertEqual(json.loads(row["facts"])["visible_content"]["text"], row["body_text"])

    async def test_rejeu_ancien_sans_verdict_ajoute_vue_mais_pas_apres_acceptation(self):
        store, result, _ = await self.capture()
        await self.pool.execute("UPDATE messages SET facts=facts-'visible_content' WHERE id=$1::uuid", result.message_id)
        self.assertTrue(await store.reinvestigate(result.message_id))
        self.assertTrue(await self.pool.fetchval("SELECT facts ? 'visible_content' FROM messages WHERE id=$1::uuid", result.message_id))
        await self.pool.execute("""INSERT INTO verdicts
            (investigation_id,classification,source,confidence,rationale,is_binding)
            SELECT id,'legitimate','test',1,'Accepté',true FROM investigations WHERE message_id=$1::uuid""", result.message_id)
        await self.pool.execute("UPDATE messages SET facts=facts-'visible_content' WHERE id=$1::uuid", result.message_id)
        self.assertFalse(await store.reinvestigate(result.message_id))
        self.assertFalse(await self.pool.fetchval("SELECT facts ? 'visible_content' FROM messages WHERE id=$1::uuid", result.message_id))
        self.assertTrue(await self.pool.fetchval("""SELECT EXISTS(SELECT 1 FROM verdicts v JOIN investigations i
            ON i.id=v.investigation_id WHERE i.message_id=$1::uuid AND is_binding)""", result.message_id))
