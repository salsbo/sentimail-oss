"""Les projections SQL remplacent NUL, l'original et ses mesures restent exacts."""

from __future__ import annotations

import base64
from contextlib import asynccontextmanager
import hashlib
import json
import os
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
import uuid

import asyncpg

from sentimail_v3.observation import storage
from sentimail_v3.observation.dossier.models import Clue, HookResult
from sentimail_v3.observation.parser import parse_message
from sentimail_v3.postgres_values import pg_json, pg_jsonsafe, pg_text

DSN = os.environ.get("NUL_TEST_DATABASE_URL", os.environ.get("ENRICHER_TEST_DATABASE_URL", ""))


class ProjectionTests(unittest.TestCase):
    def test_nul_est_remplace_sans_retirer_les_autres_caracteres(self):
        text = "Avant\x00après\n\tfin"
        self.assertEqual(pg_text(text), "Avant\ufffdaprès\n\tfin")
        self.assertEqual(text, "Avant\x00après\n\tfin")
        self.assertEqual(pg_text(b"avant\x00apres"), b"avant\x00apres")
        self.assertIsNone(pg_text(None))

    def test_json_imbrique_et_echappement_litteral_restent_distincts(self):
        original = {"cle\x00": ["valeur\x00", {"nested": ("\x00", "\\u0000")}], "raw": b"\x00"}
        safe = pg_jsonsafe(original)
        self.assertEqual(safe["cle\ufffd"][1]["nested"], ("\ufffd", "\\u0000"))
        self.assertEqual(safe["raw"], b"\x00")
        self.assertIn("cle\x00", original)
        decoded = json.loads(pg_json(original))
        self.assertEqual(decoded["cle\ufffd"][0], "valeur\ufffd")
        self.assertEqual(decoded["cle\ufffd"][1]["nested"][1], "\\u0000")
        self.assertNotIn("\x00", str(decoded))


class _PinnedPool:
    def __init__(self, connection):
        self.connection = connection

    def __getattr__(self, name):
        return getattr(self.connection, name)

    @asynccontextmanager
    async def acquire(self):
        yield self.connection


@unittest.skipUnless(DSN, "PostgreSQL local jetable requis")
class CaptureNulPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.assertEqual(urlsplit(DSN).hostname, "127.0.0.1")
        self.assertTrue(urlsplit(DSN).path.endswith("_test"))
        self.connection = await asyncpg.connect(DSN)
        self.transaction = self.connection.transaction()
        await self.transaction.start()
        self.pool = _PinnedPool(self.connection)

    async def asyncTearDown(self):
        await self.transaction.rollback()
        await self.connection.close()

    async def test_capture_et_rejeu_acceptent_toutes_les_projections_sans_changer_eml_ni_hash(self):
        body = "Avant\x00après".encode()
        raw = (f"From: sender@example.org\r\nTo: recipient@example.org\r\n"
               f"Message-ID: <{uuid.uuid4()}@test.example>\r\n"
               "Subject: Objet\x00visible\r\nX-Projection-Test: avant\x00apres\r\n"
               "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=nul-test\r\n\r\n"
               "--nul-test\r\nContent-Type: text/plain; charset=utf-8\r\n"
               "Content-Transfer-Encoding: base64\r\n\r\n").encode() + base64.b64encode(body) + (
               "\r\n--nul-test\r\nContent-Type: application/octet-stream\r\n"
               'Content-Disposition: attachment; filename="piece\x00test.bin"\r\n'
               "Content-Transfer-Encoding: base64\r\n\r\nAAEC\r\n--nul-test--\r\n").encode()
        parsed = parse_message(raw)
        original_hooks = storage.run_hooks
        original_entities = storage.extract_entities

        async def hooks(context):
            result = await original_hooks(context)
            result.append(HookResult("projection_test", "test", "error", 1.0,
                clues=[Clue("POLICY-001", "EVIDENCE_INCOMPLETE", "neutral", 0, 1.0,
                            "Texte\x00observé", facts={"nested": ["\x00"]}, provenance={"source": "preuve\x00"})],
                facts={"key\x00": "value\x00"}, error_type="ValueError", error_detail="Erreur\x00observée"))
            return result

        def entities(*args):
            return [*original_entities(*args), {"entity_type": "url", "role": "projection_test", "ordinal": 900,
                "value_raw": "https://example.org/a\x00b", "value_normalized": "https://example.org/a\x00b",
                "attributes": {"nested": {"key\x00": "value\x00"}}}]

        store = storage.Store(self.pool)
        with patch.object(storage, "run_hooks", hooks), patch.object(storage, "extract_entities", entities):
            captured = await store.capture(raw, "sender@example.org", ["recipient@example.org"], {"helo": "mx\x00example"})
            duplicate = await store.capture(raw, "sender@example.org", ["recipient@example.org"], {"helo": "mx\x00example"})
            self.assertFalse(duplicate.inserted)
            self.assertEqual(duplicate.message_id, captured.message_id)
            self.assertTrue(await store.reinvestigate(captured.message_id))
        row = await self.pool.fetchrow("""SELECT raw_eml,raw_sha256,raw_size_bytes,contains_nul,
            subject,smtp_helo,body_text,facts,ingest_key FROM messages WHERE id=$1::uuid""", captured.message_id)
        self.assertEqual(bytes(row["raw_eml"]), raw)
        self.assertEqual(row["raw_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(row["raw_size_bytes"], len(raw))
        self.assertEqual(row["contains_nul"], b"\x00" in raw)
        self.assertEqual(row["ingest_key"], storage.ingest_key(raw, "sender@example.org", ["recipient@example.org"]))
        self.assertEqual(row["subject"], "Objet\ufffdvisible")
        self.assertEqual(row["smtp_helo"], "mx\ufffdexample")
        self.assertIn("Avant\ufffdaprès", row["body_text"])
        self.assertIn("Avant\ufffdaprès", json.loads(row["facts"])["visible_content"]["text"])
        headers = await self.pool.fetch("SELECT value_raw,value_sha256 FROM headers WHERE message_id=$1::uuid ORDER BY ordinal", captured.message_id)
        self.assertEqual([h["value_sha256"] for h in headers], [h["value_sha256"] for h in parsed.headers])
        self.assertTrue(any("\ufffd" in h["value_raw"] for h in headers))
        parts = await self.pool.fetch("SELECT decoded_sha256,filename,text_content FROM mime_parts WHERE message_id=$1::uuid ORDER BY ordinal", captured.message_id)
        self.assertEqual([p["decoded_sha256"] for p in parts], [p["decoded_sha256"] for p in parsed.parts])
        self.assertTrue(any("Avant\ufffdaprès" in (p["text_content"] or "") for p in parts))
        hook = await self.pool.fetchrow("SELECT facts,error_detail FROM hook_runs WHERE investigation_id IN(SELECT id FROM investigations WHERE message_id=$1::uuid) AND hook_name='projection_test'", captured.message_id)
        self.assertEqual(hook["error_detail"], "Erreur\ufffdobservée")
        self.assertEqual(json.loads(hook["facts"]), {"key\ufffd": "value\ufffd"})
        clue = await self.pool.fetchrow("SELECT statement,facts,provenance FROM clues WHERE investigation_id IN(SELECT id FROM investigations WHERE message_id=$1::uuid) AND statement LIKE 'Texte%'", captured.message_id)
        self.assertEqual(clue["statement"], "Texte\ufffdobservé")
        self.assertEqual(json.loads(clue["facts"]), {"nested": ["\ufffd"]})
        entity = await self.pool.fetchrow("SELECT value_raw,value_normalized,attributes FROM entities WHERE message_id=$1::uuid AND role='projection_test'", captured.message_id)
        self.assertEqual(entity["value_raw"], "https://example.org/a\ufffdb")
        self.assertEqual(json.loads(entity["attributes"]), {"nested": {"key\ufffd": "value\ufffd"}})
