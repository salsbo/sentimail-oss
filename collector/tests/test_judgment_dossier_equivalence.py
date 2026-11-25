"""Compare la fabrication extraite au moteur figé avant la refonte."""

from __future__ import annotations

import copy
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
from decimal import Decimal
from functools import lru_cache
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import asyncpg

from sentimail_v3.judgment import dossier, dossier_view as view
from sentimail_v3.observation.storage import Store

DSN = os.environ.get("DOSSIER_TEST_DATABASE_URL", os.environ.get("ENRICHER_TEST_DATABASE_URL", ""))
SETTINGS = SimpleNamespace(auto_delivery_confidence=0.9)


@lru_cache(maxsize=1)
def oracle():
    path = Path(__file__).parent / "reference" / "verdict_engine_b07a5ec.py"
    spec = importlib.util.spec_from_file_location("sentimail_dossier_reference_b07a5ec", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def entity(kind, value, *, role="body", data=None, attributes=None):
    return {"entity_type": kind, "value_normalized": value, "role": role,
            "attributes": attributes or {}, "enrichment_data": data or {},
            "enrichment_status": "ok", "enrichment_source": "rdap+dns"}


class DossierViewEquivalenceTests(unittest.TestCase):
    def test_json_et_bornes_sont_identiques_y_compris_nul_et_types_sql(self):
        values = {"datetime": datetime(2026, 10, 30, tzinfo=timezone.utc),
                  "date": date(2026, 10, 30), "uuid": UUID("12345678-1234-1234-1234-123456789abc"),
                  "decimal": Decimal("0.95"), "nested": [{"nul\x00": "texte\x00"}],
                  "long": "x" * 2000}
        self.assertEqual(view._json(values), oracle()._json(values))
        for function in ("_bounded", "_short"):
            self.assertEqual(getattr(view, function)(values), getattr(oracle(), function)(values))
        for function in (view._json, oracle()._json):
            with self.assertRaisesRegex(TypeError, "unsupported JSON type: object"):
                function(object())

    def test_entites_jsonb_roles_troncature_et_age_ne_changent_pas(self):
        captured = datetime(2026, 10, 30, tzinfo=timezone.utc)
        facts = {"creation_date": "2026-10-01T00:00:00Z", "age_days": 1,
                 "dns": {"A": ["192.0.2.1"]}, "rdap": {"private": "absent du dossier"}}
        rows = [entity("domain", "exemple.org", data=facts),
                entity("domain", "exemple.org", role="header", data=json.dumps(facts))]
        rows += [entity("url", f"https://cdn.exemple.org/path/{i}?q=" + "x" * 1000,
                        attributes=json.dumps({"host": "cdn.exemple.org", "tracking": True})) for i in range(9)]
        rows += [entity("address", "user@example.org", attributes="JSON invalide")]
        before = copy.deepcopy(rows)
        actual = view._compact_entities(rows, captured_at=captured)
        self.assertEqual(actual, oracle()._compact_entities(copy.deepcopy(rows), captured_at=captured))
        self.assertEqual(rows, before)
        self.assertEqual(actual[0]["enrichment"]["age_days"], 29)
        self.assertEqual(actual[0]["roles"], ["body", "header"])
        self.assertNotIn("rdap", actual[0]["enrichment"])

    def test_deduplication_articles_et_ordre_du_cache_restent_exacts(self):
        clues = [{"id": 1, "clue_code": "AUTH_DMARC_PASS", "article_code": "AUTH-001", "direction": "favorable", "strength": 20},
                 {"id": 2, "clue_code": "AUTH_DMARC_PASS", "article_code": "AUTH-001", "direction": "favorable", "strength": 30},
                 {"id": 3, "clue_code": "AUTH_DMARC_PASS", "article_code": "AUTH-001", "direction": "adverse", "strength": 10}]
        articles = [{"article_code": "AUTH-001", "title": "Authentification", "principle": "p" * 1500},
                    {"article_code": "ATT-010", "title": "Pièce", "principle": "q"}]
        for name, args in (("_deduplicate_clues", (clues,)), ("_cited_code_articles", (articles, clues)),
                           ("_code_index", (articles,))):
            self.assertEqual(getattr(view, name)(*copy.deepcopy(args)), getattr(oracle(), name)(*copy.deepcopy(args)))
        value = {"message": {}, "clues": clues, "code_index": [], "privacy": {}, "schema": "schema", "attack_technique_registry": []}
        self.assertEqual(list(view._ordered_dossier(value)), list(oracle()._ordered_dossier(value)))
        self.assertEqual(view._json(view._ordered_dossier(value)), oracle()._json(oracle()._ordered_dossier(value)))

    def test_compaction_garde_exactement_les_memes_sections_et_limites(self):
        value = {"schema": "test", "message": {"body_text": "x" * 200000},
                 "clues": [{"clue_code": f"CLUE_{i}", "statement": "s" * 1800} for i in range(80)],
                 "entities": [{"value": "v" * 2000} for _ in range(150)],
                 "reference_knowledge": {"passages": [{"nature": "normative", "text": "r" * 3000},
                                                      {"nature": "adversarial", "text": "a" * 3000}]}}
        for limit in (140000, 500):
            with self.subTest(limit=limit), patch.object(oracle(), "MAX_LLM_DOSSIER_CHARS", limit):
                expected = oracle()._fit_dossier(copy.deepcopy(value))
                self.assertEqual(view._fit_dossier(copy.deepcopy(value), max_chars=limit), expected)
        self.assertEqual(view._fit_dossier({"message": {"body_text": "court"}}),
                         oracle()._fit_dossier({"message": {"body_text": "court"}}))

    def test_les_barrieres_voient_tous_les_indices_avant_compaction(self):
        clues = [{"clue_code": f"URL_BRUIT_{i}", "article_code": "URL-001", "direction": "adverse",
                  "strength": 50, "confidence": 0.9, "statement": "constat" * 100} for i in range(70)]
        clues.append({"clue_code": "ATTACHMENT_ACTIVE_CODE", "article_code": "ATT-010", "direction": "adverse",
                      "strength": 5, "confidence": 0.9, "statement": "Code actif"})
        value = {"message": {"investigation_status": "complete", "adverse_points": 0}, "clues": clues,
                 "code_articles": [{"article_code": "ATT-010", "parameters": json.dumps(
                     {"delivery_barrier": "material_danger", "material_kind": "active_code_execution"})}]}
        with patch.object(oracle(), "MAX_LLM_DOSSIER_CHARS", 500):
            expected = oracle()._prepare_for_judgment(copy.deepcopy(value), {"complete": True}, SETTINGS)
        actual = dossier._prepare_for_judgment(copy.deepcopy(value), {"complete": True}, SETTINGS, max_chars=500)
        self.assertEqual(actual, expected)
        self.assertTrue(actual["judgment_rules"]["material_danger_evidence"])
        self.assertNotIn("ATTACHMENT_ACTIVE_CODE", {c["clue_code"] for c in actual["clues"]})

    def test_aucun_module_dossier_ne_reimporte_le_workflow(self):
        root = Path(view.__file__).parent
        for filename in ("dossier.py", "dossier_view.py"):
            self.assertNotIn("verdict_engine", (root / filename).read_text())


class _PinnedPool:
    def __init__(self, connection):
        self.connection = connection

    def __getattr__(self, name):
        return getattr(self.connection, name)

    @asynccontextmanager
    async def acquire(self):
        yield self.connection


@unittest.skipUnless(DSN, "PostgreSQL local jetable requis")
class DossierDatabaseEquivalenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_dossier_reel_canonique_et_secours_produisent_le_meme_prompt(self):
        self.assertEqual(urlsplit(DSN).hostname, "127.0.0.1")
        self.assertTrue(urlsplit(DSN).path.endswith("_test"))
        connection = await asyncpg.connect(DSN)
        transaction = connection.transaction()
        await transaction.start()
        pool = _PinnedPool(connection)
        try:
            source = "source-" + uuid4().hex + ".com"
            raw = (f"From: Sender <sender@{source}>\r\nTo: recipient@example.org\r\n"
                   f"Message-ID: <{uuid4()}@test.example>\r\nSubject: Dossier fictif\r\n"
                   "Content-Type: text/html; charset=utf-8\r\n\r\n"
                   "<html><body><p>Montant et pièce de test.</p><a href='https://exemple.org/'>Consulter</a></body></html>").encode()
            capture = await Store(pool).capture(raw, f"sender@{source}", ["recipient@example.org"], {})
            investigation = await pool.fetchval("SELECT id::text FROM investigations WHERE message_id=$1::uuid", capture.message_id)
            enrichment = await pool.fetchval("""INSERT INTO enrichments(entity_type,value_normalized,source,status,data,expires_at)
                VALUES('domain',$1,'rdap+dns','ok',$2::jsonb,now()+interval '7 days') RETURNING id""", source,
                json.dumps({"creation_date": "2026-10-01T00:00:00Z", "age_days": 1, "dns": {"MX": ["mx.exemple.org"]}, "rdap": {"raw": "hors prompt"}}))
            await pool.execute("UPDATE entities SET enrichment_id=$3 WHERE message_id=$1::uuid AND entity_type='domain' AND value_normalized=$2",
                               capture.message_id, source, enrichment)
            deep = {"complete": True, "urls_complete": True, "attachments_complete": True,
                    "history": {"ground_truth_labels": {}, "ground_truth_feedback": [], "learned_signals": []}}
            for canonical in (True, False):
                with self.subTest(canonical=canonical):
                    if not canonical:
                        await pool.execute("UPDATE messages SET facts=facts-'visible_content' WHERE id=$1::uuid", capture.message_id)
                    actual = await dossier._build_dossier(pool, investigation, copy.deepcopy(deep))
                    expected = await oracle()._build_dossier(pool, investigation, copy.deepcopy(deep))
                    self.assertEqual(view._json(actual), oracle()._json(expected))
                    actual = dossier._prepare_for_judgment(actual, copy.deepcopy(deep), SETTINGS)
                    expected = oracle()._prepare_for_judgment(expected, copy.deepcopy(deep), SETTINGS)
                    self.assertEqual(oracle()._prompt(actual), oracle()._prompt(expected))
                    self.assertNotIn("body_html", actual["message"])
                    self.assertIn("Montant et pièce de test", actual["message"]["body_text"])
            self.assertEqual(await dossier._express_dossier(pool, capture.message_id),
                             await oracle()._express_dossier(pool, capture.message_id))
        finally:
            await transaction.rollback()
            await connection.close()
