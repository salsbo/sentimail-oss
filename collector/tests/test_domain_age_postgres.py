"""Le cache garde son âge observé ; ses lecteurs dérivent l'âge à réception."""

from __future__ import annotations

import json
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import asyncpg

from sentimail_v3.observation.deep_analysis import _domain_ages, _signals

DSN = os.environ.get("ENRICHER_TEST_DATABASE_URL", "")


@unittest.skipUnless(DSN, "base PostgreSQL locale jetable requise")
class AgeDomainePostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        self.connection = await asyncpg.connect(DSN)
        await self.connection.execute("""
            CREATE TEMP TABLE messages(id uuid, captured_at timestamptz);
            CREATE TEMP TABLE enrichments(id bigint, status text, data jsonb);
            CREATE TEMP TABLE entities(message_id uuid, entity_type text,
                                       value_normalized text, enrichment_id bigint);
        """)

    async def asyncTearDown(self) -> None:
        await self.connection.close()

    async def test_age_a_reception_et_reexamen_stable_sans_recrire_snapshot(self) -> None:
        observed = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
        old_message, new_message = uuid.uuid4(), uuid.uuid4()
        facts = {"creation_date": (observed-timedelta(days=28)).isoformat(), "age_days": 28}
        await self.connection.execute(
            "INSERT INTO enrichments VALUES(1,'ok',$1::jsonb)", json.dumps(facts))
        for message_id, captured in ((old_message, observed), (new_message, observed+timedelta(days=6))):
            await self.connection.execute("INSERT INTO messages VALUES($1,$2)", message_id, captured)
            await self.connection.execute(
                "INSERT INTO entities VALUES($1,'domain','young.example.org',1)", message_id)
        old_ages = await _domain_ages(self.connection, str(old_message))
        new_ages = await _domain_ages(self.connection, str(new_message))
        self.assertEqual(old_ages, {"example.org": 28})
        self.assertEqual(new_ages, {"example.org": 34})
        urls = [{"role": "actionable", "final_apex": "example.org"}]
        history = {"ground_truth_labels": {}, "previous_message_count": 1}
        old_signals = _signals(urls, [], history, True, authenticated=True,
                               sender_apex="sender.org", domain_ages=old_ages)
        new_signals = _signals(urls, [], history, True, authenticated=True,
                               sender_apex="sender.org", domain_ages=new_ages)
        self.assertIn("DOMAIN-004", {s["article_code"] for s in old_signals})
        self.assertNotIn("DOMAIN-004", {s["article_code"] for s in new_signals})
        self.assertEqual(await _domain_ages(self.connection, str(old_message)), {"example.org": 28})
        self.assertEqual(json.loads(await self.connection.fetchval(
            "SELECT data FROM enrichments WHERE id=1")), facts)

    async def test_date_absente_malformee_ou_age_invalide_ne_casse_pas_la_chaine(self) -> None:
        message_id = uuid.uuid4()
        await self.connection.execute(
            "INSERT INTO messages VALUES($1,$2)", message_id, datetime.now(timezone.utc))
        for identifier, domain, facts in (
            (1, "fallback.org", {"age_days": 28}),
            (2, "malformed.org", {"creation_date": "non-date", "age_days": "40"}),
            (3, "unknown.org", {"creation_date": "non-date", "age_days": "invalide"}),
        ):
            await self.connection.execute(
                "INSERT INTO enrichments VALUES($1,'ok',$2::jsonb)", identifier, json.dumps(facts))
            await self.connection.execute(
                "INSERT INTO entities VALUES($1,'domain',$2,$3)", message_id, domain, identifier)
        self.assertEqual(await _domain_ages(self.connection, str(message_id)), {
            "fallback.org": 28, "malformed.org": 40})
