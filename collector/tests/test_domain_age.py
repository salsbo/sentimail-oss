"""Une observation RDAP partagée ne fige pas l'âge des nouveaux messages."""

from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from sentimail_v3.judgment.verdict_engine import _compact_entities
from sentimail_v3.observation import deep_analysis as deep
from sentimail_v3.observation.domain_age import domain_age

OBSERVED = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
CAPTURED = OBSERVED + timedelta(days=6)
FACTS = {"creation_date": (OBSERVED-timedelta(days=28)).isoformat(), "age_days": 28}


class AgeDomaineTests(unittest.TestCase):
    def test_cache_age_de_six_jours_et_relecture_restent_immutables(self) -> None:
        source = copy.deepcopy(FACTS)
        self.assertEqual(domain_age(source, OBSERVED), 28)
        self.assertEqual(domain_age(source, CAPTURED), 34)
        self.assertEqual(domain_age(source, CAPTURED), 34)
        self.assertEqual(source, FACTS)

    def test_le_repli_accepte_les_anciens_snapshots_sans_date_valide(self) -> None:
        for creation in (None, "date invalide", "2026-02-30", 123):
            with self.subTest(creation=creation):
                self.assertEqual(domain_age({"creation_date": creation, "age_days": "28"}, CAPTURED), 28)
        for observed in (None, "absent", False, 2.5):
            self.assertIsNone(domain_age({"age_days": observed}, CAPTURED))

    def test_date_iso_z_et_fuseaux_representent_le_meme_instant(self) -> None:
        captured = datetime.fromisoformat("2026-10-30T14:00:00+01:00")
        self.assertEqual(domain_age({"creation_date": "2026-10-01T13:00:00Z"}, captured), 29)

    def test_le_dossier_compact_utilise_la_date_capture_sans_modifier_la_source(self) -> None:
        source = copy.deepcopy(FACTS)
        row = {"entity_type": "domain", "value_normalized": "young.example.org",
               "role": "sender", "attributes": {}, "enrichment_status": "ok",
               "enrichment_source": "rdap+dns", "enrichment_data": source}
        [entity] = _compact_entities([row], captured_at=CAPTURED)
        self.assertEqual(entity["enrichment"]["age_days"], 34)
        self.assertEqual(source, FACTS)
        # L'API de compaction seule conserve son comportement historique.
        self.assertEqual(_compact_entities([row])[0]["enrichment"]["age_days"], 28)


class HistoriqueAgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_historique_recalcule_age_du_message_et_garde_la_preuve(self) -> None:
        source = {"status": "ok", **FACTS, "countries": []}
        unchanged = copy.deepcopy(source)
        current = {"envelope_from": "sender@young.example.org",
                   "from_header": "sender@young.example.org",
                   "envelope_recipients": ["recipient@example.org"],
                   "captured_at": CAPTURED, "raw_size_bytes": 100,
                   "attachment_count": 0}
        pool = SimpleNamespace(
            fetchrow=AsyncMock(side_effect=[current, source, {"delivered_count": 0}]),
            fetch=AsyncMock(return_value=[]), fetchval=AsyncMock(return_value=False),
        )
        with patch.object(deep, "read_proven_identity", AsyncMock(return_value=None)), \
             patch.object(deep, "_learned_signals", AsyncMock(return_value=[])), \
             patch.object(deep, "profile_history", AsyncMock(return_value={})), \
             patch.object(deep, "asks_only_on_real_doubt", AsyncMock(return_value=False)):
            history = await deep._history(pool, "message")
        self.assertEqual(history["sender_domain_age_days"], 34)
        self.assertEqual(history["sender_domain_creation_date"], FACTS["creation_date"])
        self.assertEqual(source, unchanged)
