"""État compatible avec les anciens rapports et lecture explicite des tentatives."""

import json
import unittest
from datetime import datetime, timezone

from sentimail_admin.pages import page_etat


class ConsommationEtatTests(unittest.TestCase):
    def component(self, details):
        return [{"component": "sentimail-v3", "status": "ok", "observed_at": datetime.now(timezone.utc), "details": details}]

    def test_ancien_releve_sans_synthese_reste_lisible(self):
        html = page_etat(self.component({"reasons": []}), [])
        self.assertIn("État actuel", html)
        self.assertNotIn("Appels de modèles", html)

    def test_dates_et_denominateurs_explicites_sans_prix_invente(self):
        usage = {"status": "ok", "window_start_utc": "2026-10-29T12:30:00+00:00",
            "window_end_utc": "2026-10-30T12:30:00+00:00", "attempts": 5, "distinct_messages": 2,
            "unattributed_attempts": 1, "groups": [{"role": "analysis", "provider": "openai_compatible",
                "model_name": "<script>", "attempts": 5, "distinct_messages": 2, "complete": 2,
                "error": 1, "cancelled": 1, "started": 1, "usage_reported": 3,
                "input_tokens": 35, "output_tokens": 5, "cache_read_tokens": 9, "cache_creation_tokens": 4}]}
        html = page_etat(self.component(json.dumps({"reasons": [], "model_usage_24h": usage})), [])
        self.assertIn("29/10/2026 12:30 UTC", html)
        self.assertIn("30/10/2026 12:30 UTC", html)
        self.assertIn("5 tentatives", html)
        self.assertIn("2 messages distincts identifiés", html)
        self.assertIn("tentatives sans message rattaché : 1", html)
        self.assertIn("sans fin enregistrée", html)
        self.assertIn("Usage rapporté sur 3 tentatives", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)
        self.assertNotIn("€", html)

    def test_mesure_indisponible_ne_disparait_pas_dans_un_zero(self):
        html = page_etat(self.component({"reasons": [], "model_usage_24h": {"status": "unavailable"}}), [])
        self.assertIn("Mesure indisponible", html)
        self.assertIn("État actuel", html)
