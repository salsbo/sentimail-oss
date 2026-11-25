"""La population opérationnelle ne se confond pas avec la qualité évaluée."""

from __future__ import annotations

import copy
import unittest

from sentimail_admin.pages import page_mesure
from test_pages import RAPPORT


class PopulationMesureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = copy.deepcopy(RAPPORT)
        self.report.update({
            "schema_version": 2,
            "window_start_utc": "2026-09-30T13:50:00+00:00",
            "window_end_utc": "2026-10-30T13:50:00+00:00",
            "population": {"captured": 412, "consumed_excluded": 20,
                           "protected": 392, "quality_evaluated": 366,
                           "ignored_with_notice": 13},
            "executions": {"deliver": 220, "ask_user": 52, "filed_as_junk": 94,
                           "suppressed": 8, "undeliverable": 7, "pending": 6,
                           "unconfirmed": 5},
            "residuals": {"missing_case": 2, "without_execution_event": 18,
                          "delivered_without_event": 5, "suppressed_without_event": 0},
        })

    def page(self) -> str:
        return page_mesure(self.report, "2026-10-30T14:00:00+00:00")

    def test_population_et_taux_ont_leurs_denominateurs_distincts(self) -> None:
        page = self.page()
        self.assertIn("412 messages captés", page)
        self.assertIn("20 échanges consommés par MAIA", page)
        self.assertIn("392 messages protégés", page)
        self.assertIn("366 messages dont la première", page)
        self.assertIn("sont exclus de ces taux", page)
        self.assertIn("<td>Supprimé par préférence authentifiée</td><td>8</td>", page)
        self.assertIn("<td>En attente de première exécution</td><td>6</td>", page)

    def test_le_silence_et_les_preuves_absentes_restent_visibles(self) -> None:
        page = self.page()
        self.assertIn("13 dossiers abandonnés", page)
        self.assertIn("silence ne crée aucune qualification", page)
        self.assertIn("18 sans événement", page)
        self.assertIn("5 marqués livrés", page)
        self.assertIn("219", page)  # Les livrés non qualifiés restent inconnus.
        self.assertNotIn("vérité terrain est presque complète", page)

    def test_les_dates_sont_lisibles_en_utc_y_compris_le_changement_d_heure(self) -> None:
        page = self.page()
        self.assertIn("30/09/2026 13:50 UTC", page)
        self.assertIn("30/10/2026 13:50 UTC", page)
        self.assertIn("borne de fin exclue", page)

    def test_une_mesure_ancienne_reste_lisible_avant_republication(self) -> None:
        page = page_mesure(RAPPORT, None)
        self.assertIn("Matrice", page)
        self.assertIn("219", page)
        self.assertNotIn("Population et premières exécutions", page)
