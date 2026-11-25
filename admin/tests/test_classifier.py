"""L'observation ne s'affiche ni comme une économie ni comme une preuve de sûreté."""

import json
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

from sentimail_admin import classifier, pages
from sentimail_admin.app import classifieur


def state():
    return {"mode": "shadow", "model_id": "a" * 64,
            "observed_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc),
            "errors": "0", "downgrades": "0",
            "report": {"model_id": "a" * 64, "threshold": .995,
                       "training": {"groups": 1224, "expert_groups": 1, "teacher_groups": 1223},
                       "evaluation": {"expert_test": {"total": 0, "unsafe": 0},
                                      "teacher_test": {"total": 266, "accepted": 18, "unsafe": 0}},
                       "enforcement_blockers": ["validation expertisée insuffisante"],
                       "shadow": {"eligible_groups": 0}}}


class ClassifierPageTests(unittest.TestCase):
    def test_observation_et_absence_de_mesure_experte_sont_explicites(self):
        html = classifier.page(state(), {"compared": 0}, [])
        self.assertIn("En observation", html)
        self.assertIn("Aucun appel n'est économisé", html)
        self.assertIn("Non mesuré", html)
        self.assertIn("Pas encore mesurée", html)
        self.assertIn("validation expertisée insuffisante", html)

    def test_taux_compare_et_verdicts_locaux_sont_distincts(self):
        html = classifier.page(state(), {"compared": 100, "eligible": 12, "local_verdicts": 7}, [])
        self.assertIn("12.0%", html)
        self.assertIn("<strong>7</strong>", html)

    def test_un_rapport_perime_ne_confirme_pas_la_qualification(self):
        value = state()
        value["observed_at"] -= timedelta(minutes=11)
        html = classifier.page(value, {}, [])
        self.assertIn("Rapport de qualification indisponible", html)
        self.assertNotIn("validation expertisée insuffisante", html)

    def test_un_ancien_modele_ne_confirme_pas_le_nouveau(self):
        value = state()
        value["report"]["model_id"] = "b" * 64
        self.assertIn("Rapport de qualification indisponible", classifier.page(value, {}, []))

    def test_aucun_modele_et_rapport_json(self):
        self.assertIn("Aucun modèle installé", classifier.page({}, {}, []))
        value = state()
        value["report"] = json.dumps(value["report"])
        self.assertIn("1224 groupes appris", classifier.page(value, {}, []))

    def test_valeurs_echappees_et_navigation(self):
        value = state()
        value["report"]["enforcement_blockers"] = ["<script>danger</script>"]
        body = classifier.page(value, {}, [{"reason": "<img onerror=x>", "total": 2}])
        html = pages.document("Classifieur local", "/classifieur", body)
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn('href="/classifieur"', html)


class ClassifierRouteTests(unittest.IsolatedAsyncioTestCase):
    async def test_route_lit_les_mesures_sans_modification(self):
        pool = SimpleNamespace(fetch=AsyncMock(side_effect=[[state()], [{"compared": 0}], [], []]))
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(pool=pool)))
        response = await classifieur(request)
        self.assertEqual(response.status_code, 200)
        for call in pool.fetch.call_args_list:
            self.assertTrue(call.args[0].lstrip().startswith("SELECT"))
            self.assertNotIn("input_snapshot", call.args[0])
            self.assertNotIn("body_text", call.args[0])
