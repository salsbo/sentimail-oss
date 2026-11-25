from __future__ import annotations

import json
import os
import unittest

import asyncpg
from sentimail_v3.code.attack_techniques import (
    dossier_view,
    recognized,
    summary,
)
from sentimail_v3.judgment.verdict_engine import _parse_verdict

REGISTRE = {
    "SENDER_SPOOFING": {
        "technique_code": "SENDER_SPOOFING",
        "name": "Usurpation d'adresse expéditeur",
        "category": "impersonation",
        "description": "explication",
        "indicator_clues": ["AUTH_DMARC_FAIL"],
        "mitre_refs": ["T1598", "T1656"],
    },
    "URGENCY_PRESSURE": {
        "technique_code": "URGENCY_PRESSURE",
        "name": "Pression par l'urgence",
        "category": "social_engineering",
        "description": "explication",
        "indicator_clues": ["CONTENT_URGENCY"],
        "mitre_refs": [],
    },
}
RULES = {
    "verdict_is_final": True,
    "confidence_required": 0.90,
    "deep_execution_complete": True,
    "static_investigation_complete": True,
    "material_danger_evidence": [],
    "authenticated_sender_policy": "none",
}


class ReconnaissanceTests(unittest.TestCase):
    def test_une_technique_inventee_disparait_sans_bruit(self) -> None:
        entries = recognized(
            ["SENDER_SPOOFING", "TECHNIQUE_IMAGINAIRE", "URGENCY_PRESSURE"],
            REGISTRE,
        )
        self.assertEqual(
            [entry["technique_code"] for entry in entries],
            ["SENDER_SPOOFING", "URGENCY_PRESSURE"],
        )

    def test_la_cartographie_vient_du_registre_pas_du_modele(self) -> None:
        carte = summary(recognized(["SENDER_SPOOFING"], REGISTRE))
        self.assertEqual(carte["mitre"], ["T1598", "T1656"])
        self.assertEqual(carte["categories"], ["impersonation"])

    def test_le_dossier_ne_porte_pas_la_pedagogie(self) -> None:
        # La description est pour le destinataire, pas pour le prompt.
        for entry in dossier_view(REGISTRE):
            self.assertNotIn("description", entry)


class VerdictAvecAttaqueTests(unittest.TestCase):
    def _dossier(self) -> dict:
        return {
            "clues": [
                {"id": 1, "clue_code": "AUTH_DMARC_FAIL", "direction": "adverse"}
            ],
            "judgment_rules": dict(RULES),
            "attack_technique_registry": dossier_view(REGISTRE),
        }

    def _reponse(self, techniques: list, rationale: str) -> str:
        return json.dumps(
            {
                "unfavorable": {"clue_codes": ["AUTH_DMARC_FAIL"], "arguments": []},
                "favorable": {"clue_codes": [], "arguments": []},
                "attack": {
                    "techniques": techniques,
                    "impersonated_brand": "Microsoft",
                    "targeted": False,
                },
                "final_verdict": {
                    "classification": "dangerous",
                    "confidence": 0.95,
                    "delivery_decision": "junk",
                    "rationale": rationale,
                    "doubt": True,
                    "doubt_reasons": [],
                },
            }
        )

    def test_les_techniques_reconnues_sont_filtrees_et_cartographiees(self) -> None:
        parsed = _parse_verdict(
            self._reponse(
                ["SENDER_SPOOFING", "INVENTION_TOTALE"], "Usurpation établie."
            ),
            self._dossier(),
        )
        self.assertEqual(parsed["attack"]["techniques"], ["SENDER_SPOOFING"])
        self.assertEqual(parsed["attack"]["mitre"], ["T1598", "T1656"])
        self.assertEqual(parsed["attack"]["impersonated_brand"], "Microsoft")

    def test_citer_une_technique_dans_la_motivation_est_permis(self) -> None:
        # SENDER_SPOOFING ressemble à un code de preuve : il ne doit pas faire
        # rejeter le verdict comme une invention.
        parsed = _parse_verdict(
            self._reponse(
                ["SENDER_SPOOFING"],
                "SENDER_SPOOFING est établi par l'échec DMARC.",
            ),
            self._dossier(),
        )
        self.assertEqual(parsed["classification"], "dangerous")

    def test_un_verdict_sans_attaque_reste_valide(self) -> None:
        reponse = json.loads(self._reponse([], "x"))
        del reponse["attack"]
        reponse["final_verdict"].update(
            {"classification": "suspect", "delivery_decision": "ask_user",
             "confidence": 0.7}
        )
        parsed = _parse_verdict(json.dumps(reponse), self._dossier())
        self.assertEqual(parsed["attack"], {})


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class RegistreEnBaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])

    async def asyncTearDown(self) -> None:
        await self.pool.close()

    async def test_le_registre_est_seme_et_pedagogique(self) -> None:
        from sentimail_v3.code.attack_techniques import pedagogy, registry

        techniques = await registry(self.pool)
        self.assertGreaterEqual(len(techniques), 20)
        self.assertIn("EXTORTION_SEXTORSION", techniques)
        lessons = await pedagogy(self.pool, ["QUISHING"])
        self.assertEqual(len(lessons), 1)
        self.assertIn("code", lessons[0]["description"].casefold())

    async def test_une_reconnaissance_alimente_le_registre_vivant(self) -> None:
        from sentimail_v3.code.attack_techniques import record_observations

        avant = await self.pool.fetchval(
            "SELECT observations FROM attack_techniques WHERE technique_code='QUISHING'"
        )
        await record_observations(self.pool, ["QUISHING"])
        apres = await self.pool.fetchrow(
            "SELECT observations, last_seen_at FROM attack_techniques "
            "WHERE technique_code='QUISHING'"
        )
        self.assertEqual(int(apres["observations"]), int(avant) + 1)
        self.assertIsNotNone(apres["last_seen_at"])


if __name__ == "__main__":
    unittest.main()
