from __future__ import annotations

import json
import unittest

from sentimail_v3.supervision.training import SCHEMA, compact_dossier, fingerprint

DOSSIER = {
    "schema": "sentinel-verdict-dossier-v3-trial-roles",
    "message": {
        "subject": "Facture urgente à régler",
        "body_text": "Bonjour Alex, merci de virer 4200 euros sur IBAN FR76...",
        "from_header": "Compta <compta@fournisseur.example>",
        "favorable_points": 12,
        "adverse_points": 95,
        "investigation_status": "complete",
        "attachment_count": 1,
    },
    "selected_headers": [{"name": "subject", "value": "Facture urgente à régler"}],
    "entities": [{"value_normalized": "https://paiement.example/collecte?token=abc"}],
    "clues": [
        {
            "clue_code": "AUTH_DMARC_FAIL",
            "article_code": "AUTH-001",
            "direction": "adverse",
            "strength": 70,
            "confidence": 1.0,
            "statement": "Le relais de confiance indique DMARC=fail.",
            "facts": {"raw": "compta@fournisseur.example"},
        },
        {
            "clue_code": "URL_SANDBOX_FORM",
            "article_code": "DEEP-002",
            "direction": "adverse",
            "strength": 60,
            "confidence": 0.9,
            "statement": "Un formulaire réclame des identifiants.",
            "facts": {"final_apexes": ["paiement.example"]},
        },
    ],
    "judgment_rules": {
        "confidence_required": 0.9,
        "deep_execution_complete": True,
        "trusted_sender": False,
        "material_danger_evidence": [],
    },
    "deep_analysis": {
        "complete": True,
        "url_coverage": {"actionable_total": 12},
        "signals": [{"article_code": "DEEP-002", "kind": "credential_form"}],
        "history": {
            "previous_message_count": 3,
            "ground_truth_labels": {"spam": 2},
            "persistent_allow": False,
            "sender_domain_age_days": 12,
        },
    },
    "learned_signals": [{"clue_code": "AUTH_DMARC_FAIL", "confirmed_adverse": 4}],
}


class CompactDossierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.view = compact_dossier(DOSSIER)
        self.text = json.dumps(self.view, ensure_ascii=False)

    def test_no_personal_content_survives(self) -> None:
        for leak in (
            "Facture urgente",
            "Bonjour Alex",
            "IBAN",
            "compta@fournisseur.example",
            "paiement.example/collecte",
            "token=abc",
        ):
            self.assertNotIn(leak, self.text, f"{leak} ne doit pas être conservé")

    def test_the_reasoning_survives_entirely(self) -> None:
        codes = {clue["clue_code"] for clue in self.view["clues"]}
        self.assertEqual(codes, {"AUTH_DMARC_FAIL", "URL_SANDBOX_FORM"})
        self.assertEqual(self.view["counts"]["adverse"], 2)
        self.assertEqual(self.view["counts"]["adverse_points"], 95)
        self.assertEqual(self.view["judgment_rules"]["confidence_required"], 0.9)
        self.assertTrue(self.view["deep_analysis"]["complete"])
        self.assertEqual(self.view["history"]["ground_truth_labels"], {"spam": 2})
        self.assertEqual(self.view["schema"], SCHEMA)

    def test_evidence_families_group_the_clues(self) -> None:
        # Les familles sont celles du jugement, tirées de l'article et non du
        # préfixe du code : l'apprentissage doit ranger les preuves comme le
        # jugement les a rangées.
        self.assertEqual(self.view["evidence_families"], ["identite", "liens"])

    def test_the_view_is_far_smaller_than_the_dossier(self) -> None:
        complete = len(json.dumps(DOSSIER, ensure_ascii=False))
        self.assertLess(len(self.text), complete)

    def test_the_fingerprint_is_stable_and_content_addressed(self) -> None:
        self.assertEqual(fingerprint(self.view), fingerprint(compact_dossier(DOSSIER)))
        other = compact_dossier({**DOSSIER, "clues": DOSSIER["clues"][:1]})
        self.assertNotEqual(fingerprint(self.view), fingerprint(other))

    def test_an_empty_dossier_never_raises(self) -> None:
        view = compact_dossier({})
        self.assertEqual(view["clues"], [])
        self.assertEqual(view["evidence_families"], [])


if __name__ == "__main__":
    unittest.main()
