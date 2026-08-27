from __future__ import annotations

import unittest

from sentimail_v3.judgment.verdict_engine import _fit_dossier


def _gros_dossier() -> dict:
    return {
        "reference_knowledge": {
            "nature": "documentation citable",
            "passages": [
                {"document": "Techniques d'usurpation", "section": "1. Emprunt",
                 "text": "corps " * 100, "nature": "adversarial"},
                {"document": "RFC 7489", "section": "6. DMARC",
                 "text": "corps " * 100, "nature": "normative"},
            ],
        },
        "clues": [{"clue_code": f"CODE_{i}", "statement": "x" * 400} for i in range(200)],
        "entities": [{"value": "y" * 400} for _ in range(200)],
        "message": {"body_text": "z" * 60000},
    }


class DossierKeepsKnowledgeTests(unittest.TestCase):
    def test_la_doctrine_survit_a_la_compaction(self) -> None:
        """Elle était le premier élément supprimé : le juge ne la voyait jamais."""
        ajuste = _fit_dossier(_gros_dossier())

        self.assertTrue(ajuste["llm_budget"]["truncated_for_llm"])
        self.assertIn("reference_knowledge", ajuste)
        self.assertTrue(ajuste["reference_knowledge"]["passages"])

    def test_la_doctrine_adverse_est_conservee_en_priorite(self) -> None:
        ajuste = _fit_dossier(_gros_dossier())
        natures = {p["nature"] for p in ajuste["reference_knowledge"]["passages"]}
        self.assertIn("adversarial", natures)
