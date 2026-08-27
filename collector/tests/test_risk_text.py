from __future__ import annotations

import unittest

from sentimail_v3.observation.risk_text import risky_text_excerpts


class RiskTextTests(unittest.TestCase):
    def test_extracts_exact_risky_sentences(self) -> None:
        excerpts = risky_text_excerpts(
            "Action urgente",
            "Bonjour. Votre compte est suspendu. Cliquez pour vérifier votre mot de passe.",
        )
        self.assertTrue(any("suspendu" in value for value in excerpts))
        self.assertTrue(any("mot de passe" in value for value in excerpts))

    def test_does_not_mark_ordinary_text(self) -> None:
        self.assertEqual(
            risky_text_excerpts("Compte rendu", "Bonjour, voici le document demandé."),
            [],
        )


if __name__ == "__main__":
    unittest.main()
