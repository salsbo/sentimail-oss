from __future__ import annotations

import unittest

from sentimail_v3.code.families import FAMILIES
from sentimail_v3.judgment.verdict_engine import _judgment_rules, _prompt


class _Settings:
    auto_delivery_confidence = 0.9


def _dossier(clues: list[dict[str, object]]) -> dict[str, object]:
    return {
        "clues": clues,
        "code_articles": [],
        "message": {"investigation_status": "complete", "adverse_points": 0},
    }


def _clue(article: str, strength: int = 70) -> dict[str, object]:
    return {
        "clue_code": "X_" + article.replace("-", "_"),
        "article_code": article,
        "direction": "adverse",
        "strength": strength,
    }


class WiringTests(unittest.TestCase):
    """Une grille de lecture que le jugement ne reçoit pas ne sert à rien."""

    def test_le_jugement_recoit_la_couverture_par_famille(self) -> None:
        rules = _judgment_rules(
            _dossier([_clue("AUTH-001")]), {"complete": True}, _Settings()
        )
        coverage = rules["family_coverage"]
        self.assertEqual(len(coverage), len(FAMILIES))
        identite = next(f for f in coverage if f["family"] == "identite")
        self.assertFalse(identite["silent"])

    def test_le_jugement_recoit_les_familles_convergentes(self) -> None:
        rules = _judgment_rules(
            _dossier([_clue("AUTH-001"), _clue("ATT-010", 90)]),
            {"complete": True},
            _Settings(),
        )
        self.assertEqual(
            set(rules["converging_families"]), {"identite", "pieces_jointes"}
        )

    def test_trois_indices_d_un_meme_sujet_ne_font_pas_une_convergence(self) -> None:
        rules = _judgment_rules(
            _dossier([_clue("AUTH-001"), _clue("AUTH-002"), _clue("IDENTITY-001")]),
            {"complete": True},
            _Settings(),
        )
        self.assertEqual(rules["converging_families"], ["identite"])

    def test_la_couverture_ne_produit_aucun_score_global(self) -> None:
        # Le piège que cette grille doit éviter : moyenner les familles
        # redonnerait le chiffre unique qu'on cherche justement à ne pas faire.
        rules = _judgment_rules(
            _dossier([_clue("AUTH-001")]), {"complete": True}, _Settings()
        )
        interdits = {"family_score", "global_score", "total_strength", "risk_score"}
        self.assertEqual(interdits & set(rules), set())


class PromptTests(unittest.TestCase):
    def test_le_prompt_enseigne_qu_une_famille_muette_ne_plaide_rien(self) -> None:
        system = _prompt({})[0]["content"]
        self.assertIn("family_coverage", system)
        self.assertIn("muette", system.casefold())

    def test_le_prompt_rattache_la_convergence_aux_familles_calculees(self) -> None:
        self.assertIn("converging_families", _prompt({})[0]["content"])


if __name__ == "__main__":
    unittest.main()
