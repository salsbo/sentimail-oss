from __future__ import annotations

import unittest

from sentimail_v3.observation.deep_analysis import _signals


def _codes(signals: list[dict[str, object]]) -> set[str]:
    return {str(value.get("article_code")) for value in signals}


class DeepOrganisationSignalTests(unittest.TestCase):
    def test_une_redirection_intra_groupe_est_constatee(self) -> None:
        """Sans ce constat, le lien d'un groupe vers ses propres domaines
        ressemble à un détournement et fait retenir un message ordinaire."""
        signals = _signals(
            [{"initial_apex": "credit-agricole.fr", "final_apex": "ca-des-savoie.fr"}],
            [],
            {},
            True,
            sender_apex="credit-agricole.fr",
            organisations={
                "credit-agricole.fr": {"credit agricole"},
                "ca-des-savoie.fr": {"credit agricole"},
            },
        )
        self.assertIn("DEEP-015", _codes(signals))

    def test_une_redirection_vers_un_tiers_ne_produit_rien(self) -> None:
        signals = _signals(
            [{"initial_apex": "boutique.fr", "final_apex": "collecte.top"}],
            [],
            {},
            True,
            sender_apex="boutique.fr",
            organisations={"boutique.fr": {"boutique"}, "collecte.top": {"autre"}},
        )
        self.assertNotIn("DEEP-015", _codes(signals))

    def test_sans_information_de_titulaire_rien_n_est_affirme(self) -> None:
        signals = _signals(
            [{"initial_apex": "boutique.fr", "final_apex": "ailleurs.com"}],
            [],
            {},
            True,
            sender_apex="boutique.fr",
            organisations={},
        )
        self.assertNotIn("DEEP-015", _codes(signals))


if __name__ == "__main__":
    unittest.main()
