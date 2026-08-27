from __future__ import annotations

import unittest

from sentimail_v3.code.organisation import same_organisation_destinations


class SameOrganisationDestinationTests(unittest.TestCase):
    def test_une_redirection_vers_le_meme_groupe_est_reconnue(self) -> None:
        """Un groupe possède plusieurs domaines : ses liens ne détournent rien."""
        destinations = same_organisation_destinations(
            [{"initial_apex": "credit-agricole.fr", "final_apex": "ca-des-savoie.fr"}],
            sender_apex="credit-agricole.fr",
            organisations={
                "credit-agricole.fr": {"credit agricole"},
                "ca-des-savoie.fr": {"credit agricole"},
            },
        )
        self.assertEqual(destinations, ["ca-des-savoie.fr"])

    def test_une_redirection_vers_un_tiers_n_est_pas_reconnue(self) -> None:
        self.assertEqual(
            same_organisation_destinations(
                [{"initial_apex": "boutique.fr", "final_apex": "collecte-inconnue.top"}],
                sender_apex="boutique.fr",
                organisations={
                    "boutique.fr": {"boutique sas"},
                    "collecte-inconnue.top": {"autre chose"},
                },
            ),
            [],
        )

    def test_un_titulaire_masque_ne_conclut_rien(self) -> None:
        # Le RGPD masque la plupart des titulaires : sans information, on ne
        # peut ni rapprocher ni séparer, et surtout pas rassurer.
        self.assertEqual(
            same_organisation_destinations(
                [{"initial_apex": "boutique.fr", "final_apex": "ailleurs.com"}],
                sender_apex="boutique.fr",
                organisations={"boutique.fr": set(), "ailleurs.com": set()},
            ),
            [],
        )

    def test_une_destination_sur_le_domaine_de_l_expediteur_n_est_pas_comptee(
        self,
    ) -> None:
        # Rester chez soi n'est pas une convergence d'organisation : c'est déjà
        # traité comme une absence de saut inter-apex.
        self.assertEqual(
            same_organisation_destinations(
                [{"initial_apex": "boutique.fr", "final_apex": "boutique.fr"}],
                sender_apex="boutique.fr",
                organisations={"boutique.fr": {"boutique sas"}},
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
