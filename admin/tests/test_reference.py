"""La référence courte : ce qu'on cite pour parler d'un dossier."""

from __future__ import annotations

import unittest

from sentimail_admin import pages, queries
from sentimail_admin.reference import lire_reference, reference


class ReferenceTests(unittest.TestCase):
    _UUID = "c6280578-c338-4fdb-9d66-eaa5d5f9ed66"

    def test_une_reference_derive_de_l_identifiant(self) -> None:
        self.assertEqual(reference("E", self._UUID), "E-c62805")
        self.assertEqual(reference("M", self._UUID), "M-c62805")

    def test_la_meme_entree_donne_toujours_la_meme_reference(self) -> None:
        # Elle n'est pas stockée : sa stabilité est sa seule garantie.
        self.assertEqual(reference("E", self._UUID), reference("E", self._UUID))
        self.assertEqual(
            reference("E", self._UUID.upper()), reference("E", self._UUID)
        )

    def test_un_identifiant_absent_ne_produit_pas_de_reference(self) -> None:
        self.assertEqual(reference("E", None), "")
        self.assertEqual(reference("E", "abc"), "")

    def test_une_reference_se_relit_comme_on_la_recopie(self) -> None:
        for saisie in ("E-c62805", "e-c62805", " E-C62805 ", "E c62805"):
            with self.subTest(saisie=saisie):
                self.assertEqual(lire_reference(saisie), ("E", "c62805"))

    def test_ce_qui_n_est_pas_une_reference_est_refuse(self) -> None:
        # Refuser plutôt que chercher au hasard : une saisie approximative ne
        # doit pas ouvrir un dossier qui n'est pas celui qu'on visait.
        for saisie in ("bonjour", "E-c628", "X-c62805", "c62805", "", None):
            with self.subTest(saisie=saisie):
                self.assertIsNone(lire_reference(saisie))

    def test_le_recapitulatif_reste_une_famille_reconnue(self) -> None:
        # « D-… » vit dans une lettre et non dans une table : le reconnaître
        # permet de le dire, au lieu de rendre une erreur de saisie.
        self.assertEqual(lire_reference("D-3f9c1a"), ("D", "3f9c1a"))

    def test_le_bandeau_porte_le_champ_qui_ouvre_un_dossier(self) -> None:
        html = pages.document("Test", "/courrier", "<p>x</p>")
        self.assertIn('action="/aller"', html)
        self.assertIn('name="ref"', html)

    def test_le_courrier_cherche_le_prefixe_sans_l_interpoler(self) -> None:
        sql, params = queries.recent_messages(50, "e9e8f2")
        self.assertIn("id::text LIKE $1 || '%'", sql)
        self.assertNotIn("e9e8f2", sql)
        self.assertEqual(params, ("e9e8f2", 50))

    def test_sans_reference_le_courrier_reste_le_fil_complet(self) -> None:
        sql, params = queries.recent_messages(50)
        self.assertNotIn("LIKE", sql)
        self.assertEqual(params, (50,))

    def test_chaque_message_porte_sa_reference(self) -> None:
        html = pages.page_courrier(
            [
                {
                    "id": "e9e8f2cd-5c48-411b-87de-5b022f7b4f03",
                    "captured_at": None,
                    "delivery_status": "delivered",
                    "subject": "Objet",
                    "from_header": "a@b.fr",
                    "envelope_from": "a@b.fr",
                    "envelope_recipients": ["c@d.fr"],
                }
            ],
            10,
        )
        self.assertIn("M-e9e8f2", html)
        self.assertIn("<th>Réf.</th>", html)

    def test_une_reference_sans_message_le_dit(self) -> None:
        html = pages.page_courrier([], 10, "M-abcdef")
        self.assertIn("Aucun message ne porte la référence M-abcdef", html)

    def test_les_avis_de_saisie_existent(self) -> None:
        self.assertIn("reference_illisible", pages.AVIS)
        self.assertIn("reference_courrier", pages.AVIS)


if __name__ == "__main__":
    unittest.main()
