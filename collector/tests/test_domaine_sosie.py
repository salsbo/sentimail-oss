"""Le domaine d'envoi écrit pour se lire comme un domaine officiel.

IDENTITY_COUSIN_DOMAIN n'avait plus de producteur depuis le 27 août 2026 : la
table de marques écrite à la main était partie, et CORR-004 exigeait son
indice sans que rien ne puisse le poser. La référence est désormais ce que les
recherches passées ont établi comme officiel, jamais une liste.

Tous les domaines de ce fichier sont fictifs.
"""

from __future__ import annotations

import unittest

from sentimail_v3.code.organisation_lookup import officials_in_memory
from sentimail_v3.code.sosies import domaine_sosie

OFFICIEL = ["exemplebanque.fr"]


class DomaineSosieTests(unittest.TestCase):
    def test_un_chiffre_pour_une_lettre_est_un_sosie(self) -> None:
        self.assertEqual(domaine_sosie("exemp1ebanque.fr", OFFICIEL), "exemplebanque.fr")

    def test_rn_pour_m_est_un_sosie(self) -> None:
        self.assertEqual(
            domaine_sosie("banquexernple.fr", ["banquexemple.fr"]), "banquexemple.fr"
        )

    def test_zero_pour_o_est_un_sosie(self) -> None:
        self.assertEqual(
            domaine_sosie("c0mptoirdusud.fr", ["comptoirdusud.fr"]), "comptoirdusud.fr"
        )

    def test_i_pour_l_est_un_sosie(self) -> None:
        self.assertEqual(
            domaine_sosie("iivraison-express.fr", ["livraison-express.fr"]),
            "livraison-express.fr",
        )

    def test_le_sosie_dans_un_sous_domaine(self) -> None:
        # L'apex est innocent ; le déguisement vit dans le domaine complet.
        self.assertEqual(
            domaine_sosie(
                "envoi-rapide.net",
                OFFICIEL,
                from_domain="exemp1ebanque.envoi-rapide.net",
            ),
            "exemplebanque.fr",
        )

    def test_l_ecriture_exacte_n_est_pas_un_sosie(self) -> None:
        # Le même domaine, ou la même étiquette sous une autre extension :
        # l'appartenance se juge ailleurs, pas par la graphie.
        self.assertEqual(domaine_sosie("exemplebanque.fr", OFFICIEL), "")
        self.assertEqual(domaine_sosie("exemplebanque.com", OFFICIEL), "")

    def test_le_nom_accole_releve_d_un_autre_constat(self) -> None:
        # Le nom écrit en entier avec un mot de plus : c'est le constat du nom
        # accolé (appended_to_official), déjà posé par la revendication.
        self.assertEqual(domaine_sosie("exemplebanque-offres.fr", OFFICIEL), "")

    def test_une_faute_de_frappe_n_est_pas_un_sosie(self) -> None:
        """Une lettre oubliée ou intervertie ne se lit pas comme l'autre.

        La distance d'édition d'une lettre touchait 15 messages, dont 13
        légitimes, sur toute la base du 11 août au 29 septembre 2026.
        """
        self.assertEqual(domaine_sosie("exemplebanqe.fr", OFFICIEL), "")
        self.assertEqual(domaine_sosie("exmeplebanque.fr", OFFICIEL), "")

    def test_une_etiquette_courte_ne_se_compare_pas(self) -> None:
        self.assertEqual(domaine_sosie("ab1d.fr", ["abid.fr"]), "")


class MemoireOfficielleTests(unittest.TestCase):
    def test_la_memoire_ne_retient_que_les_domaines_qui_portent_le_nom(self) -> None:
        # La table garde des lignes écrites avant le filtre par le nom.
        self.assertEqual(
            officials_in_memory(
                [("exemple banque", ["exemplebanque.fr", "annuaire-general.fr"])]
            ),
            {"exemplebanque.fr": "exemple banque"},
        )

    def test_un_hebergeur_n_est_officiel_pour_personne(self) -> None:
        self.assertEqual(officials_in_memory([("wikipedia", ["wikipedia.org"])]), {})


if __name__ == "__main__":
    unittest.main()
