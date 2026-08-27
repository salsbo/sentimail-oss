"""Chercher les domaines d'une organisation plutôt que de les énumérer.

Le référentiel de marques ne contenait pas « Disney », et rien ne pouvait donc
constater qu'une école de langue australienne n'est pas son service des
abonnements. La recherche répond à la seule question utile : quels domaines
cette organisation utilise-t-elle vraiment ?
"""

from __future__ import annotations

import unittest

from sentimail_v3.code.organisation_lookup import (
    belongs,
    lookup_outcome,
    official_apexes,
    search_query,
    searchable,
)


def _resultats(*urls: str) -> list[dict[str, object]]:
    return [{"url": url, "title": "", "content": ""} for url in urls]


class CeQuiPartDehorsTests(unittest.TestCase):
    def test_la_requete_ne_porte_que_le_nom_affiche(self) -> None:
        requete = search_query("DISNEY+ RECOVERY")
        self.assertIn("DISNEY+ RECOVERY", requete)
        # Ni adresse, ni domaine du destinataire, ni identifiant de compte.
        for interdit in ("@", "mondomaine", "destinataire"):
            self.assertNotIn(interdit, requete)

    def test_un_intitule_generique_ne_se_cherche_pas(self) -> None:
        for nom in ("Service client", "Notifications", "support", "Ne pas repondre"):
            with self.subTest(nom=nom):
                self.assertFalse(searchable(nom))

    def test_un_nom_d_organisation_se_cherche(self) -> None:
        for nom in ("Disney+", "Crédit Agricole", "Doctolib"):
            with self.subTest(nom=nom):
                self.assertTrue(searchable(nom))


class DomainesRetenusTests(unittest.TestCase):
    def test_les_domaines_officiels_sont_extraits_dans_l_ordre(self) -> None:
        apexes = official_apexes(
            _resultats("https://www.disneyplus.com/fr-fr", "https://disney.fr/")
        )
        self.assertEqual(apexes, ["disneyplus.com", "disney.fr"])

    def test_les_annuaires_et_encyclopedies_ne_sont_pas_des_sites_officiels(
        self,
    ) -> None:
        # Sinon un message envoyé depuis wikipedia.org passerait pour Disney.
        apexes = official_apexes(
            _resultats(
                "https://fr.wikipedia.org/wiki/Disney%2B",
                "https://www.linkedin.com/company/disney",
                "https://www.disneyplus.com/",
            )
        )
        self.assertEqual(apexes, ["disneyplus.com"])

    def test_un_suffixe_a_deux_etiquettes_garde_son_domaine(self) -> None:
        self.assertEqual(
            official_apexes(_resultats("https://careerwiseenglish.com.au/about")),
            ["careerwiseenglish.com.au"],
        )

    def test_un_meme_domaine_n_est_compte_qu_une_fois(self) -> None:
        self.assertEqual(
            official_apexes(
                _resultats("https://disney.com/a", "https://www.disney.com/b")
            ),
            ["disney.com"],
        )


class AppartenanceTests(unittest.TestCase):
    def test_un_sous_domaine_appartient_a_son_apex(self) -> None:
        self.assertTrue(belongs("mail.disneyplus.com", ["disneyplus.com"]))

    def test_une_ressemblance_de_nom_ne_suffit_pas(self) -> None:
        # « disneyplus-billing.top » est exactement ce qu'un montage fabrique.
        self.assertFalse(belongs("disneyplus-billing.top", ["disneyplus.com"]))

    def test_un_domaine_etranger_n_appartient_pas(self) -> None:
        self.assertFalse(belongs("careerwiseenglish.com.au", ["disneyplus.com"]))


class CeQueLaRechercheApprendTests(unittest.TestCase):
    def test_le_cas_du_26_aout_est_verifie(self) -> None:
        issue = lookup_outcome(
            "Disney+",
            "careerwiseenglish.com.au",
            ["disneyplus.com", "disney.fr"],
        )
        self.assertTrue(issue["verified"])
        self.assertFalse(issue["cleared"])
        self.assertIn("disneyplus.com", str(issue["statement"]))
        self.assertIn("careerwiseenglish.com.au", str(issue["statement"]))

    def test_le_bruit_du_moteur_n_est_pas_cite(self) -> None:
        """« nlm.nih.gov » est arrivé dans les résultats pour Disney+.

        Il ne change pas la décision, mais l'écrire dans un avis affirmerait
        une sottise à l'utilisateur.
        """
        issue = lookup_outcome(
            "Disney+",
            "careerwiseenglish.com.au",
            ["disneyplus.com", "disney.com", "nlm.nih.gov", "disneycareers.com"],
        )
        self.assertNotIn("nlm.nih.gov", str(issue["statement"]))
        self.assertIn("disneyplus.com", str(issue["statement"]))
        # La décision, elle, a bien vu la liste entière.
        self.assertIn("nlm.nih.gov", issue["official_apexes"])

    def test_un_domaine_sans_rapport_lexical_reste_citable(self) -> None:
        # « Ameli » publie sur assurance-maladie.fr : aucun mot commun, et
        # pourtant c'est bien son domaine. Faute de mieux, on cite les premiers.
        issue = lookup_outcome(
            "Ameli", "courrier-ameli.top", ["assurance-maladie.fr", "ameli.fr"]
        )
        self.assertIn("ameli.fr", str(issue["statement"]))

    def test_un_domaine_officiel_annule_le_soupcon(self) -> None:
        # Le modèle peut se tromper : la recherche doit pouvoir le démentir.
        issue = lookup_outcome("Synology", "news.synology.com", ["synology.com"])
        self.assertTrue(issue["cleared"])
        self.assertFalse(issue["verified"])

    def test_une_recherche_sans_resultat_laisse_le_soupcon_intact(self) -> None:
        self.assertIsNone(lookup_outcome("Disney+", "exemple.test", []))


if __name__ == "__main__":
    unittest.main()
