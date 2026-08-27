"""Chercher d'abord, juger ensuite : le nom affiché face au domaine réel.

L'ordre est ce qui change tout. Interroger le modèle en premier lui faisait
fermer la porte sur ce qu'il ignore - « dans le doute, ça peut appartenir » -
et aucune recherche ne partait. Ici il ne répond plus de mémoire, il répond sur
ce que la recherche a rendu.
"""

from __future__ import annotations

import unittest

from sentimail_v3.code.identity_relation import (
    RELATION_PROMPT,
    appended_to_official,
    obvious_relation,
    relation_clue,
    relation_question,
    worth_asking,
)


def _resultats(*paires: tuple[str, str]) -> list[dict[str, str]]:
    return [
        {"title": titre, "url": f"https://{hote}/", "content": titre}
        for titre, hote in paires
    ]


class RapportEvidentTests(unittest.TestCase):
    """Le courrier légitime ne doit rien coûter : ni recherche, ni modèle."""

    def test_le_nom_qui_reprend_son_domaine_ne_pose_pas_question(self) -> None:
        for nom, apex in (
            ("Synology News", "news.synology.com"),
            ("Crédit Agricole", "credit-agricole.fr"),
            ("Doctolib", "doctolib.fr"),
            ("L’équipe Vinted", "vinted.fr"),
        ):
            with self.subTest(nom=nom):
                self.assertTrue(obvious_relation(nom, apex))

    def test_un_nom_etranger_a_son_domaine_pose_question(self) -> None:
        for nom, apex in (
            ("DISNEY+ RECOVERY", "careerwiseenglish.com.au"),
            ("Service client PayPal", "printerpoint.co.in"),
        ):
            with self.subTest(nom=nom):
                self.assertFalse(obvious_relation(nom, apex))

    def test_un_domaine_qui_accole_la_marque_n_est_pas_la_marque(self) -> None:
        """C'est le montage le plus courant, et il passait pour évident.

        « doctolib-offres.fr » et « decathlon-offres.fr » contiennent le nom de
        la marque sans lui appartenir : les reconnaître sur cette base revenait
        à offrir la dispense de vérification à qui la fabrique.
        """
        for nom, apex in (
            ("Doctolib", "doctolib-offres.fr"),
            ("Decathlon", "decathlon-offres.fr"),
            ("PayPal", "paypal-securite.com"),
            ("Crédit Agricole d’Île-de-France", "ca-paris.fr"),
        ):
            with self.subTest(apex=apex):
                self.assertFalse(obvious_relation(nom, apex))

    def test_l_habillage_seul_ne_fait_pas_un_rapport(self) -> None:
        # « Service client » ne désigne personne : il ne peut pas non plus
        # servir à établir un rapport avec le domaine.
        self.assertFalse(obvious_relation("Service client", "exemple.test"))


class QuandLaQuestionSePoseTests(unittest.TestCase):
    def test_un_nom_qui_recopie_l_adresse_ne_revendique_rien(self) -> None:
        self.assertFalse(worth_asking("info@exemple.test", set()))

    def test_un_expediteur_deja_confirme_n_a_rien_a_prouver(self) -> None:
        self.assertFalse(
            worth_asking("DISNEY+", {"HISTORY_CONFIRMED_LEGITIMATE_SENDER"})
        )

    def test_un_intitule_sans_mot_propre_ne_se_cherche_pas(self) -> None:
        self.assertFalse(worth_asking("Service client", set()))

    def test_un_nom_d_organisation_se_confronte(self) -> None:
        self.assertTrue(worth_asking("DISNEY+ RECOVERY", set()))


class LaQuestionPoseeTests(unittest.TestCase):
    def test_les_deux_recherches_sont_montrees_au_modele(self) -> None:
        question = relation_question(
            display_name="DISNEY+ RECOVERY",
            from_apex="careerwiseenglish.com.au",
            sur_le_nom=_resultats(("Disney+ streaming", "disneyplus.com")),
            sur_le_domaine=_resultats(("English school in Sydney", "careerwiseenglish.com.au")),
        )
        self.assertIn("DISNEY+ RECOVERY", question)
        self.assertIn("careerwiseenglish.com.au", question)
        self.assertIn("Disney+ streaming", question)
        self.assertIn("English school", question)

    def test_rien_du_message_ne_part_avec_la_question(self) -> None:
        question = relation_question(
            display_name="DISNEY+ RECOVERY",
            from_apex="careerwiseenglish.com.au",
            sur_le_nom=[],
            sur_le_domaine=[],
        )
        for interdit in ("Objet", "OBJET", "destinataire", "corps"):
            self.assertNotIn(interdit, question)

    def test_les_domaines_officiels_trouves_sont_montres(self) -> None:
        """Sans eux, le juge tenait « doctolib-offres.fr » pour Doctolib.

        La recherche rendait pourtant « doctolib.fr » : l'information existait
        et ne lui était pas donnée.
        """
        question = relation_question(
            display_name="Doctolib",
            from_apex="doctolib-offres.fr",
            sur_le_nom=_resultats(("Doctolib, rendez-vous médicaux", "doctolib.fr")),
            sur_le_domaine=[],
            official_apexes=["doctolib.fr", "doctolib.de"],
        )
        self.assertIn("doctolib.fr", question)
        self.assertIn("n’en fait pas partie", question)

    def test_sans_domaine_officiel_trouve_rien_n_est_affirme(self) -> None:
        question = relation_question(
            display_name="Doctolib",
            from_apex="doctolib-offres.fr",
            sur_le_nom=[],
            sur_le_domaine=[],
            official_apexes=[],
        )
        self.assertNotIn("n’en fait pas partie", question)

    def test_la_consigne_refuse_le_domaine_accole(self) -> None:
        # « marque-offres.fr » n'est pas une explication : c'est le procédé.
        self.assertIn("accole", RELATION_PROMPT)

    def test_la_consigne_impose_le_doute(self) -> None:
        self.assertIn("null", RELATION_PROMPT)
        self.assertIn("Dans le doute", RELATION_PROMPT)


class DomaineAccoleTests(unittest.TestCase):
    """Accoler le nom d'un domaine officiel est le procédé, pas une explication."""

    def test_le_faux_la_poste_est_constate_sans_avis(self) -> None:
        self.assertEqual(
            appended_to_official("notif-colissimo-laposte.info", ["laposte.fr"]),
            "laposte.fr",
        )

    def test_le_domaine_d_offres_est_constate(self) -> None:
        self.assertEqual(
            appended_to_official("doctolib-offres.fr", ["doctolib.fr", "doctolib.de"]),
            "doctolib.fr",
        )

    def test_le_domaine_officiel_lui_meme_n_est_pas_une_imitation(self) -> None:
        self.assertEqual(appended_to_official("doctolib.fr", ["doctolib.fr"]), "")

    def test_un_sous_domaine_officiel_n_est_pas_une_imitation(self) -> None:
        self.assertEqual(appended_to_official("news.synology.com", ["synology.com"]), "")

    def test_un_domaine_etranger_ne_ressemble_a_rien(self) -> None:
        self.assertEqual(
            appended_to_official("careerwiseenglish.com.au", ["disneyplus.com"]), ""
        )


class IndiceProduitTests(unittest.TestCase):
    def test_l_absence_de_rapport_etayee_pese_le_plus(self) -> None:
        clue = relation_clue(
            {
                "rapport": False,
                "organisation": "Disney+",
                "explication": "Le domaine est celui d’une école de langue australienne.",
            },
            display_name="DISNEY+ RECOVERY",
            from_apex="careerwiseenglish.com.au",
            official_apexes=["disneyplus.com", "disney.com"],
            searched=True,
        )
        self.assertEqual(clue["article_code"], "DEEP-022")
        self.assertEqual(clue["facts"]["verified_by"], "search")
        # Une lecture de recherches pèse moins qu'un constat mécanique : le
        # modèle a tenu un routeur d'emailing pour une usurpation.
        self.assertLess(clue["strength"], 65)

    def test_sans_domaine_officiel_trouve_rien_n_est_reproche(self) -> None:
        """Le silence des moteurs n'accuse pas.

        Une petite entreprise peu référencée n'a pas à payer l'absence de
        résultats : c'est ce silence qui a fait accuser « Grange Immobilier »
        écrivant depuis grange-immo.fr.
        """
        self.assertIsNone(
            relation_clue(
                {"rapport": False, "organisation": "Disney+", "explication": "x"},
                display_name="DISNEY+ RECOVERY",
                from_apex="careerwiseenglish.com.au",
                official_apexes=[],
                searched=False,
            )
        )

    def test_un_rapport_reconnu_ne_produit_rien(self) -> None:
        self.assertIsNone(
            relation_clue(
                {"rapport": True, "organisation": "Synology", "explication": "x"},
                display_name="Synology News",
                from_apex="news.synology.com",
                official_apexes=["synology.com"],
                searched=True,
            )
        )

    def test_un_doute_ne_produit_rien(self) -> None:
        self.assertIsNone(
            relation_clue(
                {"rapport": None, "organisation": "", "explication": ""},
                display_name="Notifications",
                from_apex="exemple.test",
                official_apexes=[],
                searched=True,
            )
        )

    def test_une_reponse_hors_format_n_accuse_pas(self) -> None:
        for reponse in (None, {}, "non", [], {"rapport": "non"}):
            with self.subTest(reponse=reponse):
                self.assertIsNone(
                    relation_clue(
                        reponse,
                        display_name="X",
                        from_apex="exemple.test",
                        official_apexes=[],
                        searched=True,
                    )
                )


if __name__ == "__main__":
    unittest.main()
