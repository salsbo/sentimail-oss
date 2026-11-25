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
    claimed_name,
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


class FaitDeProprieteTests(unittest.TestCase):
    """Un fait de propriété lève l'accusation « domaine avec un mot en plus ».

    Le 3 septembre 2026, e-ca-paris.fr a été accusé d'imiter ca-paris.com sur
    sa seule graphie, alors que sa délégation DNS - déjà en base - le
    rattachait à credit-agricole.fr, apex officiel trouvé par la recherche.
    """

    def test_la_delegation_ns_vers_un_apex_officiel_atteste_la_propriete(self) -> None:
        from sentimail_v3.code.identity_relation import owned_by_official

        self.assertEqual(
            owned_by_official(
                "e-ca-paris.fr",
                ["ca-paris.com", "credit-agricole.fr"],
                {"e-ca-paris.fr": {"ns:credit-agricole.fr"}},
            ),
            "credit-agricole.fr",
        )

    def test_une_signature_partagee_avec_un_apex_officiel_atteste(self) -> None:
        from sentimail_v3.code.identity_relation import owned_by_official

        self.assertEqual(
            owned_by_official(
                "free-mobile.fr",
                ["free.fr"],
                {
                    "free-mobile.fr": {"ns:proxad.net", "free sas"},
                    "free.fr": {"ns:proxad.net"},
                },
            ),
            "free.fr",
        )

    def test_la_signature_dkim_d_un_apex_officiel_atteste(self) -> None:
        from sentimail_v3.code.identity_relation import owned_by_official

        self.assertEqual(
            owned_by_official(
                "marque-offres.fr", ["marque.fr"], {"marque-offres.fr": {"dkim:marque.fr"}}
            ),
            "marque.fr",
        )

    def test_sans_fait_attestable_rien_ne_leve(self) -> None:
        """DNS mutualisé, RDAP masqué : on n'assouplit pas sur l'absence de preuve."""
        from sentimail_v3.code.identity_relation import owned_by_official

        self.assertEqual(
            owned_by_official("doctolib-offres.fr", ["doctolib.fr"], {}), ""
        )
        self.assertEqual(
            owned_by_official("doctolib-offres.fr", ["doctolib.fr"], {"doctolib-offres.fr": set()}),
            "",
        )

    def test_une_signature_etrangere_ne_leve_rien(self) -> None:
        from sentimail_v3.code.identity_relation import owned_by_official

        self.assertEqual(
            owned_by_official(
                "notif-colissimo-laposte.info",
                ["laposte.fr"],
                {
                    "notif-colissimo-laposte.info": {"ns:hebergeur-louche.ru"},
                    "laposte.fr": {"ns:laposte.fr"},
                },
            ),
            "",
        )


class AcronymeTests(unittest.TestCase):
    """Un sigle de trois lettres désigne quelqu'un, même écrit lettre à lettre.

    « C I C » depuis cic-notification.sju.somesepta.best (M-490357, 6 septembre
    2026) : aucun mot de quatre lettres, donc aucun jeton, donc aucune
    question posée - et le message est parti en doute au lieu d'être accusé.
    """

    def test_les_lettres_isolees_font_un_sigle(self) -> None:
        for nom in ("C I C", "C.I.C.", "C. I. C", "B N P"):
            with self.subTest(nom=nom):
                self.assertTrue(worth_asking(nom, set()))

    def test_un_sigle_en_majuscules_designe_quelqu_un(self) -> None:
        for nom in ("CIC", "WTW", "BNP", "Service Client WTW"):
            with self.subTest(nom=nom):
                self.assertTrue(worth_asking(nom, set()))

    def test_deux_lettres_ne_designent_personne(self) -> None:
        for nom in ("SG", "FR", "A B"):
            with self.subTest(nom=nom):
                self.assertFalse(worth_asking(nom, set()))

    def test_un_mot_court_en_minuscules_n_est_pas_un_sigle(self) -> None:
        self.assertFalse(worth_asking("cic", set()))

    def test_le_sigle_qui_reprend_son_domaine_ne_pose_pas_question(self) -> None:
        for nom, apex in (("CIC", "cic.fr"), ("C I C", "cic.fr"), ("BNP", "bnp.fr")):
            with self.subTest(nom=nom):
                self.assertTrue(obvious_relation(nom, apex))

    def test_le_sigle_etranger_a_son_domaine_pose_question(self) -> None:
        self.assertFalse(obvious_relation("C I C", "somesepta.best"))

    def test_le_nom_cherche_recolle_les_lettres(self) -> None:
        self.assertEqual(claimed_name("C I C"), "CIC")
        self.assertEqual(claimed_name("C.I.C. Banque"), "CIC Banque")
        self.assertEqual(claimed_name("Crédit Agricole"), "Crédit Agricole")


class SigleDansUnSousDomaineTests(unittest.TestCase):
    """Le nom volé peut vivre dans un sous-domaine, pas seulement dans l'apex."""

    def test_le_sigle_en_sous_domaine_est_constate(self) -> None:
        self.assertEqual(
            appended_to_official(
                "somesepta.best",
                ["cic.fr"],
                from_domain="cic-notification.sju.somesepta.best",
            ),
            "cic.fr",
        )

    def test_un_sigle_court_exige_un_segment_entier(self) -> None:
        # « pacific » contient « cic » : ce n'est pas une imitation.
        self.assertEqual(
            appended_to_official(
                "pacific-news.com", ["cic.fr"], from_domain="mail.pacific-news.com"
            ),
            "",
        )

    def test_le_sigle_dans_l_apex_est_constate(self) -> None:
        self.assertEqual(
            appended_to_official("cic-notification.best", ["cic.fr"]), "cic.fr"
        )

    def test_le_sous_domaine_officiel_n_est_pas_une_imitation(self) -> None:
        self.assertEqual(
            appended_to_official("cic.fr", ["cic.fr"], from_domain="notification.cic.fr"),
            "",
        )
