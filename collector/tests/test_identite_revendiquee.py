from __future__ import annotations

import unittest

from sentimail_v3.code.identity_claim import (
    CLAIM_PROMPT,
    claim_clue,
    claim_question,
    should_ask_claim,
)


class QuandPoserLaQuestionTests(unittest.TestCase):
    """Un site illisible ne doit plus produire un silence.

    Le contrôle de cohérence exige une page d'accueil exploitable. Un domaine
    jetable n'en a pas : la question n'était donc pas posée, et l'absence de
    site - qui est en soi remarquable pour qui se réclame d'une organisation -
    ne laissait aucune trace.
    """

    def test_un_site_illisible_et_un_nom_d_organisation_declenchent(self) -> None:
        self.assertTrue(
            should_ask_claim(
                display_name="CIC-Passerelle", site_headline="", clue_codes=set()
            )
        )

    def test_un_site_lisible_ne_dispense_plus_de_la_question(self) -> None:
        """L'angle mort du 26 août : un vrai site, un nom d'emprunt.

        « DISNEY+ RECOVERY » écrivait depuis le domaine d'une école de langue
        australienne - domaine authentifié, site parfaitement lisible. La
        cohérence d'activité n'y voyait rien : son registre « abonnement »
        n'existe pas, et un site d'école ne contredit aucun envoi. Personne ne
        posait la seule question qui comptait : ce nom, est-ce bien lui ?
        """
        self.assertTrue(
            should_ask_claim(
                display_name="DISNEY+ RECOVERY",
                site_headline="Study English in Australia - courses for "
                "international students in Sydney and Melbourne.",
                clue_codes=set(),
            )
        )

    def test_sans_nom_affiche_il_n_y_a_rien_a_comparer(self) -> None:
        self.assertFalse(
            should_ask_claim(display_name="", site_headline="", clue_codes=set())
        )

    def test_un_expediteur_deja_confirme_ne_declenche_pas(self) -> None:
        self.assertFalse(
            should_ask_claim(
                display_name="CIC-Passerelle",
                site_headline="",
                clue_codes={"HISTORY_CONFIRMED_LEGITIMATE_SENDER"},
            )
        )

    def test_un_nom_affiche_qui_repete_l_adresse_ne_declenche_pas(self) -> None:
        # « info@exemple.test » comme nom affiché n'invoque aucune identité.
        self.assertFalse(
            should_ask_claim(
                display_name="info@printerpoint.co.in",
                site_headline="",
                clue_codes=set(),
            )
        )


class LaQuestionPoseeTests(unittest.TestCase):
    """Le domaine et le nom, et la question qui les relie."""

    def test_le_nom_et_le_domaine_y_sont(self) -> None:
        question = claim_question(
            display_name="CIC-Passerelle",
            from_apex="printerpoint.co.in",
            subject="Vous avez un nouveau message",
        )
        self.assertIn("CIC-Passerelle", question)
        self.assertIn("printerpoint.co.in", question)

    def test_la_consigne_ne_demande_aucune_liste(self) -> None:
        self.assertNotIn("liste", CLAIM_PROMPT.casefold())


class IndiceProduitTests(unittest.TestCase):
    """Adverse, ou rien. Jamais rassurant."""

    def test_un_domaine_etranger_a_l_organisation_est_adverse(self) -> None:
        indice = claim_clue(
            {"appartient": False, "organisation": "CIC",
             "explication": "CIC est une banque française, ce domaine est indien."},
            from_apex="printerpoint.co.in",
        )
        self.assertEqual(indice["direction"], "adverse")
        self.assertIn("CIC", str(indice["statement"]))

    def test_un_domaine_plausible_ne_produit_aucun_indice(self) -> None:
        # Rassurer sur la foi d'un site absent serait refaire l'erreur qu'on
        # vient de corriger : ici l'absence de preuve n'est pas une preuve.
        self.assertIsNone(
            claim_clue(
                {"appartient": True, "organisation": "Printer Point",
                 "explication": "le domaine reprend le nom."},
                from_apex="printerpoint.co.in",
            )
        )

    def test_un_nom_qui_ne_designe_aucune_organisation_ne_produit_rien(self) -> None:
        self.assertIsNone(
            claim_clue(
                {"appartient": None, "organisation": "", "explication": ""},
                from_apex="exemple.test",
            )
        )

    def test_une_reponse_hors_format_n_accuse_pas(self) -> None:
        for reponse in (None, {}, {"appartient": "non"}, "oui", []):
            with self.subTest(reponse=reponse):
                self.assertIsNone(claim_clue(reponse, from_apex="exemple.test"))

    def test_l_indice_porte_moins_que_la_coherence_mesuree(self) -> None:
        # Un jugement sans site repose sur moins de matière : il pèse moins que
        # celui qui a pu lire ce que l'expéditeur publie (55).
        indice = claim_clue(
            {"appartient": False, "organisation": "CIC", "explication": "x"},
            from_apex="printerpoint.co.in",
        )
        self.assertLess(int(indice["strength"]), 55)


if __name__ == "__main__":
    unittest.main()


class SupervisionTests(unittest.TestCase):
    """Un enquêteur non supervisé peut cesser de tourner sans que rien ne le dise."""

    def test_l_enqueteur_est_inscrit_au_registre(self) -> None:
        from sentimail_v3.observation.deep_hooks import DEEP_HOOKS

        self.assertIn("identity_claim", [hook.name for hook in DEEP_HOOKS])

    def test_la_sonde_exige_son_passage(self) -> None:
        from sentimail_v3.supervision.watchdog import REQUIRED_DEEP_HOOKS

        self.assertIn("identity_claim", REQUIRED_DEEP_HOOKS)

    def test_chaque_enqueteur_du_registre_est_exige(self) -> None:
        # Sinon un enquêteur ajouté échappe durablement au contrôle.
        from sentimail_v3.observation.deep_hooks import DEEP_HOOKS
        from sentimail_v3.supervision.watchdog import REQUIRED_DEEP_HOOKS

        self.assertEqual(
            sorted(hook.name for hook in DEEP_HOOKS), sorted(REQUIRED_DEEP_HOOKS)
        )


class LectureUniqueDuSiteTests(unittest.TestCase):
    """La page d'accueil est lue une fois, pas une fois par enquêteur."""

    def test_aucun_enqueteur_ne_va_chercher_le_site_lui_meme(self) -> None:
        import inspect

        from sentimail_v3.observation import deep_hooks

        source = inspect.getsource(deep_hooks)
        self.assertNotIn("_sender_site(", source)

    def test_l_indice_est_declare_en_mots_simples(self) -> None:
        from sentimail_v3.code.plain_words import _PLAIN

        self.assertIn("IDENTITY_CLAIMED_ORGANISATION_UNRELATED", _PLAIN)

    def test_l_article_a_une_famille(self) -> None:
        from sentimail_v3.code.families import _BY_ARTICLE

        self.assertIn("DEEP-021", _BY_ARTICLE)
