from __future__ import annotations

import unittest

from sentimail_v3.supervision.evaluation import (
    ASK,
    DELIVER,
    JUNK,
    SE_LABS_WEIGHTS,
    confusion_matrix,
    generalized_risk,
    hold_precision,
    labelling_coverage,
    lam_percent,
    trec_rates,
    utility_score,
)


def _cas(issue: str, verite: str | None, n: int = 1) -> list[dict[str, object]]:
    return [{"outcome": issue, "truth": verite} for _ in range(n)]


class MatriceTests(unittest.TestCase):
    """La matrice ne se ferme jamais sur la colonne « inconnu ».

    L'imputation des labels manquants est le mode d'échec documenté du scoring
    crédit : l'exactitude monte, le rappel s'effondre, et rien ne le montre.
    Ce qui n'est pas observé reste compté à part, visible, jamais réparti.
    """

    def test_les_trois_issues_sont_toujours_presentes(self) -> None:
        matrice = confusion_matrix(_cas(DELIVER, "legitimate"))
        self.assertEqual(sorted(matrice["rows"]), sorted([DELIVER, ASK, JUNK]))

    def test_l_inconnu_a_sa_propre_colonne(self) -> None:
        matrice = confusion_matrix(
            _cas(DELIVER, "legitimate", 3) + _cas(DELIVER, None, 97)
        )
        ligne = matrice["rows"][DELIVER]
        self.assertEqual(ligne["legitimate"], 3)
        self.assertEqual(ligne["unknown"], 97)
        self.assertEqual(ligne["total"], 100)

    def test_l_inconnu_n_est_jamais_reparti(self) -> None:
        # Le total labellisé ne doit pas absorber l'inconnu, sous aucune forme.
        matrice = confusion_matrix(_cas(ASK, None, 50) + _cas(ASK, "spam", 10))
        ligne = matrice["rows"][ASK]
        self.assertEqual(ligne["legitimate"] + ligne["spam"], 10)
        self.assertEqual(ligne["unknown"], 50)

    def test_une_reponse_ambigue_n_est_pas_une_classe(self) -> None:
        # La réponse C en texte libre ne peut pas être versée dans la matrice
        # sans arbitrage : elle est comptée à part, et sa croissance signale
        # que la question posée est mal formée.
        matrice = confusion_matrix(_cas(ASK, "ambiguous", 4))
        self.assertEqual(matrice["rows"][ASK]["ambiguous"], 4)
        self.assertEqual(matrice["rows"][ASK]["legitimate"], 0)
        self.assertEqual(matrice["rows"][ASK]["spam"], 0)

    def test_une_issue_inconnue_est_refusee(self) -> None:
        with self.assertRaises(ValueError):
            confusion_matrix([{"outcome": "teleporte", "truth": "spam"}])


class CouvertureTests(unittest.TestCase):
    """Sans couverture, aucun taux n'est lisible."""

    def test_la_couverture_est_donnee_par_issue(self) -> None:
        couverture = labelling_coverage(
            _cas(DELIVER, None, 90) + _cas(DELIVER, "spam", 10) + _cas(ASK, "spam", 5)
        )
        self.assertAlmostEqual(couverture[DELIVER]["rate"], 0.10)
        self.assertAlmostEqual(couverture[ASK]["rate"], 1.0)

    def test_une_issue_sans_message_ne_divise_pas_par_zero(self) -> None:
        couverture = labelling_coverage(_cas(DELIVER, "spam", 1))
        self.assertIsNone(couverture[JUNK]["rate"])
        self.assertEqual(couverture[JUNK]["total"], 0)


class PrecisionDeLaRetenueTests(unittest.TestCase):
    """La seule métrique dont la vérité terrain est presque complète.

    Quand le système dérange, avait-il raison ? C'est mesurable parce que
    l'utilisateur répond justement sur ce qu'on lui soumet.
    """

    def test_la_precision_ne_compte_que_les_retenus_labellises(self) -> None:
        precision = hold_precision(
            _cas(ASK, "spam", 3) + _cas(ASK, "legitimate", 1) + _cas(ASK, None, 40)
        )
        self.assertAlmostEqual(precision["value"], 0.75)
        self.assertEqual(precision["labelled"], 4)

    def test_sans_retenue_labellisee_la_precision_est_indefinie(self) -> None:
        precision = hold_precision(_cas(ASK, None, 12))
        self.assertIsNone(precision["value"])


class RisqueGeneraliseTests(unittest.TestCase):
    """La probabilité qu'un indésirable arrive sans aucun signal.

    C'est le risque généralisé, pas le risque sélectif : normaliser par les
    seuls livrés ferait baisser le chiffre dès qu'on retient davantage, à
    nombre de spams livrés identique.
    """

    def test_le_risque_est_normalise_par_le_volume_total(self) -> None:
        risque = generalized_risk(
            _cas(DELIVER, "spam", 2) + _cas(DELIVER, "legitimate", 8) + _cas(ASK, "spam", 90)
        )
        self.assertAlmostEqual(risque["value"], 0.02)

    def test_sans_sondage_aleatoire_ce_n_est_qu_une_borne_basse(self) -> None:
        risque = generalized_risk(_cas(DELIVER, "spam", 1) + _cas(DELIVER, None, 99))
        self.assertTrue(risque["lower_bound_only"])

    def test_avec_sondage_aleatoire_l_estimation_est_declaree(self) -> None:
        risque = generalized_risk(
            _cas(DELIVER, "spam", 1) + _cas(DELIVER, None, 99),
            sampled_delivered=True,
        )
        self.assertFalse(risque["lower_bound_only"])


class TauxTrecTests(unittest.TestCase):
    """hm% et sm%, avec les deux bornes pour la retenue.

    Un système dont les deux bornes divergent beaucoup ne décide pas : il
    transfère. L'écart est donc une information, pas une imprécision.
    """

    def test_les_deux_bornes_encadrent_la_retenue(self) -> None:
        taux = trec_rates(_cas(ASK, "spam", 10) + _cas(DELIVER, "spam", 10))
        self.assertAlmostEqual(taux["sm_optimistic"], 0.5)
        self.assertAlmostEqual(taux["sm_pessimistic"], 1.0)

    def test_un_legitime_retenu_compte_selon_la_borne(self) -> None:
        taux = trec_rates(_cas(ASK, "legitimate", 1) + _cas(DELIVER, "legitimate", 9))
        self.assertAlmostEqual(taux["hm_optimistic"], 0.0)
        self.assertAlmostEqual(taux["hm_pessimistic"], 0.1)

    def test_sans_classe_observee_le_taux_est_indefini(self) -> None:
        taux = trec_rates(_cas(DELIVER, None, 5))
        self.assertIsNone(taux["hm_optimistic"])
        self.assertIsNone(taux["sm_optimistic"])


class LamTests(unittest.TestCase):
    """L'agrégat qui n'arbitre pas entre les deux erreurs."""

    def test_deux_erreurs_egales_donnent_leur_valeur(self) -> None:
        self.assertAlmostEqual(lam_percent(0.10, 0.10), 0.10, places=6)

    def test_l_agregat_reste_entre_les_deux_erreurs(self) -> None:
        valeur = lam_percent(0.01, 0.25)
        self.assertGreater(valeur, 0.01)
        self.assertLess(valeur, 0.25)

    def test_une_erreur_nulle_ne_fait_pas_exploser_le_calcul(self) -> None:
        # logit(0) est indéfini : une correction de continuité est nécessaire.
        valeur = lam_percent(0.0, 0.10)
        self.assertIsNotNone(valeur)
        self.assertGreater(valeur, 0.0)

    def test_sans_taux_mesurable_l_agregat_est_indefini(self) -> None:
        self.assertIsNone(lam_percent(None, 0.1))


class UtiliteTests(unittest.TestCase):
    """Un chiffre unique dont les poids viennent d'un tiers, pas de nous."""

    def test_les_poids_sont_exposes_avec_le_score(self) -> None:
        score = utility_score(_cas(DELIVER, "legitimate", 1))
        self.assertEqual(score["weights"], SE_LABS_WEIGHTS)

    def test_livrer_un_legitime_est_le_meilleur_resultat(self) -> None:
        bon = utility_score(_cas(DELIVER, "legitimate", 10))
        retenu = utility_score(_cas(ASK, "legitimate", 10))
        self.assertGreater(bon["normalised"], retenu["normalised"])

    def test_livrer_un_indesirable_est_le_pire_resultat(self) -> None:
        mauvais = utility_score(_cas(DELIVER, "spam", 10))
        self.assertAlmostEqual(mauvais["normalised"], -1.0)

    def test_retenir_un_indesirable_vaut_mieux_que_le_classer(self) -> None:
        # Barème SE Labs : la quarantaine avec accès utilisateur protège mieux
        # qu'un dossier indésirables, parce que la menace est tenue plus loin.
        retenu = utility_score(_cas(ASK, "spam", 10))
        classe = utility_score(_cas(JUNK, "spam", 10))
        self.assertGreater(retenu["normalised"], classe["normalised"])

    def test_l_inconnu_ne_pese_rien(self) -> None:
        score = utility_score(_cas(DELIVER, "legitimate", 1) + _cas(DELIVER, None, 500))
        self.assertEqual(score["scored"], 1)

    def test_le_score_normalise_reste_borne(self) -> None:
        for cas in (
            _cas(DELIVER, "legitimate", 5),
            _cas(DELIVER, "spam", 5),
            _cas(ASK, "spam", 5) + _cas(JUNK, "legitimate", 5),
        ):
            with self.subTest(cas=cas[0]):
                valeur = utility_score(cas)["normalised"]
                self.assertGreaterEqual(valeur, -1.0)
                self.assertLessEqual(valeur, 1.0)


if __name__ == "__main__":
    unittest.main()
