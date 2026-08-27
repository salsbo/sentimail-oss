from __future__ import annotations

import unittest

from sentimail_v3.observation.deep_analysis import (
    MAX_PROFILE_COMPARISONS,
    should_compare_profiles,
)


class PorteDuSecondProfilTests(unittest.TestCase):
    """Le second profil coûte une requête : il ne se déclenche pas partout.

    Une seconde inspection de chaque lien doublerait le coût qu'on vient de
    réduire. Elle se réserve donc là où le cloaking se cache : chez les
    expéditeurs que rien n'authentifie.
    """

    def test_un_expediteur_non_authentifie_merite_le_second_profil(self) -> None:
        self.assertTrue(
            should_compare_profiles(
                {"final_status": 200}, authenticated=False, deja_compares=0
            )
        )

    def test_un_expediteur_authentifie_ne_le_declenche_pas(self) -> None:
        # SPF, DKIM et DMARC alignés : l'expéditeur est celui qu'il annonce.
        # Se présenter en navigateur face à lui n'apprendrait rien et ferait
        # sortir le bac à sable sous une fausse identité sans raison.
        self.assertFalse(
            should_compare_profiles(
                {"final_status": 200}, authenticated=True, deja_compares=0
            )
        )

    def test_un_premier_rendu_en_erreur_ne_declenche_rien(self) -> None:
        # Sans premier rendu, il n'y a rien à comparer.
        self.assertFalse(
            should_compare_profiles(
                {"error": "hop_timeout"}, authenticated=False, deja_compares=0
            )
        )

    def test_un_lien_saute_ne_declenche_rien(self) -> None:
        self.assertFalse(
            should_compare_profiles(
                {"analysis_skipped": True}, authenticated=False, deja_compares=0
            )
        )

    def test_le_budget_par_message_est_borne(self) -> None:
        self.assertFalse(
            should_compare_profiles(
                {"final_status": 200},
                authenticated=False,
                deja_compares=MAX_PROFILE_COMPARISONS,
            )
        )

    def test_le_budget_reste_ouvert_juste_avant_la_limite(self) -> None:
        self.assertTrue(
            should_compare_profiles(
                {"final_status": 200},
                authenticated=False,
                deja_compares=MAX_PROFILE_COMPARISONS - 1,
            )
        )

    def test_le_budget_est_modeste(self) -> None:
        # Trois comparaisons suffisent à établir un service conditionnel ;
        # au-delà, on paie sans rien apprendre de plus.
        self.assertLessEqual(MAX_PROFILE_COMPARISONS, 3)


if __name__ == "__main__":
    unittest.main()
