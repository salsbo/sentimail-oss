from __future__ import annotations

import unittest

from sentimail_v3.observation.deep_analysis import compare_profiles


def _rendu(**champs: object) -> dict[str, object]:
    base: dict[str, object] = {
        "final_status": 200,
        "final_apex": "exemple.fr",
        "final_host": "www.exemple.fr",
        "forms": [],
        "content_digest": "aaa",
    }
    base.update(champs)
    return base


class DivergenceStructurelleTests(unittest.TestCase):
    """Le cloaking se prouve par une divergence de structure, pas de texte.

    Quarante pour cent des URL de phishing servent une page anodine au scanner
    et la vraie page au visiteur. Mais une page datée, personnalisée ou portant
    un jeton change à chaque appel : comparer le texte brut ferait de tout site
    dynamique un cloaker. Seules comptent les divergences qu'un contenu vivant
    ne produit pas de lui-même.
    """

    def test_deux_rendus_identiques_ne_sont_pas_du_cloaking(self) -> None:
        verdict = compare_profiles(_rendu(), _rendu())
        self.assertFalse(verdict["cloaking_detected"])
        self.assertEqual(verdict["divergences"], [])

    def test_un_texte_different_seul_ne_suffit_pas(self) -> None:
        # Une page qui affiche l'heure change à chaque appel : ce n'est pas
        # une preuve, seulement un contexte.
        verdict = compare_profiles(_rendu(), _rendu(content_digest="bbb"))
        self.assertFalse(verdict["cloaking_detected"])
        self.assertIn("content_digest", verdict["context"])

    def test_une_destination_differente_est_du_cloaking(self) -> None:
        verdict = compare_profiles(_rendu(), _rendu(final_apex="piege.tk"))
        self.assertTrue(verdict["cloaking_detected"])
        self.assertIn("final_apex", verdict["divergences"])

    def test_un_statut_different_est_du_cloaking(self) -> None:
        # Le scanner reçoit 404, le visiteur reçoit la page : le cas d'école.
        verdict = compare_profiles(_rendu(final_status=404), _rendu())
        self.assertTrue(verdict["cloaking_detected"])
        self.assertIn("final_status", verdict["divergences"])

    def test_un_formulaire_qui_n_apparait_que_pour_le_visiteur(self) -> None:
        visiteur = _rendu(forms=[{"action": "/login", "inputs": ["user", "pass"]}])
        verdict = compare_profiles(_rendu(), visiteur)
        self.assertTrue(verdict["cloaking_detected"])
        self.assertIn("form_count", verdict["divergences"])

    def test_plusieurs_divergences_sont_toutes_rapportees(self) -> None:
        visiteur = _rendu(final_apex="piege.tk", final_status=302, forms=[{"a": 1}])
        verdict = compare_profiles(_rendu(), visiteur)
        self.assertEqual(
            sorted(verdict["divergences"]),
            ["final_apex", "final_status", "form_count"],
        )


class ComparaisonImpossibleTests(unittest.TestCase):
    """Sans deux rendus exploitables, on ne conclut rien - surtout pas au calme."""

    def test_un_second_rendu_en_erreur_ne_conclut_pas(self) -> None:
        verdict = compare_profiles(_rendu(), {"error": "hop_timeout"})
        self.assertFalse(verdict["cloaking_detected"])
        self.assertTrue(verdict["comparison_incomplete"])

    def test_un_premier_rendu_en_erreur_ne_conclut_pas(self) -> None:
        verdict = compare_profiles({"error": "hop_timeout"}, _rendu())
        self.assertFalse(verdict["cloaking_detected"])
        self.assertTrue(verdict["comparison_incomplete"])

    def test_un_second_rendu_absent_ne_conclut_pas(self) -> None:
        verdict = compare_profiles(_rendu(), None)
        self.assertFalse(verdict["cloaking_detected"])
        self.assertTrue(verdict["comparison_incomplete"])

    def test_une_comparaison_aboutie_n_est_pas_incomplete(self) -> None:
        verdict = compare_profiles(_rendu(), _rendu())
        self.assertFalse(verdict["comparison_incomplete"])


class TraceDeLaComparaisonTests(unittest.TestCase):
    """Le dossier doit pouvoir dire ce qui a été comparé, et sous quoi."""

    def test_les_deux_profils_sont_nommes(self) -> None:
        verdict = compare_profiles(
            _rendu(profile="scanner"), _rendu(profile="browser")
        )
        self.assertEqual(verdict["profiles"], ["scanner", "browser"])

    def test_les_valeurs_divergentes_sont_montrees(self) -> None:
        verdict = compare_profiles(_rendu(), _rendu(final_apex="piege.tk"))
        preuve = verdict["evidence"]["final_apex"]
        self.assertEqual(preuve["scanner"], "exemple.fr")
        self.assertEqual(preuve["browser"], "piege.tk")



class RemonteeAuDossierTests(unittest.TestCase):
    """Un signal que l'examen final ne voit pas ne sert à rien."""

    def _resume(self, comparaison: dict[str, object] | None) -> dict[str, object]:
        from sentimail_v3.observation.deep_analysis import _url_summary

        data: dict[str, object] = {
            "initial_url": "https://exemple.fr/a",
            "initial_host": "exemple.fr",
            "final_host": "exemple.fr",
            "final_status": 200,
        }
        if comparaison is not None:
            data["profile_comparison"] = comparaison
        return _url_summary(data, "cle", {"url": "https://exemple.fr/a"})

    def test_le_cloaking_etabli_remonte_au_dossier(self) -> None:
        resume = self._resume(
            {
                "cloaking_detected": True,
                "comparison_incomplete": False,
                "divergences": ["final_apex"],
                "evidence": {"final_apex": {"scanner": "a.fr", "browser": "b.tk"}},
                "profiles": ["scanner", "browser"],
                "context": [],
            }
        )
        self.assertTrue(resume["cloaking_detected"])
        self.assertEqual(resume["cloaking_divergences"], ["final_apex"])

    def test_une_comparaison_negative_remonte_aussi(self) -> None:
        # Savoir qu'on a regardé et rien trouvé vaut mieux que le silence :
        # sans cela, l'examen ne peut pas distinguer « pas de cloaking » de
        # « pas cherché ».
        resume = self._resume(
            {
                "cloaking_detected": False,
                "comparison_incomplete": False,
                "divergences": [],
                "evidence": {},
                "profiles": ["scanner", "browser"],
                "context": [],
            }
        )
        self.assertFalse(resume["cloaking_detected"])
        self.assertTrue(resume["profiles_compared"])

    def test_sans_comparaison_le_dossier_le_dit(self) -> None:
        resume = self._resume(None)
        self.assertFalse(resume["profiles_compared"])
        self.assertFalse(resume["cloaking_detected"])

if __name__ == "__main__":
    unittest.main()


class SignalPourLExamenTests(unittest.TestCase):
    """Un cloaking établi doit devenir un indice, pas rester un champ inerte.

    Le dossier peut porter le fait ; sans article du code, il n'a aucun poids
    probatoire et l'examen final n'a rien pour le pondérer.
    """

    def _signaux(self, urls: list[dict[str, object]]) -> list[dict[str, object]]:
        from sentimail_v3.observation.deep_analysis import _cloaking_signals

        return _cloaking_signals(urls)

    def test_un_cloaking_etabli_produit_un_article(self) -> None:
        signaux = self._signaux(
            [
                {
                    "cloaking_detected": True,
                    "cloaking_divergences": ["final_apex"],
                    "final_apex": "piege.tk",
                }
            ]
        )
        self.assertEqual(len(signaux), 1)
        self.assertEqual(signaux[0]["article_code"], "DEEP-020")
        self.assertEqual(signaux[0]["kind"], "conditional_serving")

    def test_le_signal_dit_ce_qui_a_diverge(self) -> None:
        signaux = self._signaux(
            [
                {
                    "cloaking_detected": True,
                    "cloaking_divergences": ["final_apex", "form_count"],
                    "final_apex": "piege.tk",
                }
            ]
        )
        self.assertIn("final_apex", signaux[0]["divergences"])
        self.assertIn("form_count", signaux[0]["divergences"])

    def test_aucun_cloaking_ne_produit_aucun_article(self) -> None:
        self.assertEqual(
            self._signaux([{"cloaking_detected": False, "profiles_compared": True}]), []
        )

    def test_une_comparaison_non_faite_ne_produit_aucun_article(self) -> None:
        # Ne pas avoir cherché n'accuse personne.
        self.assertEqual(self._signaux([{"profiles_compared": False}]), [])

    def test_plusieurs_liens_cloakes_comptent_leurs_occurrences(self) -> None:
        signaux = self._signaux(
            [
                {"cloaking_detected": True, "cloaking_divergences": ["final_apex"]},
                {"cloaking_detected": True, "cloaking_divergences": ["final_status"]},
            ]
        )
        self.assertEqual(signaux[0]["occurrences"], 2)
