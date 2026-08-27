"""Un signal produit doit pouvoir devenir un indice.

L'analyse profonde constate des faits et les publie sous forme de signaux, qui
sont ensuite traduits en indices du Code. La traduction se fait par une table :
un article absent de cette table voit son signal jeté, sans un mot.

Deux articles y sont restés depuis leur écriture. « Service conditionnel selon
le visiteur » - la page montrée au scanner n'est pas celle montrée au visiteur -
a été constaté une fois sur le courrier réel, et l'indice n'est jamais arrivé.
« Envoi de masse sans lien d'abonnement établi » n'a jamais rien produit non
plus. Deux détections écrites, testées, déployées, et muettes.

Ce test lit le module et compare ce qu'il produit à ce qu'il sait traduire.
"""

from __future__ import annotations

import inspect
import re
import unittest

from sentimail_v3.observation import deep_analysis


def _entre(source: str, debut: str, fin: str) -> str:
    depart = source.index(debut)
    return source[depart : source.index(fin, depart)]


class ToutSignalSaitDevenirIndiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = inspect.getsource(deep_analysis)

    def _produits(self) -> set[str]:
        return set(re.findall(r'"article_code": "([A-Z]+-\d+)"', self.source))

    def _traduits(self) -> set[str]:
        bloc = _entre(self.source, "_SIGNAL_RULES", "\nasync def persist_deep_hook_runs")
        return set(re.findall(r'"([A-Z]+-\d+)":\s*\(', bloc))

    def _auto_qualifies(self) -> set[str]:
        """Les signaux qui portent eux-mêmes leur énoncé et leur direction.

        Ils viennent d'un jugement de sens, où la direction est le résultat de
        l'appréciation et non d'une table. Ils n'ont pas besoin de règle.
        """
        return {"DEEP-021", "DEEP-022", "CORR-011"}

    def test_aucun_signal_n_est_jete_faute_de_traduction(self) -> None:
        orphelins = self._produits() - self._traduits() - self._auto_qualifies()
        self.assertEqual(
            orphelins,
            set(),
            f"signaux produits sans règle ni énoncé propre : {sorted(orphelins)}",
        )

    def test_le_service_conditionnel_sait_se_dire(self) -> None:
        self.assertIn("DEEP-020", self._traduits())

    def test_l_envoi_de_masse_sans_abonnement_sait_se_dire(self) -> None:
        self.assertIn("NATURE-002", self._traduits())

    def test_un_signal_jete_laisse_une_trace(self) -> None:
        # Sans elle, la prochaine détection écrite mais non branchée sera aussi
        # silencieuse que ces deux-là.
        bloc = _entre(self.source, "        rule = _SIGNAL_RULES.get(article_code)", "            else:")
        self.assertIn("signal_untranslated", bloc)


if __name__ == "__main__":
    unittest.main()
