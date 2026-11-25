from __future__ import annotations

import inspect
import unittest

from sentimail_v3.judgment import verdict_engine


class AttendreCeQuiCompteTests(unittest.TestCase):
    """Attendre l'analyse, pas une horloge.

    Le moteur laissait passer trente secondes après la capture avant de
    prendre un message en charge. La pause existait pour laisser l'analyse se
    terminer - mais elle attendait une durée, pas l'analyse. Mesuré le 18 août
    sur un code de connexion X : investigation terminée en zéro seconde,
    verdict démarré trente et une secondes plus tard, message livré au bout de
    cinquante-cinq. Plus de la moitié du délai était cette pause, et elle
    frappait tous les messages.

    La condition porte désormais sur le fait attendu : l'investigation est-elle
    terminée. Le délai fixe demeure en filet, pour le dossier dont
    l'investigation n'aboutit jamais - sans lui, un message resterait en
    attente indéfiniment.
    """

    def _requete(self) -> str:
        return inspect.getsource(verdict_engine._claim)

    def test_l_investigation_terminee_ouvre_la_prise_en_charge(self) -> None:
        sql = self._requete()
        self.assertIn("investigations", sql)
        self.assertIn("completed_at", sql)

    def test_le_delai_fixe_reste_un_filet(self) -> None:
        # Sans lui, un dossier dont l'investigation n'aboutit jamais ne serait
        # jamais jugé : le retard deviendrait un silence.
        self.assertIn("analysis_wait_seconds", inspect.getsource(verdict_engine._claim))

    def test_les_deux_conditions_sont_alternatives(self) -> None:
        # « investigation terminée OU délai écoulé », jamais « ET » : exiger
        # les deux garderait l'attente de trente secondes.
        sql = self._requete()
        fenetre = sql[sql.index("delivery_status IN ('captured','analyzing')"):]
        fenetre = fenetre[: fenetre.index("ORDER BY")]
        self.assertIn(" OR ", fenetre)

    def test_l_attente_ne_bloque_plus_un_dossier_pret(self) -> None:
        # La formulation doit permettre la prise en charge immédiate : aucune
        # comparaison de captured_at ne doit rester seule à filtrer la fenêtre.
        sql = self._requete()
        fenetre = sql[sql.index("delivery_status IN ('captured','analyzing')"):]
        fenetre = fenetre[: fenetre.index("ORDER BY")]
        self.assertIn("i.completed_at IS NOT NULL", fenetre)


if __name__ == "__main__":
    unittest.main()
