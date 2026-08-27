from __future__ import annotations

import unittest

from sentimail_v3.supervision.replay import replay_outcome


class RejeuAnnonceTests(unittest.TestCase):
    """Un outil de diagnostic qui annonce un travail qu'il ne fera pas est pire
    qu'un outil absent : on croit avoir vérifié une correction.

    En mode décision, le moteur ne reprend que les messages en cours d'analyse.
    Rejouer un message déjà livré refait bien l'observation, mais aucun nouveau
    jugement ne suivra - alors que la commande annonçait que « le pipeline
    reprend son cours ».
    """

    def test_un_message_livre_ne_sera_pas_rejuge_en_mode_decision(self) -> None:
        outcome = replay_outcome("delivered", decision_mode=True)
        self.assertFalse(outcome["verdict_expected"])
        self.assertIn("observation", outcome["explanation"].casefold())

    def test_un_message_en_analyse_sera_rejuge(self) -> None:
        for statut in ("captured", "analyzing"):
            with self.subTest(statut=statut):
                outcome = replay_outcome(statut, decision_mode=True)
                self.assertTrue(outcome["verdict_expected"])

    def test_hors_mode_decision_le_message_livre_est_rejuge(self) -> None:
        # Le moteur d'observation, lui, ne juge que les messages déjà livrés.
        outcome = replay_outcome("delivered", decision_mode=False)
        self.assertTrue(outcome["verdict_expected"])

    def test_un_message_retenu_sera_bien_rejuge(self) -> None:
        # Le rejeu remet les dossiers non terminaux en « analyzing » : c'est le
        # statut d'arrivée qui décide, pas celui d'avant le rejeu. Raisonner sur
        # l'ancien ferait annoncer l'inverse de ce qui va se passer.
        for statut in ("held", "deferred"):
            with self.subTest(statut=statut):
                outcome = replay_outcome(statut, decision_mode=True)
                self.assertTrue(outcome["verdict_expected"])

    def test_seuls_les_etats_terminaux_echappent_au_jugement(self) -> None:
        for statut in ("delivered", "consumed", "undeliverable"):
            with self.subTest(statut=statut):
                outcome = replay_outcome(statut, decision_mode=True)
                self.assertFalse(outcome["verdict_expected"])

    def test_l_explication_dit_quoi_faire(self) -> None:
        outcome = replay_outcome("delivered", decision_mode=True)
        self.assertTrue(outcome["explanation"].strip())
        self.assertNotIn("reprend son cours", outcome["explanation"])


if __name__ == "__main__":
    unittest.main()
