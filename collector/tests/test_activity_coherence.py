from __future__ import annotations

import unittest

from sentimail_v3.code.activity_coherence import (
    COHERENCE_PROMPT,
    coherence_clue,
    should_ask,
)


class ShouldAskTests(unittest.TestCase):
    """La question ne se pose que si elle peut apprendre quelque chose."""

    def test_un_expediteur_inconnu_avec_un_site_lisible_merite_la_question(self) -> None:
        self.assertTrue(
            should_ask(
                site_headline="Mutuelle santé, prévoyance et retraite complémentaire",
                clue_codes={"HISTORY_FIRST_OBSERVATION"},
            )
        )

    def test_un_correspondant_habituel_ne_merite_pas_la_question(self) -> None:
        # Son métier ne change pas d'un message à l'autre, et l'historique dit
        # déjà l'essentiel : dépenser un appel ici n'apprendrait rien.
        self.assertFalse(
            should_ask(
                site_headline="Mutuelle santé, prévoyance",
                clue_codes={"HISTORY_CONFIRMED_LEGITIMATE_SENDER"},
            )
        )

    def test_un_site_muet_ne_merite_pas_la_question(self) -> None:
        self.assertFalse(
            should_ask(site_headline="", clue_codes={"HISTORY_FIRST_OBSERVATION"})
        )

    def test_un_site_trop_court_ne_merite_pas_la_question(self) -> None:
        self.assertFalse(
            should_ask(site_headline="Bienvenue", clue_codes={"HISTORY_FIRST_OBSERVATION"})
        )


class CoherenceClueTests(unittest.TestCase):
    def test_une_incoherence_affirmee_devient_un_indice_a_charge(self) -> None:
        clue = coherence_clue(
            {"coherent": False, "explication": "Un installateur réseau n’expédie pas de colis."},
            sender_apex="fioresrl.com",
        )
        self.assertIsNotNone(clue)
        self.assertEqual(clue["clue_code"], "SENDER_ACTIVITY_INCOHERENT")
        self.assertEqual(clue["direction"], "adverse")
        self.assertIn("colis", str(clue["statement"]))

    def test_une_coherence_confirmee_devient_un_indice_favorable(self) -> None:
        clue = coherence_clue(
            {"coherent": True, "explication": "Une mutuelle envoie des codes de sécurité."},
            sender_apex="harmonie-mutuelle.fr",
        )
        self.assertEqual(clue["clue_code"], "SENDER_ACTIVITY_COHERENT")
        self.assertEqual(clue["direction"], "favorable")

    def test_une_reponse_illisible_ne_produit_aucun_indice(self) -> None:
        """Un modèle muet ou incohérent ne doit rien affirmer à sa place."""
        for reponse in ({}, {"coherent": "peut-être"}, {"explication": "..."}, None):
            with self.subTest(reponse=reponse):
                self.assertIsNone(coherence_clue(reponse, sender_apex="x.fr"))

    def test_l_indice_cite_ce_qui_l_a_fonde(self) -> None:
        clue = coherence_clue(
            {"coherent": False, "explication": "Sans rapport."}, sender_apex="x.fr"
        )
        self.assertEqual(clue["facts"]["sender_apex"], "x.fr")
        self.assertIn("explication", clue["facts"])


class PromptTests(unittest.TestCase):
    def test_le_doute_profite_a_l_expediteur(self) -> None:
        """Sans cette règle, tout site mal rédigé deviendrait suspect."""
        self.assertIn("doute", COHERENCE_PROMPT.casefold())

    def test_le_prompt_ne_demande_aucun_verdict(self) -> None:
        # Il apprécie une correspondance, il ne juge pas le message : le
        # verdict appartient au moteur de jugement, pas à cette question.
        for mot in ("spam", "phishing", "dangereux", "livrer"):
            self.assertNotIn(mot, COHERENCE_PROMPT.casefold())


if __name__ == "__main__":
    unittest.main()
