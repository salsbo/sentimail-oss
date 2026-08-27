from __future__ import annotations

import unittest

from sentimail_v3.code.requested_action import (
    ACTION_PROMPT,
    KNOWN_ACTIONS,
    action_clues,
)


class ActionClueTests(unittest.TestCase):
    def test_un_virement_demande_est_l_action_la_plus_grave(self) -> None:
        """Ce qui sépare un indésirable d'une fraude à cinq chiffres."""
        clues = action_clues({"actions": ["payment_transfer"], "explication": "Virement urgent demandé."})
        codes = {c["clue_code"]: c for c in clues}
        self.assertIn("ACTION_PAYMENT_TRANSFER", codes)
        self.assertEqual(codes["ACTION_PAYMENT_TRANSFER"]["direction"], "adverse")
        self.assertGreaterEqual(int(codes["ACTION_PAYMENT_TRANSFER"]["strength"]), 70)

    def test_un_changement_de_coordonnees_bancaires_est_grave(self) -> None:
        clues = action_clues({"actions": ["bank_details_change"]})
        self.assertEqual(clues[0]["clue_code"], "ACTION_BANK_DETAILS_CHANGE")
        self.assertGreaterEqual(int(clues[0]["strength"]), 70)

    def test_une_simple_lecture_n_est_pas_a_charge(self) -> None:
        # Lire, c'est ce que fait tout courrier : le compter accuserait tout.
        clues = action_clues({"actions": ["read_only"]})
        self.assertEqual(clues, [])

    def test_plusieurs_actions_produisent_plusieurs_indices(self) -> None:
        clues = action_clues({"actions": ["click_link", "credential_entry"]})
        codes = {c["clue_code"] for c in clues}
        self.assertEqual(codes, {"ACTION_CLICK_LINK", "ACTION_CREDENTIAL_ENTRY"})

    def test_une_action_inventee_est_ignoree(self) -> None:
        """Le modèle ne doit pas pouvoir créer de critère hors registre."""
        self.assertEqual(action_clues({"actions": ["danser_la_gigue"]}), [])

    def test_une_reponse_illisible_ne_produit_rien(self) -> None:
        for reponse in (None, {}, {"actions": "virement"}, {"actions": [123]}):
            with self.subTest(reponse=reponse):
                self.assertEqual(action_clues(reponse), [])

    def test_chaque_indice_porte_son_article_et_son_enonce(self) -> None:
        for clue in action_clues({"actions": sorted(KNOWN_ACTIONS)}):
            self.assertTrue(clue["article_code"])
            self.assertTrue(clue["statement"])
            self.assertIn(clue["direction"], ("adverse", "neutral"))


class PromptDistinctionTests(unittest.TestCase):
    """Le piège central de cette famille : fournir n'est pas réclamer."""

    def test_le_prompt_distingue_fournir_d_un_code_et_le_reclamer(self) -> None:
        # « Votre code est 481920 » est le service ; « renvoyez-nous le code »
        # est l'attaque. Sans cette distinction, tout code de connexion
        # légitime porterait l'indice le plus grave du registre.
        prompt = ACTION_PROMPT.casefold()
        self.assertIn("fourni", prompt)
        self.assertIn("mfa_code_disclosure", prompt)
        # La règle doit être écrite noir sur blanc, pas déduite.
        self.assertIn("communiquer", prompt)


class ActionRegistryTests(unittest.TestCase):
    def test_les_actions_de_fraude_sont_couvertes(self) -> None:
        """Celles qui font perdre de l'argent, pas seulement des identifiants."""
        for action in (
            "payment_transfer",
            "bank_details_change",
            "gift_card_purchase",
            "credential_entry",
            "mfa_code_disclosure",
            "qr_code_scan",
            "phone_callback",
            "file_execution",
        ):
            self.assertIn(action, KNOWN_ACTIONS)


class PromptTests(unittest.TestCase):
    def test_le_prompt_n_appelle_aucun_verdict(self) -> None:
        for mot in ("spam", "phishing", "dangereux", "livrer", "bloquer"):
            self.assertNotIn(mot, ACTION_PROMPT.casefold())

    def test_le_prompt_impose_le_registre_ferme(self) -> None:
        for action in ("payment_transfer", "read_only"):
            self.assertIn(action, ACTION_PROMPT)


if __name__ == "__main__":
    unittest.main()
