"""Répondre depuis une autre adresse que celle où l'avis est arrivé.

Une personne lit ses avis dans une boîte et répond depuis une autre : son
logiciel agrège plusieurs comptes et signe avec l'identité par défaut. La
réponse portait pourtant le jeton de l'avis. Elle était rejetée en silence,
et la décision humaine - la seule vérité dont dispose SentiMail - se perdait.
"""

from __future__ import annotations

import unittest

from sentimail_v3.conversation.reply_alias import (
    ALIAS_PURPOSE,
    ALIAS_TTL_MINUTES,
    alias_challenge_letter,
    alias_decision,
)


class DecisionTests(unittest.TestCase):
    def test_la_boite_attendue_est_acceptee_sans_rien_demander(self) -> None:
        self.assertEqual(alias_decision(True, False), "accept")

    def test_un_alias_deja_confirme_est_accepte_directement(self) -> None:
        """Une fois suffit : c'est ce qui rend le réglage durable."""
        self.assertEqual(alias_decision(False, True), "accepted_alias")

    def test_une_adresse_inconnue_demande_une_confirmation(self) -> None:
        self.assertEqual(alias_decision(False, False), "challenge")

    def test_la_boite_attendue_n_a_jamais_besoin_d_alias(self) -> None:
        self.assertEqual(alias_decision(True, True), "accept")


class CourrierDeConfirmationTests(unittest.TestCase):
    """Le courrier part vers la boîte de l'avis, jamais vers l'adresse à valider.

    C'est ce qui distingue la personne de quelqu'un à qui l'avis a été
    transféré : seul celui qui lit la boîte peut ouvrir l'alias.
    """

    def _lettre(self, code: str = "AB3D9K") -> tuple[str, str]:
        return alias_challenge_letter(
            "cmartin@example.org", "cmartin@agence.example", code
        )

    def test_les_deux_adresses_sont_nommees(self) -> None:
        _, corps = self._lettre()
        self.assertIn("cmartin@example.org", corps)
        self.assertIn("cmartin@agence.example", corps)

    def test_le_code_est_a_recopier_avec_la_phrase(self) -> None:
        _, corps = self._lettre()
        self.assertIn("CONFIRME MAIA AB3D9K", corps)

    def test_la_lettre_dit_que_la_reponse_sera_appliquee(self) -> None:
        # Sans cela, on demande un geste sans dire ce qu'on en fait.
        _, corps = self._lettre()
        self.assertIn("prise en compte", corps.casefold())

    def test_la_lettre_dit_qu_une_fois_suffit(self) -> None:
        _, corps = self._lettre()
        self.assertIn("une seule fois", corps.casefold())

    def test_le_code_vit_assez_pour_qu_on_lise_son_courrier(self) -> None:
        """Cinq minutes conviennent à qui attend devant sa boîte ; pas ici.

        Le courrier arrive au milieu d'une journée, dans la boîte que l'on ne
        consulte justement pas en premier - c'est même la raison du problème.
        """
        self.assertGreaterEqual(ALIAS_TTL_MINUTES, 60)
        _, corps = self._lettre()
        self.assertIn("24 heures", corps)

    def test_l_objet_ne_porte_aucune_sequence_machine(self) -> None:
        sujet, _ = self._lettre()
        self.assertNotIn("S3-ACTION", sujet)
        self.assertIn("MAIA", sujet)

    def test_le_courrier_n_invite_pas_a_agir_si_l_on_n_y_est_pour_rien(self) -> None:
        _, corps = self._lettre()
        self.assertIn("ignore", corps.casefold())


class PurposeTests(unittest.TestCase):
    def test_le_motif_est_distinct_des_autres_actions(self) -> None:
        self.assertEqual(ALIAS_PURPOSE, "confirm_reply_alias")
