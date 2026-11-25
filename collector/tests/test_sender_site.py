from __future__ import annotations

import unittest

from sentimail_v3.code.sender_site import (
    activity_registers,
    is_interstitial,
    is_navigation_chrome,
)


class ActivityRegisterTests(unittest.TestCase):
    def test_un_message_de_livraison_est_reconnu(self) -> None:
        self.assertIn(
            "livraison",
            activity_registers(
                "Votre paquet est en attente de vos instructions",
                "Votre colis n'a pas pu être livré. Régularisez les frais de port.",
            ),
        )

    def test_le_vocabulaire_reel_des_arnaques_au_colis_est_couvert(self) -> None:
        for sujet in (
            "Votre paquet est en attente de vos instructions",
            "Votre envoi n'a pas pu être remis",
            "Point de retrait : action requise",
        ):
            with self.subTest(sujet=sujet):
                self.assertIn("livraison", activity_registers(sujet, ""))

    def test_un_message_bancaire_est_reconnu(self) -> None:
        self.assertIn(
            "paiement",
            activity_registers(
                "Virement en attente",
                "Merci de confirmer vos coordonnées bancaires et votre IBAN.",
            ),
        )

    def test_un_message_ordinaire_n_invoque_aucun_registre(self) -> None:
        self.assertEqual(
            activity_registers("Compte rendu de réunion", "Voici les notes de lundi."),
            set(),
        )


class UnePageDeVerificationNeDecritAucuneActiviteTests(unittest.TestCase):
    def test_les_interstitiels_connus_sont_ecartes(self) -> None:
        for page in (
            "Enable JavaScript and cookies to continue",
            "Just a moment... Checking your browser before accessing the site.",
            "Verify you are human by completing the action below.",
            "Attention Required! | Cloudflare · Please enable cookies.",
            "Access denied · Error 1020 · You do not have access to this page.",
            "Please turn JavaScript on and reload the page to continue browsing.",
        ):
            with self.subTest(page=page[:30]):
                self.assertTrue(is_interstitial(page), page)

    def test_une_vraie_page_d_accueil_est_gardee(self) -> None:
        for page in (
            "Mermaid Chart Products Solutions Pricing Community Open Source Docs "
            "Contact sales You already think in systems. Now you can diagram them.",
            "Mutuelle santé, prévoyance et retraite complémentaire pour les "
            "entreprises et les particuliers depuis 1945.",
        ):
            with self.subTest(page=page[:30]):
                self.assertFalse(is_interstitial(page), page)

    def test_une_page_riche_qui_mentionne_javascript_est_gardee(self) -> None:
        page = (
            "Banque et assurances pour les particuliers, les professionnels et "
            "les entreprises. Consultez vos comptes, effectuez vos virements et "
            "souscrivez en ligne. Pour une meilleure expérience, veuillez "
            "activer JavaScript dans votre navigateur."
        )
        self.assertFalse(is_interstitial(page))


if __name__ == "__main__":
    unittest.main()


class NavigationChromeTests(unittest.TestCase):
    """Un menu de rubriques n'est pas une description de métier."""

    MENU = (
        "Home \\ Anthropic Skip to main content Skip to footer Research Overview Alignment Economics Engineering Frontier Red Team Interpretability Science Societal Impacts Policy Commitments Initiatives Claude's Constitution"
    )

    def test_un_menu_de_navigation_ne_decrit_aucune_activite(self) -> None:
        # L'extraction du 1er septembre 2026 sur anthropic.com : longue, donc
        # le seuil de longueur la laisse passer, et pourtant muette.
        self.assertTrue(is_navigation_chrome(self.MENU))

    def test_une_accroche_ponctuee_reste_lisible(self) -> None:
        self.assertFalse(
            is_navigation_chrome(
                "Mutuelle santé, prévoyance et retraite complémentaire"
            )
        )

    def test_un_site_bavard_ouvert_par_son_menu_reste_lisible(self) -> None:
        # Le lien d'évitement seul n'écarte rien : ce qui suit est une prose.
        self.assertFalse(
            is_navigation_chrome(
                "Skip to main content. Nous installons et maintenons des "
                "réseaux professionnels pour les collectivités, depuis 1998."
            )
        )

    def test_une_liste_d_etiquettes_sans_lien_d_evitement_reste_lisible(self) -> None:
        # L'absence de ponctuation seule n'écarte rien non plus : une accroche
        # courte et vraie n'a pas à porter de virgule.
        self.assertFalse(
            is_navigation_chrome("Wi-Fi à bord et services numériques sur les ferries")
        )

    def test_une_page_vide_ne_decrit_aucune_activite(self) -> None:
        self.assertTrue(is_navigation_chrome("   "))
