from __future__ import annotations

import unittest

from sentimail_v3.observation.risk_text import (
    message_text_excerpts,
    neutralize_excerpt_links,
    risky_text_excerpts,
)


class RiskTextTests(unittest.TestCase):
    def test_extracts_exact_risky_sentences(self) -> None:
        excerpts = risky_text_excerpts(
            "Action urgente",
            "Bonjour. Votre compte est suspendu. Cliquez pour vérifier votre mot de passe.",
        )
        self.assertTrue(any("suspendu" in value for value in excerpts))
        self.assertTrue(any("mot de passe" in value for value in excerpts))

    def test_does_not_mark_ordinary_text(self) -> None:
        self.assertEqual(
            risky_text_excerpts("Compte rendu", "Bonjour, voici le document demandé."),
            [],
        )

    def test_le_doute_garde_aussi_un_contexte_sans_mot_de_risque(self) -> None:
        self.assertEqual(
            [
                "Nous redescendons de notre nuage et vous remercions pour "
                "votre présence.",
                "Les photos sont disponibles pendant sept jours.",
            ],
            message_text_excerpts(
                "Bonjour à tous. Nous redescendons de notre nuage et vous "
                "remercions pour votre présence. Les photos sont disponibles "
                "pendant sept jours.",
                limit=2,
            ),
        )

    def test_les_passages_a_risque_restent_prioritaires(self) -> None:
        excerpts = message_text_excerpts(
            "Présentation ordinaire suffisamment longue. "
            "Votre compte est suspendu. Cliquez pour vérifier votre mot de passe.",
            limit=2,
        )
        self.assertTrue(any("suspendu" in value for value in excerpts))
        self.assertTrue(any("mot de passe" in value for value in excerpts))

    def test_les_liens_restent_lisibles_mais_ne_sont_plus_auto_cliquables(self) -> None:
        inert = neutralize_excerpt_links(
            "Voir https://danger.example/payer, danger.example ou "
            "fraudeur@danger.example"
        )
        self.assertNotIn("https://danger.example", inert)
        self.assertNotIn(" danger.example", inert)
        self.assertNotIn("fraudeur@danger.example", inert)
        self.assertEqual(
            inert.replace("\u200b", ""),
            "Voir https://danger.example/payer, danger.example ou "
            "fraudeur@danger.example",
        )

    def test_le_remplissage_invisible_du_preentete_disparait(self) -> None:
        texte = (
            "Ce code expirera dans 3 heures. "
            + "\u200c \u200c " * 15
            + "  Vous vérifiez votre identité depuis un nouvel appareil."
        )
        for extrait in message_text_excerpts(texte):
            self.assertNotIn("\u200c", extrait)
        self.assertIn(
            "Vous vérifiez votre identité depuis un nouvel appareil.",
            message_text_excerpts(texte),
        )

    def test_une_adresse_ip_ne_coupe_pas_la_phrase(self) -> None:
        extraits = risky_text_excerpts(
            "", "Vous vérifiez votre identité depuis l'adresse IP 203.0.113.5 (FR)"
        )
        self.assertEqual(
            ["Vous vérifiez votre identité depuis l'adresse IP 203.0.113.5 (FR)"],
            extraits,
        )

    def test_une_url_devient_un_simple_marqueur_de_lien(self) -> None:
        extraits = message_text_excerpts(
            "Vérifier cet appareil [https://universal.exemple.test/login?token=1] "
            "Cet e-mail vous a été envoyé depuis un appareil inconnu."
        )
        self.assertEqual(
            [
                (
                    "Vérifier cet appareil [lien] Cet e-mail vous a été envoyé "
                    "depuis un appareil inconnu."
                )
            ],
            extraits,
        )

    def test_une_ligne_faite_de_liens_n_est_pas_un_extrait(self) -> None:
        self.assertEqual(
            [],
            message_text_excerpts(
                "[https://www.exemple.test/a] [https://x.exemple.test/b] "
                "[https://y.exemple.test/c]"
            ),
        )


if __name__ == "__main__":
    unittest.main()
