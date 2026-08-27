"""La page des sources hostiles se rend sans données comme avec."""

from __future__ import annotations

import unittest

from sentimail_admin import pages


class PageSourcesTests(unittest.TestCase):
    def test_le_registre_vide_se_rend(self) -> None:
        html = pages.page_sources([], 0)
        self.assertIn('name="q"', html)
        self.assertIn("Aucune source au registre", html)
        self.assertIn("/sources/ajouter", html)

    def test_une_entree_s_affiche_avec_son_retrait(self) -> None:
        html = pages.page_sources(
            [
                {
                    "ip": "93.184.216.99/32",
                    "hits": 13,
                    "first_seen": "2026-08-20",
                    "last_seen": "2026-08-20 21:00:00+00",
                    "last_reason": "backfill_spam",
                    "rdns": "mail.badhost.example",
                    "etat": "bloquee",
                }
            ],
            1,
        )
        self.assertIn("93.184.216.99/32", html)
        self.assertIn("mail.badhost.example", html)
        self.assertIn("/sources/supprimer", html)
        self.assertIn("refusée par le MX", html)

    def test_une_source_sous_le_seuil_est_surveillee(self) -> None:
        html = pages.page_sources(
            [
                {
                    "ip": "93.184.216.8/32",
                    "hits": 3,
                    "first_seen": "2026-08-20",
                    "last_seen": "2026-08-20 21:00:00+00",
                    "last_reason": "verdict_spam",
                    "rdns": None,
                    "etat": "surveillee",
                }
            ],
            0,
        )
        self.assertIn("surveillée", html)
        self.assertNotIn("refusée par le MX</span>", html.split("chapeau")[-1].split("</p>")[1] if "chapeau" in html else html)

    def test_le_motif_se_lit_en_francais(self) -> None:
        # Le moteur écrit « origine_qualification » pour lui-même : sur la
        # page, ce code n'apprenait rien à qui la lit.
        self.assertEqual(
            pages.motif_source("backfill_spam"), "Indésirable - reprise d'historique"
        )
        self.assertEqual(
            pages.motif_source("user_feedback_spam"), "Indésirable - ta qualification"
        )
        self.assertEqual(
            pages.motif_source("verdict_malicious"), "Malveillant - verdict du moteur"
        )
        self.assertEqual(pages.motif_source("manual_admin"), "Ajout manuel")

    def test_un_motif_inconnu_reste_lisible_tel_quel(self) -> None:
        # Un motif introduit plus tard doit se voir, pas disparaître derrière
        # un « autre » qui ferait croire à un registre exhaustif.
        self.assertEqual(pages.motif_source("nouveau_motif"), "nouveau_motif")
        self.assertEqual(pages.motif_source(None), "-")

    def test_l_adresse_ne_se_coupe_pas_en_morceaux(self) -> None:
        # « 93.184.216.99/32 » réparti sur trois lignes n'est plus une adresse.
        html = pages.page_sources(
            [
                {
                    "ip": "93.184.216.99/32",
                    "rdns": None,
                    "last_reason": "verdict_spam",
                    "hits": 12,
                    "last_seen": "2026-08-22 13:45:00+00",
                    "etat": "bloquee",
                }
            ],
            1,
        )
        self.assertIn('<code class="insecable">93.184.216.99/32</code>', html)
        self.assertIn("Indésirable - verdict du moteur", html)
        self.assertNotIn("verdict_spam", html)

    def test_l_onglet_existe_dans_la_navigation(self) -> None:
        self.assertIn(("/sources", "Sources hostiles"), pages.ONGLETS)


if __name__ == "__main__":
    unittest.main()
