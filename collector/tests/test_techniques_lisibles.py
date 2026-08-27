from __future__ import annotations

import re
import unittest
from pathlib import Path

from sentimail_v3.conversation.review_notice import render_notice_html

MIGRATION = (
    Path(__file__).resolve().parents[2]
    / "database" / "init" / "058_techniques_lisibles.sql"
)
SOURCE = MIGRATION.read_text(encoding="utf-8")
# Chaque entrée : ('CODE', 'description', 'conseil')
ENTREES = re.findall(
    r"^\('([A-Z_]+)',\n '((?:[^']|'')*)',\n '((?:[^']|'')*)'\)",
    SOURCE,
    re.M,
)


class SansJargonTests(unittest.TestCase):
    """L'avis part à tout le monde, pas aux gens du courrier électronique.

    « SPF », « DKIM », « Reply-To », « ISO dans ZIP » ne disent rien à qui
    reçoit le message. Nommer une manœuvre dans des mots qu'on ne comprend pas
    revient à ne rien nommer du tout.
    """

    def test_les_vingt_quatre_techniques_sont_reecrites(self) -> None:
        self.assertEqual(len(ENTREES), 24)

    def test_aucun_terme_de_protocole_ne_subsiste(self) -> None:
        interdits = (
            "SPF", "DKIM", "DMARC", "Reply-To", "Unicode", "ISO ", "ZIP",
            "HTML", "macro", "typosquatting", "cyrillique", "URL",
        )
        for code, description, conseil in ENTREES:
            for mot in interdits:
                with self.subTest(technique=code, mot=mot):
                    self.assertNotIn(mot, description)
                    self.assertNotIn(mot, conseil)

    def test_chaque_description_tient_en_une_phrase(self) -> None:
        for code, description, _ in ENTREES:
            with self.subTest(technique=code):
                self.assertLessEqual(description.count("."), 1)
                self.assertLessEqual(len(description), 130)

    def test_chaque_technique_dit_quoi_faire(self) -> None:
        for code, _, conseil in ENTREES:
            with self.subTest(technique=code):
                self.assertTrue(conseil.strip())
                self.assertLessEqual(len(conseil), 130)


class AffichageTests(unittest.TestCase):
    """Le conseil doit arriver jusqu'à l'avis, sinon il n'existe pas."""

    def _rendu(self, technique: dict[str, str]) -> str:
        return render_notice_html({
            "subject": "Objet", "sender": "Un expéditeur <a@b.test>",
            "status_text": "Ce message n’a pas été livré : il attend ta réponse.",
            "concerns": ["Un souci."], "reassurances": [],
            "decision": "Je préfère te demander.",
            "techniques": [technique],
            "action_address": "maia@sentinel.mondomaine.example", "has_preview": False,
        })

    def test_le_conseil_est_affiche(self) -> None:
        rendu = self._rendu({
            "name": "Leurre de suspension de compte",
            "description": "La menace de fermer ton compte sert à te faire cliquer.",
            "advice": "Connecte-toi comme d’habitude.",
        })
        self.assertIn("Connecte-toi comme d’habitude.", rendu)

    def test_le_conseil_suit_la_description(self) -> None:
        rendu = self._rendu({
            "name": "N", "description": "DESCRIPTION", "advice": "CONSEIL",
        })
        self.assertLess(rendu.index("DESCRIPTION"), rendu.index("CONSEIL"))

    def test_une_technique_sans_conseil_ne_laisse_pas_de_fleche_vide(self) -> None:
        rendu = self._rendu({"name": "N", "description": "D", "advice": ""})
        self.assertNotIn("→", rendu)

    def test_le_conseil_est_echappe(self) -> None:
        rendu = self._rendu({
            "name": "N", "description": "D", "advice": "<script>x</script>",
        })
        self.assertNotIn("<script>", rendu)


if __name__ == "__main__":
    unittest.main()
