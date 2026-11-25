"""Le texte quasi blanc sur fond quasi blanc est masqué, le blanc sur bouton non.

Le blanc sur blanc est le masquage le plus ancien : une couleur de texte égale
au fond rend le texte illisible sans le retirer du HTML. On le range avec les
autres masques, sans prendre pour caché le texte blanc légitime posé sur un
bouton ou une bannière colorée.
"""

from __future__ import annotations

import unittest

from sentimail_v3.observation.dossier.hooks.hidden_text import split_visible_hidden


class BlancSurBlancTests(unittest.TestCase):
    def test_texte_blanc_sur_fond_par_defaut(self) -> None:
        _, hidden = split_visible_hidden(
            '<p>Offre</p><div style="color:#ffffff">TEXTE CACHE</div>'
        )
        self.assertIn("TEXTE CACHE", hidden)

    def test_blanc_court_trois_chiffres(self) -> None:
        _, hidden = split_visible_hidden('<span style="color:#fff">secret</span>')
        self.assertIn("secret", hidden)

    def test_blanc_nomme(self) -> None:
        _, hidden = split_visible_hidden('<span style="color:white">secret</span>')
        self.assertIn("secret", hidden)

    def test_gris_tres_clair_de_preheader(self) -> None:
        _, hidden = split_visible_hidden(
            '<span style="color:#f4f4f4">preheader invisible</span>'
        )
        self.assertIn("preheader", hidden)

    def test_blanc_sur_blanc_declare(self) -> None:
        _, hidden = split_visible_hidden(
            '<div style="background:#ffffff;color:#fff">x caché</div>'
        )
        self.assertIn("x", hidden)

    def test_blanc_sur_bouton_colore_reste_visible(self) -> None:
        visible, hidden = split_visible_hidden(
            '<td style="background:#e03e2d">'
            '<a style="color:#ffffff">Voir mon compte</a></td>'
        )
        self.assertIn("Voir", visible)
        self.assertNotIn("Voir", hidden)

    def test_blanc_sur_image_de_fond_reste_visible(self) -> None:
        visible, _ = split_visible_hidden(
            '<div style="background:url(banner.png);color:#fff">Bienvenue</div>'
        )
        self.assertIn("Bienvenue", visible)

    def test_texte_sombre_sur_blanc_reste_visible(self) -> None:
        visible, hidden = split_visible_hidden(
            '<div style="background:#ffffff;color:#111">Bonjour</div>'
        )
        self.assertIn("Bonjour", visible)
        self.assertEqual(hidden.strip(), "")

    def test_gris_moyen_lisible_reste_visible(self) -> None:
        visible, _ = split_visible_hidden('<span style="color:#777777">gris</span>')
        self.assertIn("gris", visible)

    def test_fond_colore_herite_protege_l_enfant(self) -> None:
        # Le fond coloré posé par un ancêtre vaut pour le texte blanc en dessous.
        visible, hidden = split_visible_hidden(
            '<table style="background:#1a1a2e">'
            '<tr><td><span style="color:#ffffff">Newsletter</span></td></tr></table>'
        )
        self.assertIn("Newsletter", visible)
        self.assertNotIn("Newsletter", hidden)


if __name__ == "__main__":
    unittest.main()
