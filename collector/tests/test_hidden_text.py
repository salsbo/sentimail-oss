"""Le texte masqué par CSS ne se voit pas, mais empoisonne l'analyse.

Le « salting » injecte dans le HTML du texte rendu invisible - mots bénins
pour diluer les termes suspects, ou instructions adressées à un filtre IA -
sous font-size:0, display:none, couleur = fond, hors écran. Il doit être
séparé du texte visible : la marque, la langue et l'urgence se jugent sur ce
que le destinataire voit, et le volume caché est en soi un indice adverse.
"""

from __future__ import annotations

import unittest

from sentimail_v3.observation.dossier.hooks.hidden_text import (
    split_visible_hidden,
)


class SeparationTests(unittest.TestCase):
    def test_le_texte_ordinaire_est_visible(self) -> None:
        visible, hidden = split_visible_hidden(
            "<p>Bonjour, voici votre facture.</p>"
        )
        self.assertIn("facture", visible)
        self.assertEqual(hidden.strip(), "")

    def test_display_none_est_cache(self) -> None:
        visible, hidden = split_visible_hidden(
            '<p>Visible</p><div style="display:none">SECRET</div>'
        )
        self.assertIn("Visible", visible)
        self.assertIn("SECRET", hidden)
        self.assertNotIn("SECRET", visible)

    def test_font_size_zero_est_cache(self) -> None:
        _, hidden = split_visible_hidden('<span style="font-size:0px">x</span>')
        self.assertIn("x", hidden)

    def test_opacite_nulle_est_cachee(self) -> None:
        _, hidden = split_visible_hidden('<span style="opacity:0">y</span>')
        self.assertIn("y", hidden)

    def test_hors_ecran_est_cache(self) -> None:
        _, hidden = split_visible_hidden(
            '<span style="position:absolute;left:-9999px">z</span>'
        )
        self.assertIn("z", hidden)

    def test_l_heritage_du_masque_couvre_les_enfants(self) -> None:
        _, hidden = split_visible_hidden(
            '<div style="display:none"><p>a</p><b>b</b></div>'
        )
        self.assertIn("a", hidden)
        self.assertIn("b", hidden)


class ClueTests(unittest.IsolatedAsyncioTestCase):
    async def _codes(self, html: str):
        from sentimail_v3.observation.dossier.hooks.content import ContentHook
        from sentimail_v3.observation.dossier.models import InvestigationContext
        from sentimail_v3.observation.parser import parse_message

        raw = (
            "From: a@b.c\r\nTo: me@mondomaine.example\r\nSubject: x\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n" + html + "\r\n"
        ).encode()
        ctx = InvestigationContext(raw, parse_message(raw), "a@b.c", ["me@mondomaine.example"])
        clues, _ = await ContentHook().observe(ctx)
        return {c.clue_code: c for c in clues}

    async def test_un_bloc_cache_volumineux_est_signale(self) -> None:
        html = (
            "<p>Bonjour</p>"
            '<div style="display:none">'
            + ("mot bénin caché pour diluer les filtres " * 20)
            + "</div>"
        )
        codes = await self._codes(html)
        self.assertIn("CONTENT_HIDDEN_TEXT_SALTING", codes)
        self.assertEqual(codes["CONTENT_HIDDEN_TEXT_SALTING"].direction, "adverse")

    async def test_un_preheader_court_ne_declenche_pas(self) -> None:
        # Le texte d'aperçu légitime est masqué mais court et unique.
        html = (
            '<div style="display:none">Votre reçu du jour</div>'
            "<p>" + ("Bonjour, voici le détail de votre commande. " * 20) + "</p>"
        )
        codes = await self._codes(html)
        self.assertNotIn("CONTENT_HIDDEN_TEXT_SALTING", codes)

    async def test_le_texte_cache_duplique_du_gabarit_responsive_ne_declenche_pas(
        self,
    ) -> None:
        # Un gabarit responsive (Amazon & co) cache la variante mobile ou le
        # repli mso : ce bloc caché répète le texte visible, ce n'est pas du
        # salting.
        visible = "Bonjour, voici le détail de votre commande numéro 123-4567890. " * 5
        html = (
            f'<div style="display:none">{visible}</div>'
            f"<p>{visible}</p>"
        )
        codes = await self._codes(html)
        self.assertNotIn("CONTENT_HIDDEN_TEXT_SALTING", codes)

    async def test_le_vocabulaire_cache_inedit_declenche_toujours(self) -> None:
        # Du texte caché qui introduit un vocabulaire absent du visible reste
        # du salting, gabarit responsive ou non.
        html = (
            "<p>Bonjour, voici le détail de votre commande.</p>"
            '<div style="display:none">'
            + ("mot bénin caché pour diluer les filtres adverses suspects " * 20)
            + "</div>"
        )
        codes = await self._codes(html)
        self.assertIn("CONTENT_HIDDEN_TEXT_SALTING", codes)

    async def test_du_vocabulaire_inedit_suffisant_declenche_meme_dilue_de_duplique(
        self,
    ) -> None:
        # Le bloc caché mélange du texte dupliqué (gabarit) et un volume
        # inédit suffisant : le signal doit rester porté par la part inédite.
        visible = "Bonjour, voici le détail de votre commande numéro 123-4567890. " * 3
        novel = "cliquez ici pour confirmer votre mot de passe immédiatement faute de quoi le compte sera suspendu " * 5
        html = f'<div style="display:none">{visible}{novel}</div><p>{visible}</p>'
        codes = await self._codes(html)
        self.assertIn("CONTENT_HIDDEN_TEXT_SALTING", codes)


if __name__ == "__main__":
    unittest.main()
