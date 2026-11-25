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

    def test_display_none_ne_se_leve_pas_chez_un_enfant(self) -> None:
        # Un conteneur retiré du rendu ne rend aucun descendant, quoi que
        # celui-ci redéclare : le masque structurel est sans recours.
        _, hidden = split_visible_hidden(
            '<div style="display:none">'
            '<p style="font-size:16px;visibility:visible">a</p></div>'
        )
        self.assertIn("a", hidden)

    def test_une_taille_lisible_leve_le_font_size_zero_herite(self) -> None:
        # L'idiome MJML : font-size:0 sur la cellule de section pour supprimer
        # l'espace entre colonnes inline-block, taille lisible sur le texte.
        visible, hidden = split_visible_hidden(
            '<td style="font-size:0px;text-align:left">'
            '<div style="font-size:16px">Bonjour</div></td>'
        )
        self.assertIn("Bonjour", visible)
        self.assertEqual(hidden.strip(), "")

    def test_line_height_zero_ne_cache_pas_le_texte(self) -> None:
        # Mailchimp pose line-height:0 sur des paragraphes qui portent le texte :
        # « height:0 » n'est pas « line-height:0 ». 474 messages livrés sur
        # 2 724 (60 jours) voyaient ainsi tout leur texte compté comme caché.
        visible, hidden = split_visible_hidden(
            '<p style="line-height: 0"><span>Bonjour Jean</span></p>'
            '<td style="min-height:0;min-width:0">Facture</td>'
        )
        self.assertIn("Bonjour Jean", visible)
        self.assertIn("Facture", visible)
        self.assertEqual(hidden.strip(), "")

    def test_max_height_zero_reste_cache(self) -> None:
        _, hidden = split_visible_hidden(
            '<div style="max-height:0;overflow:hidden">preheader</div>'
        )
        self.assertIn("preheader", hidden)

    def test_height_zero_reste_cache(self) -> None:
        _, hidden = split_visible_hidden('<div style="height:0px">cache</div>')
        self.assertIn("cache", hidden)

    def test_le_font_size_zero_non_redeclare_reste_cache(self) -> None:
        _, hidden = split_visible_hidden(
            '<td style="font-size:0px"><div>SECRET</div></td>'
        )
        self.assertIn("SECRET", hidden)

    def test_visibility_visible_leve_le_masque_herite(self) -> None:
        visible, _ = split_visible_hidden(
            '<div style="visibility:hidden">'
            '<p style="visibility:visible">Bonjour</p></div>'
        )
        self.assertIn("Bonjour", visible)

    def test_un_gabarit_mjml_complet_est_integralement_visible(self) -> None:
        # Le corps d'une notification réelle, telle que MJML l'imbrique : deux
        # niveaux de font-size:0 avant le texte. Le 1er septembre 2026 cette
        # forme comptait zéro caractère visible et le corps entier en masqué.
        html = (
            '<div style="margin:0px auto;max-width:600px">'
            '<table><tbody><tr>'
            '<td style="direction:ltr;font-size:0px;padding:20px 0;text-align:center">'
            '<div class="mj-column-per-100" '
            'style="font-size:0px;text-align:left;display:inline-block;width:100%">'
            '<table><tbody><tr>'
            '<td style="font-size:0px;padding:10px 25px;word-break:break-word">'
            '<div style="font-family:Arial;font-size:16px;line-height:24px">'
            "Votre accès à l’API Claude est désactivé"
            "</div></td></tr></tbody></table>"
            "</div></td></tr></tbody></table></div>"
        )
        visible, hidden = split_visible_hidden(html)
        self.assertIn("API Claude", visible)
        self.assertEqual(hidden.strip(), "")


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


TERMIUS = (
    "Even terminal gurus spend time searching the web for complex commands. "
    "With IDE-style autocomplete, you can get work done without leaving the "
    "terminal. Enable AI-powered autocomplete in Termius. It works in a local "
    "terminal and SSH sessions and needs no setup or server-side installation. "
    "Search through the global history of your commands. Paste sudo passwords. "
    "Autocomplete commands and their options. Complete filenames and paths."
)


class AlternativeDuplicateTests(unittest.IsolatedAsyncioTestCase):
    """M-96852d (30 octobre 2026) : le texte caché du HTML est répété en clair
    dans la partie text/plain. Le destinataire lit le HTML, où il ne voit que
    « 616 » et un lien : le texte du text/plain n'est pas du texte visible."""

    @staticmethod
    def _message(plain: str, html: str, subject: str = "Renouvellement Carte") -> bytes:
        return (
            "From: a@b.c\r\nTo: me@mondomaine.example\r\n"
            f"Subject: {subject}\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/alternative; boundary="b1"\r\n\r\n'
            "--b1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
            f"{plain}\r\n"
            "--b1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
            f"{html}\r\n--b1--\r\n"
        ).encode()

    async def _codes(self, plain: str, html: str):
        from sentimail_v3.observation.dossier.hooks.content import ContentHook
        from sentimail_v3.observation.dossier.models import InvestigationContext
        from sentimail_v3.observation.parser import parse_message

        raw = self._message(plain, html)
        ctx = InvestigationContext(raw, parse_message(raw), "a@b.c", ["me@mondomaine.example"])
        clues, _ = await ContentHook().observe(ctx)
        return {c.clue_code: c for c in clues}

    async def test_le_texte_cache_repete_dans_le_texte_brut_declenche(self) -> None:
        html = (
            "<p>616</p>"
            f'<span style="display:none"><p>{TERMIUS}</p></span>'
            '<p><a href="https://x.example/a">CONSULTER</a></p>'
        )
        codes = await self._codes(TERMIUS, html)
        self.assertIn("CONTENT_HIDDEN_TEXT_SALTING", codes)

    async def test_le_gabarit_responsive_dont_le_visible_repete_le_cache_ne_declenche_pas(
        self,
    ) -> None:
        visible = "Bonjour, voici le d\u00e9tail de votre commande num\u00e9ro 123-4567890. " * 5
        html = f'<div style="display:none">{visible}</div><p>{visible}</p>'
        codes = await self._codes(visible, html)
        self.assertNotIn("CONTENT_HIDDEN_TEXT_SALTING", codes)

    async def test_un_texte_brut_fidele_a_un_html_sans_cache_ne_declenche_pas(self) -> None:
        corps = "Bonjour, voici votre facture du mois. " * 10
        codes = await self._codes(corps, f"<p>{corps}</p>")
        self.assertNotIn("CONTENT_HIDDEN_TEXT_SALTING", codes)


if __name__ == "__main__":
    unittest.main()
