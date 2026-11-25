"""Le texte qu'on juge est celui que le destinataire lit.

Le 16 septembre 2026, un faux reçu « Prime » en HTML seul a été livré à
0,95 : `body_text` était NULL, le juge et les enquêteurs profonds ont reçu un
corps vide, et le hook contenu était le seul à avoir lu le HTML. Trois lecteurs
du même message ne doivent pas lire trois textes différents.
"""

from __future__ import annotations

import unittest

from sentimail_v3.observation.dossier.hooks.visible_text import readable_text


class ReadableTextTests(unittest.TestCase):
    def test_le_texte_brut_est_prefere_quand_il_existe(self) -> None:
        texte, source = readable_text("Bonjour Jean", "<p>Autre chose</p>")
        self.assertEqual(texte, "Bonjour Jean")
        self.assertEqual(source, "text/plain")

    def test_un_mail_html_seul_rend_son_texte_visible(self) -> None:
        html = (
            "<html><head><style>p{color:red}</style></head><body>"
            "<p>Votre paiement a été accepté</p><p>Montant 69,90 €</p>"
            "</body></html>"
        )
        texte, source = readable_text(None, html)
        self.assertIn("Votre paiement a été accepté", texte)
        self.assertIn("69,90", texte)
        self.assertNotIn("color", texte)
        self.assertEqual(source, "html_visible_text")

    def test_un_texte_brut_vide_compte_comme_absent(self) -> None:
        texte, source = readable_text("   \n", "<p>Corps</p>")
        self.assertEqual(texte, "Corps")
        self.assertEqual(source, "html_visible_text")

    def test_sans_aucun_corps_rien_n_est_invente(self) -> None:
        self.assertEqual(readable_text(None, None), ("", "none"))
        self.assertEqual(readable_text("", ""), ("", "none"))


    def test_le_texte_brut_qui_repete_le_cache_du_html_cede_au_html_rendu(self) -> None:
        # M-96852d : le text/plain répète un texte que le HTML cache. Le
        # destinataire lit « 616 » et un lien ; le juge doit lire la même chose.
        cache = "Even terminal gurus spend time searching the web for complex commands. " * 6
        html = (
            "<p>616</p>"
            f'<span style="display:none"><p>{cache}</p></span>'
            '<p><a href="https://x.example/a">CONSULTER</a></p>'
        )
        texte, source = readable_text(cache, html)
        self.assertIn("616", texte)
        self.assertIn("CONSULTER", texte)
        self.assertNotIn("terminal gurus", texte)
        self.assertEqual(source, "html_visible_text")

    def test_un_html_dont_le_cache_repete_le_visible_garde_le_texte_brut(self) -> None:
        visible = "Bonjour, voici le d\u00e9tail de votre commande. " * 8
        html = f'<div style="display:none">{visible}</div><p>{visible}</p>'
        texte, source = readable_text(visible, html)
        self.assertEqual(source, "text/plain")
        self.assertIn("d\u00e9tail de votre commande", texte)


if __name__ == "__main__":
    unittest.main()
