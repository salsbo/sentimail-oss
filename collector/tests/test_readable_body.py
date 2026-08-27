from __future__ import annotations

import unittest

from sentimail_v3.conversation.conversation import readable_body, strip_quoted_reply


class LectureTests(unittest.TestCase):
    def test_une_reponse_en_texte_est_lue_telle_quelle(self) -> None:
        self.assertEqual(readable_body("A", None), "A")

    def test_une_reponse_html_seule_reste_lisible(self) -> None:
        # Outlook et la plupart des clients mobiles n'envoient que du HTML :
        # sans cette lecture, la directive arrivait vide.
        html = (
            '<html><head><style>p{color:red}</style></head><body>'
            '<p>A</p><div>Merci</div></body></html>'
        )
        lu = readable_body(None, html)
        self.assertIn("A", lu)
        self.assertIn("Merci", lu)
        self.assertNotIn("color:red", lu)

    def test_le_texte_prime_sur_le_html_quand_les_deux_existent(self) -> None:
        self.assertEqual(readable_body("B", "<p>autre chose</p>"), "B")

    def test_un_message_sans_corps_reste_vide(self) -> None:
        self.assertEqual(readable_body(None, None), "")
        self.assertEqual(readable_body("   ", ""), "")

    def test_une_reponse_html_avec_citation_garde_la_directive(self) -> None:
        html = (
            "<body><div>A</div><div>De : MAIA</div>"
            "<blockquote>Ton avis sur : recu</blockquote></body>"
        )
        directive = strip_quoted_reply(readable_body(None, html))
        self.assertTrue(directive.startswith("A"))


if __name__ == "__main__":
    unittest.main()
