"""La représentation conservée est celle du lecteur déjà utilisé par le juge."""

import unittest

from sentimail_v3.observation.visible_content import build_visible_content, VISIBLE_CONTENT_VERSION
from sentimail_v3.observation.dossier.hooks.visible_text import readable_text


class VueVisibleTests(unittest.TestCase):
    def test_la_vue_persistable_conserve_texte_source_et_version(self):
        for plain, html in (("Bonjour", "<p>Bonjour</p>"),
                            (None, "<p>Message HTML</p>"),
                            ("Bruit répété "*40, '<p>616 Consulter</p><div style="display:none">' + "Bruit répété "*40 + '</div>')):
            with self.subTest(plain=plain):
                text, source = readable_text(plain, html)
                self.assertEqual(build_visible_content(plain, html), {
                    "version": VISIBLE_CONTENT_VERSION, "text": text,
                    "source": source, "truncated": False,
                })

    def test_une_vue_bornee_ne_pretend_pas_etre_complete(self):
        view = build_visible_content("a"*20001, None)
        self.assertEqual(len(view["text"]), 20000)
        self.assertTrue(view["truncated"])
