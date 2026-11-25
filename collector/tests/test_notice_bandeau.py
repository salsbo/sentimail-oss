from __future__ import annotations

import unittest

from sentimail_v3.conversation.review_notice import render_notice_html

BASE = {
    "subject": "Facture N°54847120",
    "sender": "compta@exemple.fr",
    "status_text": "L’email ci-dessous n’a pas été livré.",
    "concerns": ["Le domaine ne correspond pas."],
    "badge": {
        "word": "DOUTEUX",
        "detail": "1 écart relevé",
        "color": "#b45309",
        "cid": "sm-indice-doubt",
    },
    "action_address": "maia@sentinel.mondomaine.example",
}


class SansBandeauTests(unittest.TestCase):
    """La fiche utile remplace entièrement l'ancien bandeau."""

    def test_le_statut_et_l_ancien_expediteur_disparaissent(self) -> None:
        html = render_notice_html(dict(BASE))
        for absent in (BASE["status_text"], BASE["sender"]):
            self.assertNotIn(absent, html)

    def test_le_sujet_revient_dans_les_informations(self) -> None:
        """L'objet reste en tête des métadonnées pour reconnaître le message."""
        html = render_notice_html(dict(BASE))
        self.assertIn(BASE["subject"], html)
        self.assertLess(html.index("Objet"), html.index(BASE["subject"]))

    def test_l_indice_est_le_premier_bloc_visible(self) -> None:
        html = render_notice_html(dict(BASE))
        self.assertLess(
            html.index("ACTION REQUISE · MESSAGE RETENU"), html.index("Objet")
        )
        self.assertLess(html.index("DOUTEUX"), html.index("Pourquoi j&#x27;hésite"))

    def test_un_ancien_statut_livre_ne_change_plus_la_presentation(self) -> None:
        retenu = render_notice_html(dict(BASE))
        livre = render_notice_html(
            {**BASE, "status_text": "Ce message t’a été livré."}
        )
        self.assertEqual(retenu, livre)


if __name__ == "__main__":
    unittest.main()
