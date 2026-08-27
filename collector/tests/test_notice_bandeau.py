from __future__ import annotations

import re
import unittest

from sentimail_v3.conversation.review_notice import render_notice_html

BASE = {
    "subject": "Facture N°54847120",
    "sender": "compta@exemple.fr",
    "concerns": ["Le domaine ne correspond pas."],
    "reassurances": [],
    "decision": "Je préfère te demander.",
    "action_address": "maia@sentinel.mondomaine.example",
}


class BandeauTests(unittest.TestCase):
    """Le bandeau dit ce qui s'est passé et ce qu'on attend de toi.

    « Il attend ta réponse » laissait croire que le message répondrait de
    lui-même. Ce qu'on attend est une directive, et c'est la première ligne
    lue : elle doit être la plus grosse.
    """

    def _html(self, statut: str) -> str:
        return render_notice_html({**BASE, "status_text": statut})

    def test_le_statut_de_retenue_est_le_nouveau_texte(self) -> None:
        from sentimail_v3.conversation.conversation import HOLD_STATUS_TEXT

        self.assertIn("n’a pas été livré", HOLD_STATUS_TEXT)
        self.assertIn("directives", HOLD_STATUS_TEXT)
        self.assertNotIn("il attend ta réponse", HOLD_STATUS_TEXT)

    def test_le_bandeau_est_plus_gros_que_le_reste(self) -> None:
        from sentimail_v3.conversation.conversation import HOLD_STATUS_TEXT

        html = self._html(HOLD_STATUS_TEXT)
        bloc = re.search(r'<div style="background:#[0-9a-f]{6};color:#ffffff;[^"]*"', html)
        self.assertIsNotNone(bloc, "bandeau introuvable")
        taille = re.search(r"font-size:(\d+)px", bloc.group(0))
        self.assertIsNotNone(taille, "aucune taille sur le bandeau")
        self.assertGreaterEqual(int(taille.group(1)), 18)

    def test_la_couleur_d_alerte_suit_le_nouveau_texte(self) -> None:
        # Le bandeau change de couleur selon que le message est retenu ou non :
        # la détection se fait sur le texte, elle doit suivre sa reformulation.
        from sentimail_v3.conversation.conversation import HOLD_STATUS_TEXT

        retenu = self._html(HOLD_STATUS_TEXT)
        livre = self._html("Ce message t’a été livré ; ta réponse me sert à mieux faire.")
        self.assertIn("#b45309", retenu)
        self.assertIn("#15803d", livre)


if __name__ == "__main__":
    unittest.main()
