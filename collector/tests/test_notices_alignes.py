from __future__ import annotations

import re
import unittest

from sentimail_v3.conversation.junk_notice import render_junk_html
from sentimail_v3.conversation.review_notice import (
    PREVIEW_CID,
    capture_block,
    render_notice_html,
)

RETENU = {
    "subject": "Votre facture est disponible",
    "sender": "Espace Client <facturation@exemple.test>",
    "status_text": "Ce message n’a pas été livré : il attend ta réponse.",
    "concerns": ["Le domaine ne correspond pas à la marque annoncée."],
    "reassurances": ["L’expéditeur est authentifié."],
    "decision": "Je préfère te demander.",
    "action_address": "maia@sentinel.mondomaine.example",
    "has_preview": True,
}
CLASSE = {
    "subject": "Incroyable offre",
    "sender": "Promo <promo@exemple.test>",
    "verdict": "spam",
    "reasons": ["Aucune authentification."],
    "lessons": [],
    "action_address": "maia@sentinel.mondomaine.example",
    "has_preview": True,
}


class MemeModeleTests(unittest.TestCase):
    """Les deux avis doivent se lire de la même façon.

    Un message retenu et un message classé posent la même question à la même
    personne. Deux mises en page différentes obligent à réapprendre où
    regarder, alors que seule la décision change.
    """

    def test_les_deux_montrent_la_capture_dans_le_corps(self) -> None:
        for rendu, nom in ((render_notice_html(dict(RETENU)), "retenu"),
                           (render_junk_html(dict(CLASSE)), "classé")):
            with self.subTest(avis=nom):
                self.assertIn(f'src="cid:{PREVIEW_CID}"', rendu)

    def test_le_bloc_de_capture_est_le_meme(self) -> None:
        # Un seul endroit le dessine : deux copies divergeraient.
        motif = re.compile(
            r'<div style="[^"]*"><img src="cid:[^"]+"[^>]*/>'
            r'<div style="[^"]*">[^<]*</div></div>'
        )
        retenu = motif.search(render_notice_html(dict(RETENU)))
        classe = motif.search(render_junk_html(dict(CLASSE)))
        self.assertIsNotNone(retenu)
        self.assertIsNotNone(classe)
        self.assertEqual(retenu.group(0), classe.group(0))

    def test_aucun_des_deux_ne_parle_de_piece_jointe(self) -> None:
        for rendu, nom in ((render_notice_html(dict(RETENU)), "retenu"),
                           (render_junk_html(dict(CLASSE)), "classé")):
            with self.subTest(avis=nom):
                self.assertNotIn("pièce jointe", rendu)


class PlaceDeLaCaptureTests(unittest.TestCase):
    """La photo vient après l'en-tête et avant l'explication."""

    def test_dans_l_avis_retenu_elle_precede_les_colonnes(self) -> None:
        rendu = render_notice_html(dict(RETENU))
        self.assertLess(rendu.index("cid:"), rendu.index("Ce qui me gêne"))

    def test_dans_l_avis_classe_elle_precede_la_raison(self) -> None:
        rendu = render_junk_html(dict(CLASSE))
        self.assertLess(rendu.index("cid:"), rendu.index("Pourquoi je l’ai classé"))

    def test_dans_l_avis_classe_elle_suit_l_expediteur(self) -> None:
        rendu = render_junk_html(dict(CLASSE))
        self.assertLess(rendu.index("Promo"), rendu.index("cid:"))


class MiniatureTests(unittest.TestCase):
    """Une miniature, pas une pleine page."""

    def test_la_capture_occupe_la_moitie_de_la_largeur(self) -> None:
        self.assertIn("width:50%", capture_block(True))

    def test_la_capture_est_cerclee_de_rouge(self) -> None:
        # Sans cadre, la miniature se lit comme une illustration de l'avis.
        # Entourée, elle se lit comme ce dont l'avis parle.
        bloc = capture_block(True)
        self.assertIn("border:2px solid #dc2626", bloc)

    def test_le_cadre_est_legende(self) -> None:
        self.assertIn("Le message dont je te parle", capture_block(True))

    def test_sans_capture_aucun_bloc_n_est_produit(self) -> None:
        self.assertEqual(capture_block(False), "")

    def test_sans_capture_l_avis_classe_le_dit(self) -> None:
        rendu = render_junk_html(dict(CLASSE, has_preview=False))
        self.assertNotIn("cid:", rendu)
        self.assertIn("photographier", rendu)


if __name__ == "__main__":
    unittest.main()
