from __future__ import annotations

import unittest

from sentimail_v3.conversation.junk_notice import render_junk_html
from sentimail_v3.conversation.review_notice import (
    PREVIEW_CID,
    render_notice_html,
)

RETENU = {
    "subject": "Votre facture est disponible",
    "sender": "Espace Client <facturation@exemple.test>",
    "status_text": "Ce message n’a pas été livré : il attend ta réponse.",
    "concerns": ["Le domaine ne correspond pas à la marque annoncée."],
    "badge": {
        "level": "danger", "word": "DANGEREUX", "color": "#b91c1c",
        "detail": "1 écart relevé", "cid": "sm-indice-danger",
    },
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


class DeuxUsagesTests(unittest.TestCase):
    """Les deux avis montrent la même photo, au même endroit du récit."""

    def test_les_deux_avis_montrent_la_capture(self) -> None:
        retenu = render_notice_html(dict(RETENU))
        classe = render_junk_html(dict(CLASSE))
        self.assertIn(f'src="cid:{PREVIEW_CID}"', retenu)
        self.assertIn(f'src="cid:{PREVIEW_CID}"', classe)

    def test_l_avis_classe_tient_a_l_identite_l_objet_et_la_raison(self) -> None:
        classe = render_junk_html(dict(CLASSE))
        self.assertIn(">De<", classe)
        self.assertIn(">Objet<", classe)
        self.assertIn(">Motifs</div>", classe)

    def test_sans_capture_pleine_aucun_avis_ne_parle_de_piece_jointe(self) -> None:
        self.assertNotIn("pièce jointe", render_notice_html(dict(RETENU)))
        self.assertNotIn("pièce jointe", render_junk_html(dict(CLASSE)))


class OrdreDesBlocsTests(unittest.TestCase):
    """L'état en tête, puis les métadonnées, les motifs, la photo et les boutons."""

    def test_dans_l_avis_retenu_l_indice_precede_les_ecarts(self) -> None:
        rendu = render_notice_html(dict(RETENU))
        self.assertLess(rendu.index("DANGEREUX"), rendu.index("Pourquoi j&#x27;hésite"))

    def test_dans_l_avis_retenu_la_photo_precede_les_ecarts(self) -> None:
        rendu = render_notice_html(dict(RETENU))
        self.assertLess(rendu.index("Pourquoi j&#x27;hésite"), rendu.index(PREVIEW_CID))
        self.assertLess(rendu.index(PREVIEW_CID), rendu.index('data-choice="A"'))

    def test_dans_l_avis_retenu_le_sujet_est_dans_les_informations(self) -> None:
        rendu = render_notice_html(dict(RETENU))
        self.assertIn(str(RETENU["subject"]), rendu)

    def test_dans_l_avis_classe_la_photo_precede_la_raison(self) -> None:
        rendu = render_junk_html(dict(CLASSE))
        self.assertLess(rendu.index(">Motifs</div>"), rendu.index(PREVIEW_CID))
        self.assertLess(rendu.index(PREVIEW_CID), rendu.index('data-choice="A"'))

    def test_dans_l_avis_classe_l_expediteur_precede_la_raison(self) -> None:
        rendu = render_junk_html(dict(CLASSE))
        self.assertLess(rendu.index("Promo"), rendu.index(">Motifs</div>"))


class AbsenceDeCaptureTests(unittest.TestCase):
    """Un rendu impossible ne laisse jamais d'image cassée."""

    def test_l_avis_classe_sans_capture_n_en_parle_pas(self) -> None:
        rendu = render_junk_html(dict(CLASSE, has_preview=False))
        self.assertNotIn("cid:", rendu)
        self.assertNotIn("photographier", rendu)

    def test_l_avis_retenu_sans_capture_n_en_parle_pas(self) -> None:
        rendu = render_notice_html(dict(RETENU, has_preview=False))
        self.assertNotIn(PREVIEW_CID, rendu)
        self.assertNotIn("Le message dont je te parle", rendu)


if __name__ == "__main__":
    unittest.main()
