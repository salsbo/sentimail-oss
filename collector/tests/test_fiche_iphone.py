"""La fiche d'avis du 25 septembre 2026 : deux colonnes sur un ordinateur,
une seule sur un iPhone, et l'heure de réception à l'heure de Paris."""

from __future__ import annotations

import re
import unittest
from datetime import datetime, timezone

from sentimail_v3.conversation.review_notice import render_notice_html

CONTEXTE = {
    "concerns": ["Contenu sans rapport avec l’activité publiée."],
    "badge": {
        "level": "doute",
        "word": "DOUTEUX",
        "color": "#b45309",
        "detail": "1 écart relevé",
        "cid": "sm-indice-doute",
    },
    "sender_lines": [
        "Nom affiché : lnfosPRlME",
        "Adresse affichée : noreply@a2ztelehealth.com",
        "Adresse d’enveloppe différente : bounces@em.a2ztelehealth.com",
    ],
    "subject": "prime video Notification",
    "received_at": datetime(2026, 9, 25, 6, 45, 53, tzinfo=timezone.utc),
    "action_address": "maia@sentinel.exemple.test",
    "reference": "M-8d026c",
    "has_preview": True,
}


class IphoneTests(unittest.TestCase):
    def test_la_feuille_iphone_empile_colonnes_et_reponses(self) -> None:
        """En V2, une seule colonne 560 px évite tout besoin de media queries."""
        html = render_notice_html(dict(CONTEXTE))
        self.assertNotIn("<table", html)
        self.assertIn("max-width:560px", html)

    def test_sans_feuille_les_styles_en_ligne_suffisent(self) -> None:
        """Tout le rendu V2 repose sur des styles en ligne sans tableau."""
        html = render_notice_html(dict(CONTEXTE))
        self.assertNotIn("<table", html)
        self.assertIn("max-width:560px", html)


class IdentiteLisibleTests(unittest.TestCase):
    def test_le_nom_affiche_s_ecrit_en_chasse_fixe(self) -> None:
        """En Arial, « lnfosPRlME » se lisait « InfosPRIME » dans la fiche même."""
        html = render_notice_html(dict(CONTEXTE))
        valeur = re.search(r'<span style="([^"]*)">lnfosPRlME<', html)
        self.assertIsNotNone(valeur)
        self.assertIn("monospace", valeur.group(1))  # type: ignore[union-attr]


class HeureTests(unittest.TestCase):
    def test_la_reception_se_lit_a_l_heure_de_paris(self) -> None:
        html = render_notice_html(dict(CONTEXTE))
        self.assertIn("Reçu", html)
        self.assertIn("25/09/2026 à 08:45", html)

    def test_sans_date_rien_n_est_invente(self) -> None:
        html = render_notice_html({**CONTEXTE, "received_at": None})
        self.assertNotIn("25/09/2026", html)
        self.assertNotIn(">Reçu<", html)


class TitreTests(unittest.TestCase):
    def test_le_titre_suit_le_niveau(self) -> None:
        danger = {**CONTEXTE["badge"], "level": "danger", "word": "DANGEREUX"}  # type: ignore[dict-item]
        self.assertIn("ACTION REQUISE · MESSAGE RETENU", render_notice_html(dict(CONTEXTE)))
        self.assertIn("DANGEREUX · MESSAGE RETENU", render_notice_html({**CONTEXTE, "badge": danger}))


if __name__ == "__main__":
    unittest.main()
