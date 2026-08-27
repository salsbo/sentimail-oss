"""L'accusé d'une directive parle à celui qui l'a donnée, et se répond d'un clic.

L'accusé disait « L'utilisateur a qualifié le message de spam » à l'utilisateur
lui-même, et concluait « réponds à ce message : il rouvre le dossier » - sans
dire comment. Les autres surfaces répondent par trois boutons ; celle-ci doit
parler la même langue : A pour livrer à nouveau, C pour expliquer autre chose.
"""

from __future__ import annotations

import re
import unittest
from html import unescape
from urllib.parse import parse_qs, urlsplit

from sentimail_v3.conversation.directive_policy import evaluate_directive
from sentimail_v3.conversation.directive_receipt import (
    ETAT_REGLAGE,
    receipt_html,
    receipt_text,
)
from sentimail_v3.conversation.receipt_preference import parse_receipt_toggle
from sentimail_v3.conversation.review_notice import ACTION_TOKEN_PLACEHOLDER

ADRESSE = "maia@sentinel.mondomaine.example"


def _bouton(html: str, lettre: str) -> str:
    trouve = re.search(rf'<a [^>]*data-choice="{lettre}".*?</a>', html, re.S)
    assert trouve is not None, f"bouton {lettre} absent"
    return trouve.group(0)


def _mailto_champ(bouton: str, champ: str) -> str:
    lien = re.search(r'href="([^"]+)"', bouton)
    assert lien is not None
    return parse_qs(urlsplit(unescape(lien.group(1))).query)[champ][0]


class TexteTests(unittest.TestCase):
    def test_l_objet_concerne_reste_en_tete(self) -> None:
        texte = receipt_text(
            "Tu as qualifié ce message de spam.", "Pub XYZ",
            "Les prochains messages de cet expéditeur seront retenus.",
            learned=True, offer_redelivery=True,
        )
        self.assertTrue(texte.startswith("Objet concerné : Pub XYZ"))

    def test_le_texte_propose_les_reponses_a_et_c(self) -> None:
        texte = receipt_text(
            "Tu as qualifié ce message de spam.", "Pub XYZ",
            "Les prochains messages de cet expéditeur seront retenus.",
            learned=True, offer_redelivery=True,
        )
        self.assertNotIn("réponds à ce message", texte)
        self.assertIn("A", texte)
        self.assertIn("C", texte)

    def test_l_apprentissage_du_type_est_annonce(self) -> None:
        texte = receipt_text(
            "Tu as qualifié ce message de spam.", "Pub XYZ", "",
            learned=True, offer_redelivery=True,
        )
        self.assertIn("exemple", texte)
        self.assertIn("même genre", texte)

    def test_sans_label_rien_n_est_annonce(self) -> None:
        texte = receipt_text(
            "C'est noté.", "Pub XYZ", "", learned=False, offer_redelivery=False
        )
        self.assertNotIn("exemple", texte)


class BoutonsTests(unittest.TestCase):
    def _html(self, offer_redelivery: bool = True) -> str:
        return receipt_html(
            "Tu as qualifié ce message de spam.", "Pub XYZ",
            "Les prochains messages de cet expéditeur seront retenus.",
            learned=True, offer_redelivery=offer_redelivery,
            action_address=ADRESSE,
        )

    def test_les_boutons_a_et_c_sont_presents(self) -> None:
        html = self._html()
        self.assertIn("Livrer à nouveau", _bouton(html, "A"))
        self.assertIn("Autre commentaire", _bouton(html, "C"))

    def test_le_jeton_vit_dans_l_objet_du_mailto(self) -> None:
        for lettre in ("A", "C"):
            with self.subTest(lettre=lettre):
                bouton = _bouton(self._html(), lettre)
                self.assertIn(ACTION_TOKEN_PLACEHOLDER, _mailto_champ(bouton, "subject"))
                self.assertNotIn("S3-ACTION", _mailto_champ(bouton, "body"))

    def test_le_bouton_a_est_lu_comme_une_livraison(self) -> None:
        corps = _mailto_champ(_bouton(self._html(), "A"), "body")
        verdict = evaluate_directive(corps, {"requested_action": "release_original"})
        self.assertEqual(verdict["explicit_action"], "release_original")
        self.assertEqual(verdict["explicit_classification"], "legitimate")
        self.assertEqual(verdict["conflicts"], [])

    def test_le_bouton_c_ne_decide_rien(self) -> None:
        corps = _mailto_champ(_bouton(self._html(), "C"), "body")
        verdict = evaluate_directive(corps, {"requested_action": "suppress_future"})
        self.assertIsNone(verdict["explicit_action"])

    def test_un_message_deja_livre_n_offre_pas_de_relivraison(self) -> None:
        html = self._html(offer_redelivery=False)
        self.assertNotIn('data-choice="A"', html)
        self.assertIn('data-choice="C"', html)


class EtatDuReglageTests(unittest.TestCase):
    """L'accusé dit qu'il peut se taire : l'état du réglage et son bascule.

    Un accusé n'est envoyé que si le réglage est actif ; il porte donc l'état
    « activé » et la phrase exacte qui le désactive.
    """

    def test_l_etat_et_la_bascule_sont_dans_le_texte(self) -> None:
        texte = receipt_text(
            "C'est noté.", "Pub XYZ", "", learned=False, offer_redelivery=False
        )
        self.assertIn("accusé de réception est activé", texte)
        self.assertIn("désactive l'accusé de réception", texte)

    def test_l_etat_et_la_bascule_sont_dans_la_page(self) -> None:
        html = receipt_html(
            "C'est noté.", "Pub XYZ", "", learned=False,
            offer_redelivery=False, action_address=ADRESSE,
        )
        self.assertIn("accusé de réception est activé", html)
        self.assertIn("désactive l&#x27;accusé de réception", html)

    def test_le_tiret_cadratin_a_disparu_de_la_phrase(self) -> None:
        self.assertNotIn("—", ETAT_REGLAGE)
        self.assertIn("activé : réponds", ETAT_REGLAGE)

    def test_la_bascule_est_un_lien_cliquable_dans_la_page(self) -> None:
        html = receipt_html(
            "C'est noté.", "Pub XYZ", "", learned=False,
            offer_redelivery=False, action_address=ADRESSE,
        )
        trouve = re.search(
            r'<a href="([^"]+)">désactive l&#x27;accusé de réception</a>', html
        )
        self.assertIsNotNone(trouve, "aucun lien « désactive... » trouvé dans la page")
        href = unescape(trouve.group(1))
        self.assertNotIn("+", href)
        self.assertTrue(href.startswith("mailto:" + ADRESSE + "?"))
        query = parse_qs(urlsplit(href).query)
        self.assertIn(ACTION_TOKEN_PLACEHOLDER, query["subject"][0])
        self.assertNotIn("S3-ACTION", query["body"][0])
        # Aller-retour : le corps pré-rempli, une fois cliqué et renvoyé,
        # doit être reconnu comme une désactivation, sans appel à un modèle.
        self.assertIs(parse_receipt_toggle(query["body"][0]), False)


if __name__ == "__main__":
    unittest.main()
