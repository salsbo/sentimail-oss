from __future__ import annotations

import re
import unittest
from urllib.parse import parse_qs, urlsplit

from sentimail_v3.conversation.choice_answers import GRIS, ROUGE, VERT
from sentimail_v3.conversation.review_notice import (
    ACTION_TOKEN_PLACEHOLDER,
    choice_links,
    render_notice_html,
)

CONTEXTE = {
    "subject": "Votre facture",
    "sender": "facture@exemple.fr",
    "status_text": "Ce message n’a pas été livré.",
    "concerns": ["Le domaine ne correspond pas à la marque annoncée."],
    "reassurances": ["L’expéditeur est authentifié."],
    "decision": "Je préfère te demander.",
    "action_address": "maia@sentinel.mondomaine.example",
}


def _corps(lettre: str) -> str:
    lien = choice_links("maia@sentinel.mondomaine.example")[lettre]
    return parse_qs(urlsplit(lien).query)["body"][0]


def _sujet(lettre: str) -> str:
    lien = choice_links("maia@sentinel.mondomaine.example")[lettre]
    return parse_qs(urlsplit(lien).query)["subject"][0]


class SequenceDansLObjetTests(unittest.TestCase):
    """Le jeton vit dans l'objet ; la zone de saisie reste au destinataire.

    Le corps préremplie commençait par une ligne opaque - S3-ACTION:x1m5Qbam...
    - que le destinataire ne devait surtout pas effacer. Un mailto: ne
    transporte que du texte brut : pas moyen de la cacher par la mise en forme.
    Elle vit donc dans l'objet, que personne n'édite, et que le serveur lit
    déjà (conversation.record_inbound cherche le marqueur dans objet + corps).
    """

    def test_le_choix_c_dit_quoi_ecrire(self) -> None:
        corps = _corps("C")
        self.assertNotIn(ACTION_TOKEN_PLACEHOLDER, corps)
        self.assertRegex(corps.casefold(), r"écri|consigne|demande|explique|tapez")

    def test_chaque_objet_porte_le_jeton_intact(self) -> None:
        # Le jeton est retrouvé par motif : rien ne doit lui coller.
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                sujet = _sujet(lettre)
                self.assertIn(ACTION_TOKEN_PLACEHOLDER, sujet)
                position = sujet.index(ACTION_TOKEN_PLACEHOLDER)
                fin = position + len(ACTION_TOKEN_PLACEHOLDER)
                self.assertIn(sujet[fin : fin + 1], ("", " ", "\n"))

    def test_aucun_corps_ne_porte_le_jeton(self) -> None:
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                self.assertNotIn(ACTION_TOKEN_PLACEHOLDER, _corps(lettre))


class ReponsesEnBoutonsTests(unittest.TestCase):
    """Trois petits boutons colorés, côte à côte, la lettre dedans.

    L'avis se lit sur un téléphone : un bouton doit se voir comme tel sans
    reprendre la hauteur de l'explication qu'il conclut.
    """

    def _html(self) -> str:
        return render_notice_html(dict(CONTEXTE))

    def _lien(self, lettre: str) -> str:
        trouve = re.search(rf'<a [^>]*data-choice="{lettre}".*?</a>', self._html(), re.S)
        self.assertIsNotNone(trouve, f"réponse {lettre} absente")
        return trouve.group(0)

    def test_les_trois_reponses_existent(self) -> None:
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                self.assertIn(f'data-choice="{lettre}"', self._html())

    def test_aucune_hauteur_n_est_imposee(self) -> None:
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                self.assertNotRegex(self._lien(lettre), r"(?<!line-)height:")

    def test_les_reponses_tiennent_sur_une_ligne(self) -> None:
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                self.assertIn("display:inline-block", self._lien(lettre))

    def test_chaque_lettre_garde_sa_couleur(self) -> None:
        for lettre, couleur in (("A", VERT), ("B", ROUGE), ("C", GRIS)):
            with self.subTest(lettre=lettre):
                self.assertIn(f"background:{couleur}", self._lien(lettre))


if __name__ == "__main__":
    unittest.main()
