from __future__ import annotations

import re
import unittest
from email import policy
from html import unescape
from email.parser import BytesParser
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from sentimail_v3.conversation.choice_answers import GRIS, ROUGE
from sentimail_v3.execution.delivery import append_feedback_footer

JETON = "c" * 43
REGLAGES = SimpleNamespace(action_address="maia@sentinel.example")

HTML_BRUT = (
    b"From: sender@example.org\r\n"
    b"To: user@example.org\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n\r\n"
    b"<html><body><p>Bonjour</p></body></html>\r\n"
)
TEXTE_BRUT = (
    b"From: sender@example.org\r\n"
    b"To: user@example.org\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Bonjour\r\n"
)


def _corps_html() -> str:
    rendu, insere = append_feedback_footer(HTML_BRUT, REGLAGES, JETON)  # type: ignore[arg-type]
    assert insere
    return BytesParser(policy=policy.default).parsebytes(rendu).get_content()


def _corps_texte() -> str:
    rendu, insere = append_feedback_footer(TEXTE_BRUT, REGLAGES, JETON)  # type: ignore[arg-type]
    assert insere
    return BytesParser(policy=policy.default).parsebytes(rendu).get_content()


def _bouton(html: str, lettre: str) -> str:
    trouve = re.search(rf'<a [^>]*data-choice="{lettre}".*?</a>', html, re.S)
    assert trouve is not None, f"bouton {lettre} absent du pied de page"
    return trouve.group(0)


def _mailto_champ(bouton: str, champ: str) -> str:
    lien = re.search(r'href="([^"]+)"', bouton)
    assert lien is not None
    # Dans un attribut HTML, « & » s'écrit « &amp; » : le client de messagerie
    # rétablit l'entité, puis décode le pourcentage-encodage - dans cet ordre.
    # L'inverse écraserait les retours à la ligne avant la lecture des champs.
    return parse_qs(urlsplit(unescape(lien.group(1))).query)[champ][0]


def _mailto_body(bouton: str) -> str:
    return _mailto_champ(bouton, "body")


def _mailto_subject(bouton: str) -> str:
    return _mailto_champ(bouton, "subject")


class ReponsesDuMessageLivreTests(unittest.TestCase):
    """Un message livré n'offrait qu'un lien rouge noyé dans une phrase.

    Les deux autres surfaces posent la question en toutes lettres ; celle-ci
    demandait de repérer un lien au milieu d'un texte. Elle pose désormais la
    même question, avec les mêmes couleurs.
    """

    def test_les_reponses_sont_de_petits_boutons(self) -> None:
        html = _corps_html()
        for lettre in ("B", "C"):
            with self.subTest(lettre=lettre):
                lien = _bouton(html, lettre)
                self.assertIn("display:inline-block", lien)
                self.assertNotRegex(lien, r"(?<!line-)height:")

    def test_aucune_reponse_de_livraison_sur_un_message_deja_livre(self) -> None:
        self.assertNotIn('data-choice="A"', _corps_html())

    def test_les_couleurs_sont_celles_des_autres_surfaces(self) -> None:
        html = _corps_html()
        self.assertIn(f"background:{ROUGE}", _bouton(html, "B"))
        self.assertIn(f"background:{GRIS}", _bouton(html, "C"))


class ReponsesEcritesTests(unittest.TestCase):
    """Ce que chaque bouton fait écrire doit rester lisible par les règles."""

    def test_le_bouton_b_ecrit_un_refus_lisible(self) -> None:
        from sentimail_v3.conversation.directive_policy import evaluate_directive

        corps = _mailto_body(_bouton(_corps_html(), "B"))
        # La séquence machine vit dans l'objet ; le corps est une phrase que
        # les règles lisent sans modèle.
        self.assertNotIn("S3-ACTION", corps)
        self.assertIn(f"S3-ACTION:{JETON}", _mailto_subject(_bouton(_corps_html(), "B")))
        verdict = evaluate_directive(corps, {"requested_action": "suppress_future"})
        self.assertEqual(verdict["explicit_action"], "suppress_future")

    def test_le_bouton_c_laisse_ecrire_le_jeton_reste_dans_l_objet(self) -> None:
        corps = _mailto_body(_bouton(_corps_html(), "C"))
        self.assertNotIn("S3-ACTION", corps)
        self.assertIn(f"S3-ACTION:{JETON}", _mailto_subject(_bouton(_corps_html(), "C")))
        self.assertRegex(corps.casefold(), r"écri|explique|demande|tapez")

    def test_aucune_lettre_seule_dans_le_choix_c(self) -> None:
        # Une lettre isolée serait lue comme une décision : « autre chose »
        # n'en prend aucune tant que rien n'est écrit.
        from sentimail_v3.conversation.directive_policy import evaluate_directive

        corps = _mailto_body(_bouton(_corps_html(), "C"))
        verdict = evaluate_directive(corps, {"requested_action": "suppress_future"})
        self.assertIsNone(verdict["explicit_action"])


class VersionTexteTests(unittest.TestCase):
    """Un client en texte seul doit avoir les deux mêmes possibilités."""

    def test_les_deux_choix_sont_offerts_en_texte(self) -> None:
        texte = _corps_texte()
        self.assertIn("Ce message est non sollicité ?", texte)
        self.assertEqual(texte.count("mailto:maia@sentinel.example"), 2)

    def test_le_texte_dit_ce_que_fait_chaque_lien(self) -> None:
        texte = _corps_texte().casefold()
        self.assertIn("signale", texte)
        self.assertRegex(texte, r"autre chose|explique")


class InvariantsPreservesTests(unittest.TestCase):
    def test_l_entete_de_retour_reste_pose(self) -> None:
        rendu, _ = append_feedback_footer(HTML_BRUT, REGLAGES, JETON)  # type: ignore[arg-type]
        self.assertIn(b"X-SentiMail-Feedback: smtp-action-available", rendu)

    def test_un_message_signe_reste_intact(self) -> None:
        signe = (
            b"From: sender@example.org\r\n"
            b"To: user@example.org\r\n"
            b"Content-Type: multipart/signed; boundary=x; protocol=\"application/pgp-signature\"\r\n\r\n"
            b"--x\r\nContent-Type: text/plain\r\n\r\nBonjour\r\n--x--\r\n"
        )
        rendu, insere = append_feedback_footer(signe, REGLAGES, JETON)  # type: ignore[arg-type]
        self.assertFalse(insere)
        self.assertEqual(rendu, signe)


if __name__ == "__main__":
    unittest.main()
