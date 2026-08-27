from __future__ import annotations

import re
import unittest
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qs, urlsplit

from sentimail_v3.conversation.junk_notice import (
    JUNK_TOKEN_PLACEHOLDER,
    junk_choice_links,
    render_junk_html,
)

CONTEXTE = {
    "subject": "Votre colis est en attente",
    "sender": "suivi@colis-livraison.example",
    "verdict": "spam",
    "reasons": [
        "Le domaine ne correspond pas au transporteur annoncé.",
        "Le message presse d’agir avant ce soir.",
    ],
    "lessons": [
        {"name": "Usurpation de marque", "description": "Le message se fait passer pour un transporteur connu."},
    ],
    "action_address": "maia@sentinel.mondomaine.example",
    "has_preview": True,
}


class ContenuTests(unittest.TestCase):
    def test_l_apercu_est_annonce_comme_une_image(self) -> None:
        html = render_junk_html(dict(CONTEXTE))
        self.assertIn("Aperçu de l’email", html)
        self.assertRegex(html.casefold(), r"image|photo|capture")

    def test_le_texte_du_message_n_est_pas_recopie(self) -> None:
        """La capture remplace le corps : recopier le texte rendrait au message
        sa force de persuasion, et ses liens leur pouvoir de nuire."""
        contexte = dict(CONTEXTE)
        contexte["body_text"] = "Cliquez ici pour recevoir votre colis MAINTENANT"
        html = render_junk_html(contexte)
        self.assertNotIn("MAINTENANT", html)

    def test_la_raison_est_mise_en_forme_et_non_listee_brute(self) -> None:
        html = render_junk_html(dict(CONTEXTE))
        for raison in CONTEXTE["reasons"]:
            self.assertIn(raison, html)
        self.assertRegex(html, r"background:#[0-9a-fA-F]{6}")

    def test_la_technique_est_nommee(self) -> None:
        html = render_junk_html(dict(CONTEXTE))
        self.assertIn("Usurpation de marque", html)

    def test_un_message_dangereux_se_distingue_d_un_indesirable(self) -> None:
        indesirable = render_junk_html({**CONTEXTE, "verdict": "spam"})
        dangereux = render_junk_html({**CONTEXTE, "verdict": "dangerous"})
        self.assertNotEqual(indesirable, dangereux)
        self.assertRegex(dangereux.casefold(), r"dangereux|dangereuse")

    def test_sans_raison_l_avis_reste_lisible(self) -> None:
        html = render_junk_html({**CONTEXTE, "reasons": [], "lessons": []})
        self.assertIn("Aperçu de l’email", html)
        self.assertTrue(len(html) > 400)


class BoutonsTests(unittest.TestCase):
    def test_un_bouton_permet_de_se_faire_livrer_le_message(self) -> None:
        html = render_junk_html(dict(CONTEXTE))
        self.assertRegex(html.casefold(), r"livre")
        self.assertIn("mailto:maia@sentinel.mondomaine.example", html)

    def test_les_reponses_sont_de_petits_boutons(self) -> None:
        """Un avis d'indésirable se survole : il ne mérite pas de pavés."""
        html = render_junk_html(dict(CONTEXTE))
        for lettre in ("A", "C"):
            with self.subTest(lettre=lettre):
                lien = re.search(rf'<a [^>]*data-choice="{lettre}".*?</a>', html, re.S)
                self.assertIsNotNone(lien)
                self.assertIn("display:inline-block", lien.group(0))
                self.assertNotRegex(lien.group(0), r"(?<!line-)height:")

    def test_chaque_lettre_garde_la_couleur_des_autres_surfaces(self) -> None:
        from sentimail_v3.conversation.choice_answers import GRIS, ROUGE, VERT

        html = render_junk_html(dict(CONTEXTE))
        # Le classement est déjà fait : le confirmer (B) n'apporte rien.
        self.assertNotIn('data-choice="B"', html)
        for lettre, couleur in (("A", VERT), ("C", GRIS)):
            with self.subTest(lettre=lettre):
                lien = re.search(rf'<a [^>]*data-choice="{lettre}".*?</a>', html, re.S)
                self.assertIsNotNone(lien)
                self.assertIn(f"background:{couleur}", lien.group(0))


class LiensTests(unittest.TestCase):
    def _corps(self, lettre: str) -> str:
        lien = junk_choice_links("maia@sentinel.mondomaine.example")[lettre]
        return parse_qs(urlsplit(lien).query)["body"][0]

    def test_le_choix_a_demande_la_livraison(self) -> None:
        from sentimail_v3.conversation.directive_policy import evaluate_directive

        verdict = evaluate_directive(
            self._corps("A"), {"requested_action": "release_original"}
        )
        self.assertEqual(verdict["explicit_action"], "release_original")

    def test_aucun_bouton_ne_confirme_le_classement(self) -> None:
        # Principe des jeux de boutons : un indésirable propose A et C, jamais
        # B - le classement est déjà acquis, seul le désaccord a un geste.
        self.assertNotIn("B", junk_choice_links("maia@sentinel.mondomaine.example"))

    def test_le_choix_c_dit_quoi_ecrire(self) -> None:
        # La séquence machine vit dans l'objet ; le corps invite à écrire.
        corps = self._corps("C")
        self.assertNotIn(JUNK_TOKEN_PLACEHOLDER, corps)
        self.assertRegex(corps.casefold(), r"écri|consigne|explique|demande|tapez")

    def test_chaque_objet_porte_le_jeton(self) -> None:
        for lettre in ("A", "C"):
            with self.subTest(lettre=lettre):
                lien = junk_choice_links("maia@sentinel.mondomaine.example")[lettre]
                sujet = parse_qs(urlsplit(lien).query)["subject"][0]
                self.assertIn(JUNK_TOKEN_PLACEHOLDER, sujet)
                self.assertNotIn(JUNK_TOKEN_PLACEHOLDER, self._corps(lettre))


class EnveloppeTests(unittest.TestCase):
    """Le message livré doit être l'enveloppe, pas l'original."""

    def _original(self) -> bytes:
        return (
            b"From: suivi@colis-livraison.example\r\n"
            b"To: operateur@mondomaine.example\r\n"
            b"Subject: Votre colis est en attente\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b'<html><body><a href="http://mechant.top/x">Cliquez MAINTENANT</a></body></html>\r\n'
        )

    def test_l_enveloppe_ne_contient_plus_le_lien_d_origine(self) -> None:
        from sentimail_v3.execution.delivery import build_junk_envelope

        enveloppe = build_junk_envelope(
            self._original(),
            "spam",
            reasons=["Le domaine ne correspond pas."],
            lessons=[],
            preview=b"\x89PNG\r\n\x1a\n" + b"0" * 40,
            action_address="maia@sentinel.mondomaine.example",
            assistant_sender="MAIA - SentiMail <maia@mondomaine.example>",
            recipient="moi@mondomaine.example",
        )
        self.assertNotIn(b"mechant.top", enveloppe)
        self.assertNotIn(b"MAINTENANT", enveloppe)

    def test_l_enveloppe_porte_la_capture_en_piece_jointe(self) -> None:
        from sentimail_v3.execution.delivery import build_junk_envelope

        enveloppe = build_junk_envelope(
            self._original(), "spam", reasons=[], lessons=[],
            preview=b"\x89PNG\r\n\x1a\n" + b"0" * 40,
            action_address="maia@sentinel.mondomaine.example",
            assistant_sender="MAIA - SentiMail <maia@mondomaine.example>",
            recipient="moi@mondomaine.example",
        )
        message = BytesParser(policy=policy.default).parsebytes(enveloppe)
        images = [
            part for part in message.walk()
            if part.get_content_type() == "image/png"
        ]
        self.assertEqual(len(images), 1)

    def test_l_objet_reste_reconnaissable(self) -> None:
        from sentimail_v3.execution.delivery import build_junk_envelope

        enveloppe = build_junk_envelope(
            self._original(), "spam", reasons=[], lessons=[],
            preview=None, action_address="maia@sentinel.mondomaine.example",
            assistant_sender="MAIA - SentiMail <maia@mondomaine.example>",
            recipient="moi@mondomaine.example",
        )
        message = BytesParser(policy=policy.default).parsebytes(enveloppe)
        self.assertIn("Votre colis est en attente", str(message.get("subject")))

    def test_sans_capture_l_enveloppe_est_quand_meme_produite(self) -> None:
        # Le bac à sable de rendu peut être indisponible : on ne renvoie pas
        # pour autant le message hostile intact.
        from sentimail_v3.execution.delivery import build_junk_envelope

        enveloppe = build_junk_envelope(
            self._original(), "spam", reasons=["Motif."], lessons=[],
            preview=None, action_address="maia@sentinel.mondomaine.example",
            assistant_sender="MAIA - SentiMail <maia@mondomaine.example>",
            recipient="moi@mondomaine.example",
        )
        self.assertNotIn(b"mechant.top", enveloppe)
        self.assertIn(b"Motif.", enveloppe.replace(b"=\r\n", b""))

    def test_les_entetes_d_origine_sont_conserves_pour_l_audit(self) -> None:
        from sentimail_v3.execution.delivery import build_junk_envelope

        enveloppe = build_junk_envelope(
            self._original(), "spam", reasons=[], lessons=[],
            preview=None, action_address="maia@sentinel.mondomaine.example",
            assistant_sender="MAIA - SentiMail <maia@mondomaine.example>",
            recipient="moi@mondomaine.example",
        )
        message = BytesParser(policy=policy.default).parsebytes(enveloppe)
        self.assertTrue(message.get("X-SentiMail-Original-From"))


if __name__ == "__main__":
    unittest.main()


class JetonEtBranchementTests(unittest.TestCase):
    """Un avis dont le jeton reste un marqueur ne rattache aucune réponse."""

    def test_le_jeton_est_substitue_dans_l_enveloppe(self) -> None:
        from sentimail_v3.execution.delivery import build_junk_envelope

        enveloppe = build_junk_envelope(
            b"From: a@b.c\r\nSubject: Test\r\n\r\ncorps\r\n",
            "spam",
            reasons=[],
            lessons=[],
            preview=None,
            action_address="maia@sentinel.mondomaine.example",
            assistant_sender="MAIA - SentiMail <maia@mondomaine.example>",
            recipient="moi@mondomaine.example",
            token="JETON-DE-TEST-INACTIF",
        )
        texte = enveloppe.decode("utf-8", "replace").replace("=\r\n", "")
        self.assertNotIn(JUNK_TOKEN_PLACEHOLDER, texte)
        self.assertIn("S3-ACTION%3AJETON-DE-TEST-INACTIF", texte.replace("=3A", "%3A"))

    def test_sans_jeton_le_marqueur_ne_fuit_pas_dans_l_avis(self) -> None:
        # Mieux vaut un avis sans lien pré-rempli qu'un avis affichant un
        # marqueur interne au destinataire.
        from sentimail_v3.execution.delivery import build_junk_envelope

        enveloppe = build_junk_envelope(
            b"From: a@b.c\r\nSubject: Test\r\n\r\ncorps\r\n",
            "spam", reasons=[], lessons=[], preview=None,
            action_address="maia@sentinel.mondomaine.example",
            assistant_sender="MAIA - SentiMail <maia@mondomaine.example>",
            recipient="moi@mondomaine.example",
        )
        self.assertNotIn(JUNK_TOKEN_PLACEHOLDER.encode(), enveloppe)


class LivraisonBrancheeTests(unittest.TestCase):
    """La leçon des traductions non branchées : vérifier l'appel réel."""

    def test_la_livraison_classee_construit_l_enveloppe(self) -> None:
        import inspect

        from sentimail_v3.execution import delivery

        source = inspect.getsource(delivery.release_original)
        self.assertIn("build_junk_envelope", source)

    def test_l_ancien_bandeau_n_est_qu_un_repli(self) -> None:
        # Il reste comme filet si l'avis échoue - perdre un message serait pire
        # qu'en livrer un mal présenté - mais il ne doit pas être le chemin
        # normal : l'enveloppe est construite d'abord.
        import inspect

        from sentimail_v3.execution import delivery

        source = inspect.getsource(delivery.release_original)
        self.assertLess(
            source.index("build_junk_envelope"),
            source.index("annotate_classified"),
            "le bandeau est appliqué avant l'enveloppe",
        )


class EnteteDeTriTests(unittest.TestCase):
    """Sans l'en-tête exact, l'avis atterrit en boîte de réception.

    C'est lui, et lui seul, qui fait ranger le message en indésirables côté
    serveur de messagerie. Une enveloppe qui le perdrait ferait arriver tous
    les spams classés dans la boîte principale.
    """

    def test_l_enveloppe_porte_l_entete_de_classement(self) -> None:
        from sentimail_v3.execution.delivery import build_junk_envelope

        enveloppe = build_junk_envelope(
            b"From: a@b.c\r\nSubject: Test\r\n\r\ncorps\r\n",
            "spam", reasons=["Motif."], lessons=[], preview=None,
            action_address="maia@sentinel.mondomaine.example",
            assistant_sender="MAIA - SentiMail <maia@mondomaine.example>",
            recipient="moi@mondomaine.example",
        )
        message = BytesParser(policy=policy.default).parsebytes(enveloppe)
        self.assertEqual(str(message.get("X-Sentimail-Verdict")), "spam")

    def test_la_graphie_est_celle_que_le_tri_attend(self) -> None:
        # classify_header est la source de vérité : l'enveloppe doit employer
        # exactement la même graphie, pas une variante.
        from sentimail_v3.execution.delivery import build_junk_envelope, classify_header

        attendu = classify_header(b"From: a@b.c\r\n\r\nx\r\n", "spam", reasons=[], techniques=[])
        nom = attendu.split(b":")[0]
        enveloppe = build_junk_envelope(
            b"From: a@b.c\r\nSubject: T\r\n\r\ncorps\r\n",
            "spam", reasons=[], lessons=[], preview=None,
            action_address="maia@sentinel.mondomaine.example",
            assistant_sender="MAIA - SentiMail <maia@mondomaine.example>",
            recipient="moi@mondomaine.example",
        )
        self.assertIn(nom + b":", enveloppe)

    def test_un_message_dangereux_porte_son_verdict(self) -> None:
        from sentimail_v3.execution.delivery import build_junk_envelope

        enveloppe = build_junk_envelope(
            b"From: a@b.c\r\nSubject: T\r\n\r\ncorps\r\n",
            "dangerous", reasons=[], lessons=[], preview=None,
            action_address="maia@sentinel.mondomaine.example",
            assistant_sender="MAIA - SentiMail <maia@mondomaine.example>",
            recipient="moi@mondomaine.example",
        )
        message = BytesParser(policy=policy.default).parsebytes(enveloppe)
        self.assertEqual(str(message.get("X-Sentimail-Verdict")), "dangerous")
