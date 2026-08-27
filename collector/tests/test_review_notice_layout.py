from __future__ import annotations

import unittest

from sentimail_v3.conversation.review_notice import (
    ACTION_TOKEN_PLACEHOLDER,
    choice_links,
    render_notice_html,
)

CONTEXTE = {
    "subject": "Votre facture est disponible sur sfr.fr",
    "sender": "SFR <facture@sfr.fr>",
    "status_text": "Ce message n’a pas été livré : il attend ta réponse.",
    "concerns": ["Le nom affiché est celui d’une marque connue, mais le message vient d’ailleurs."],
    "reassurances": ["L’expéditeur est bien celui qu’il annonce."],
    "decision": "Je préfère te demander avant de décider.",
    "limits": ["Je n’ai pas pu ouvrir tous les liens pour les vérifier."],
    "risk_excerpts": [],
    "techniques": [{"name": "Usurpation de marque", "description": "Le message se fait passer pour une enseigne connue."}],
    "action_address": "maia@sentinel.mondomaine.example",
}


class LayoutTests(unittest.TestCase):
    def test_l_apercu_du_message_est_titre(self) -> None:
        html = render_notice_html(CONTEXTE)
        self.assertIn("Aperçu de l’email", html)

    def test_les_deux_colonnes_s_empilent_sur_telephone(self) -> None:
        """Côte à côte quand la place existe, empilées sur un téléphone.

        Le tableau figé 50/50 broyait le texte sur iPhone : deux colonnes de
        180 px, un mot par ligne. Deux blocs fluides à largeur plafonnée se
        rangent côte à côte sur un écran large et s'empilent d'eux-mêmes
        quand l'écran est étroit - sans media query, que l'avis (un fragment
        sans <head>) ne peut pas porter partout.
        """
        html = render_notice_html(CONTEXTE)
        self.assertNotIn("<table", html)
        self.assertEqual(
            html.count("display:inline-block;width:100%;max-width:320px"), 2
        )
        # L'ordre de lecture reste le même : ce qui gêne, puis ce qui rassure.
        self.assertLess(html.index("Ce qui me gêne"), html.index("Ce qui me rassure"))

    def test_le_verdict_vient_sous_les_deux_colonnes(self) -> None:
        html = render_notice_html(CONTEXTE)
        self.assertLess(html.index("Ce qui me rassure"), html.index("Ce que j’en conclus"))

    def test_la_technique_d_attaque_accompagne_le_verdict(self) -> None:
        html = render_notice_html(CONTEXTE)
        self.assertIn("Usurpation de marque", html)
        self.assertLess(
            html.index("Ce que j’en conclus"), html.index("Usurpation de marque")
        )

    def test_les_trois_choix_sont_des_boutons(self) -> None:
        html = render_notice_html(CONTEXTE)
        for lettre in ("A", "B", "C"):
            self.assertIn(f'data-choice="{lettre}"', html)

    def test_aucun_jargon_ne_subsiste(self) -> None:
        """Un avis qui parle en codes internes n'est pas lisible."""
        html = render_notice_html(CONTEXTE).casefold()
        for jargon in ("deep_execution", "ask_user", "undetermined", "dmarc", "apex"):
            self.assertNotIn(jargon, html)


class ChoiceLinkTests(unittest.TestCase):
    def test_les_choix_a_et_b_sont_pre_remplis(self) -> None:
        liens = choice_links("maia@sentinel.mondomaine.example")
        for lettre in ("A", "B"):
            self.assertIn("body=", liens[lettre])
            self.assertIn(ACTION_TOKEN_PLACEHOLDER, liens[lettre])

    def test_le_choix_c_ouvre_un_message_a_ecrire(self) -> None:
        """« Autre chose » attend une explication : la pré-remplir la volerait."""
        lien = choice_links("maia@sentinel.mondomaine.example")["C"]
        self.assertIn(ACTION_TOKEN_PLACEHOLDER, lien)
        self.assertNotIn("Je+", lien)

    def test_le_texte_pre_rempli_est_compris_par_les_regles(self) -> None:
        # Une lettre seule ne veut rien dire pour l'interprétation : le corps
        # doit porter une phrase que les règles reconnaissent sans modèle.
        from urllib.parse import parse_qs, urlsplit

        from sentimail_v3.conversation.directive_policy import evaluate_directive

        liens = choice_links("maia@sentinel.mondomaine.example")
        for lettre, attendu in (("A", "release_original"), ("B", "suppress_future")):
            with self.subTest(lettre=lettre):
                corps = parse_qs(urlsplit(liens[lettre]).query)["body"][0]
                verdict = evaluate_directive(corps, {"requested_action": attendu})
                self.assertEqual(verdict["explicit_action"], attendu)

    def test_l_adresse_d_action_est_la_destination(self) -> None:
        liens = choice_links("maia@sentinel.mondomaine.example")
        self.assertTrue(liens["A"].startswith("mailto:maia@sentinel.mondomaine.example?"))


if __name__ == "__main__":
    unittest.main()


class TokenSubstitutionTests(unittest.IsolatedAsyncioTestCase):
    """Le jeton n'existe qu'à l'expédition : le marqueur doit y être remplacé."""

    async def test_le_marqueur_est_remplace_par_le_vrai_jeton(self) -> None:
        from types import SimpleNamespace
        from unittest.mock import AsyncMock, patch

        from sentimail_v3.conversation.assistant import _send_outbox

        envois: list[object] = []

        class _Pool:
            async def fetchrow(self, query, *args):
                return {
                    "id": 1,
                    "action_id": "11111111-1111-1111-1111-111111111111",
                    "conversation_id": "22222222-2222-2222-2222-222222222222",
                    "recipient": "moi@mondomaine.example",
                    "sender": "MAIA <maia@mondomaine.example>",
                    "reply_to": "maia@sentinel.mondomaine.example",
                    "subject": "[SentiMail] Ton avis",
                    "body_text": "corps",
                    "body_html": f"<a href='mailto:x?body={ACTION_TOKEN_PLACEHOLDER}'>A</a>",
                    "attempts": 1,
                    "attachment_content": None,
                    "attachment_filename": None,
                    "attachment_content_type": None,
                }

            async def execute(self, query, *args):
                return "UPDATE 1"

            async def fetchval(self, query, *args):
                return None

            def acquire(self):
                return self

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def transaction(self):
                return self

        async def _capture(message, **kwargs):
            envois.append(message)
            return {}

        settings = SimpleNamespace(
            assistant_token_secret="secret",
            action_address="maia@sentinel.mondomaine.example",
            relay_host="relay",
            relay_port=25,
        )
        with patch(
            "sentimail_v3.conversation.assistant.aiosmtplib.send", new=_capture
        ):
            await _send_outbox(_Pool(), settings)  # type: ignore[arg-type]

        self.assertTrue(envois)
        envoye = str(envois[0])
        self.assertNotIn(ACTION_TOKEN_PLACEHOLDER, envoye)
        self.assertIn("S3-ACTION:", envoye)


class ApercuIntegreTests(unittest.TestCase):
    """La capture était une pièce jointe : il fallait l'ouvrir pour la voir.

    L'avis pose une question sur un message que le destinataire ne voit pas.
    La capture est la seule chose qui le lui montre : elle doit être dans le
    corps, au-dessus de ce qui gêne et de ce qui rassure, pas derrière un clic.
    """

    def _avec_apercu(self) -> str:
        return render_notice_html(dict(CONTEXTE, has_preview=True))

    def test_la_capture_est_une_image_du_corps(self) -> None:
        from sentimail_v3.conversation.review_notice import PREVIEW_CID

        self.assertIn(f'src="cid:{PREVIEW_CID}"', self._avec_apercu())

    def test_la_capture_precede_les_deux_colonnes(self) -> None:
        html = self._avec_apercu()
        self.assertLess(html.index("cid:"), html.index("Ce qui me gêne"))

    def test_la_capture_suit_le_bandeau_de_statut(self) -> None:
        # L'ordre de lecture : ce qui s'est passé, de qui vient le message,
        # puis à quoi il ressemble.
        html = self._avec_apercu()
        self.assertLess(html.index("Ce message n’a pas été livré"), html.index("cid:"))

    def test_sans_capture_aucune_image_morte_n_est_affichee(self) -> None:
        html = render_notice_html(dict(CONTEXTE, has_preview=False))
        self.assertNotIn("cid:", html)
        self.assertNotIn("<img", html)

    def test_l_avertissement_parle_de_l_image_affichee(self) -> None:
        # Le texte disait « l'image jointe » : il désigne désormais ce que le
        # destinataire a sous les yeux, sans quoi il la cherche en pièce jointe.
        html = self._avec_apercu()
        self.assertIn("photo du message", html)
        self.assertNotIn("L’image jointe", html)
