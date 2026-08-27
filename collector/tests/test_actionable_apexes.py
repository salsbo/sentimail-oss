from __future__ import annotations

import unittest

from sentimail_v3.observation.dossier.hooks.urls import UrlHook
from sentimail_v3.observation.dossier.models import InvestigationContext
from sentimail_v3.observation.parser import parse_message


def _context(html: str) -> InvestigationContext:
    raw = (
        "From: Service <no-reply@exemple.fr>\r\n"
        "To: Moi <me@mondomaine.example>\r\n"
        "Subject: Code\r\n"
        "Date: Tue, 11 Aug 2026 10:00:00 +0000\r\n"
        "Message-ID: <un@exemple.fr>\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        f"{html}\r\n"
    ).encode()
    return InvestigationContext(raw, parse_message(raw), "no-reply@exemple.fr", ["me@mondomaine.example"])


class ActionableApexTests(unittest.IsolatedAsyncioTestCase):
    async def test_seuls_les_liens_cliquables_sont_actionnables(self) -> None:
        """Une image sur un CDN n'est pas une destination : on ne clique pas dessus.

        Sans cette distinction, tout courrier transactionnel se voit refuser la
        voie rapide au motif que son logo est hébergé ailleurs.
        """
        _, facts = await UrlHook().observe(
            _context(
                '<img src="https://cdn-tiers.example-cdn.net/logo.png">'
                '<a href="https://exemple.fr/valider">Valider</a>'
            )
        )
        self.assertEqual(facts.get("actionable_apexes"), ["exemple.fr"])

    async def test_un_lien_cliquable_etranger_est_bien_actionnable(self) -> None:
        _, facts = await UrlHook().observe(
            _context('<a href="https://collecte.top/x">Cliquez</a>')
        )
        self.assertIn("collecte.top", facts.get("actionable_apexes") or [])

    async def test_un_domaine_qui_prefixe_une_marque_est_reduit_a_son_vrai_apex(
        self,
    ) -> None:
        """« openai.com.evil.top » se lit openai.com au premier coup d'oeil.

        Son apex reel est evil.top, et c'est lui qui doit ressortir : sinon un
        tel domaine passerait pour un voisin de la marque qu'il imite.
        """
        _, facts = await UrlHook().observe(
            _context('<a href="https://openai.com.evil.top/x">Se connecter</a>')
        )
        self.assertEqual(facts.get("actionable_apexes"), ["evil.top"])

    async def test_un_message_sans_lien_n_a_aucune_destination(self) -> None:
        _, facts = await UrlHook().observe(_context("<p>Votre code est 123456</p>"))
        self.assertEqual(facts.get("actionable_apexes"), [])
