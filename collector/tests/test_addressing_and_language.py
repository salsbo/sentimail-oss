from __future__ import annotations

import unittest

from sentimail_v3.observation.dossier.hooks.headers import HeadersHook
from sentimail_v3.observation.dossier.hooks.nature import NatureHook
from sentimail_v3.observation.dossier.models import InvestigationContext
from sentimail_v3.observation.parser import parse_message


def _context(raw: bytes, recipients: list[str]) -> InvestigationContext:
    return InvestigationContext(raw, parse_message(raw), "sender@example.org", recipients)


def _message(headers: str, body: str = "corps ordinaire") -> bytes:
    return (
        "From: Expediteur <sender@example.org>\r\n"
        f"{headers}"
        "Date: Tue, 11 Aug 2026 10:00:00 +0000\r\n"
        "Message-ID: <one@example.org>\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        f"{body}\r\n"
    ).encode()


async def _header_codes(raw: bytes, recipients: list[str]) -> dict[str, str]:
    clues, _ = await HeadersHook().observe(_context(raw, recipients))
    return {clue.clue_code: clue.direction for clue in clues}


async def _nature_codes(raw: bytes) -> dict[str, str]:
    clues, _ = await NatureHook().observe(_context(raw, ["me@mondomaine.example"]))
    return {clue.clue_code: clue.direction for clue in clues}


class BlindCopyTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_destinataire_absent_des_entetes_est_signale(self) -> None:
        """Recevoir un message qui ne vous nomme nulle part est un envoi en masse."""
        raw = _message("To: Quelqu'un <autre@example.net>\r\n")
        codes = await _header_codes(raw, ["me@mondomaine.example"])
        self.assertEqual(codes.get("HEADERS_RECIPIENT_NOT_ADDRESSED"), "adverse")

    async def test_un_destinataire_nomme_en_copie_ne_declenche_rien(self) -> None:
        raw = _message(
            "To: Quelqu'un <autre@example.net>\r\nCc: Moi <me@mondomaine.example>\r\n"
        )
        codes = await _header_codes(raw, ["me@mondomaine.example"])
        self.assertNotIn("HEADERS_RECIPIENT_NOT_ADDRESSED", codes)

    async def test_un_destinataire_nomme_dans_to_ne_declenche_rien(self) -> None:
        raw = _message("To: Moi <me@mondomaine.example>\r\n")
        codes = await _header_codes(raw, ["me@mondomaine.example"])
        self.assertNotIn("HEADERS_RECIPIENT_NOT_ADDRESSED", codes)

    async def test_une_liste_de_diffusion_declaree_ne_declenche_rien(self) -> None:
        # Une lettre d'information annonce ce qu'elle est : l'anonymat du
        # destinataire y est normal, et n'a rien d'une dissimulation.
        raw = _message(
            "To: Abonnes <news@example.org>\r\n"
            "List-Unsubscribe: <https://example.org/out>\r\n"
        )
        codes = await _header_codes(raw, ["me@mondomaine.example"])
        self.assertNotIn("HEADERS_RECIPIENT_NOT_ADDRESSED", codes)


class LanguageTests(unittest.IsolatedAsyncioTestCase):
    async def test_la_langue_du_message_est_constatee(self) -> None:
        raw = _message(
            "To: Moi <me@mondomaine.example>\r\nSubject: Urgent action required\r\n",
            "Dear customer, your account has been suspended and you must "
            "confirm your identity before the end of the day.",
        )
        clues, facts = await NatureHook().observe(_context(raw, ["me@mondomaine.example"]))
        self.assertEqual(facts.get("language"), "en")

    async def test_la_langue_constatee_devient_un_critere_etiquete(self) -> None:
        """Un fait qui n'est pas étiqueté n'entre ni au jugement ni à l'apprentissage."""
        raw = _message(
            "To: Moi <me@mondomaine.example>\r\nSubject: Urgent action required\r\n",
            "Dear customer, your account has been suspended and you must "
            "confirm your identity before the end of the day.",
        )
        clues, _ = await NatureHook().observe(_context(raw, ["me@mondomaine.example"]))
        langue = [c for c in clues if c.clue_code == "NATURE_MESSAGE_LANGUAGE"]
        self.assertEqual(len(langue), 1)
        self.assertEqual(langue[0].direction, "neutral")
        self.assertEqual(langue[0].facts.get("language"), "en")

    async def test_une_langue_francaise_est_reconnue(self) -> None:
        raw = _message(
            "To: Moi <me@mondomaine.example>\r\nSubject: Votre commande\r\n",
            "Bonjour, nous vous confirmons que votre commande a bien ete "
            "expediee et vous remercions de votre confiance.",
        )
        _, facts = await NatureHook().observe(_context(raw, ["me@mondomaine.example"]))
        self.assertEqual(facts.get("language"), "fr")


if __name__ == "__main__":
    unittest.main()
