from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from sentimail_v3.conversation.review_notice import PREVIEW_CID

PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 64


class _Pool:
    """La file d'envoi réduite à un seul avis, capture comprise."""

    def __init__(self, avec_capture: bool) -> None:
        self._avec_capture = avec_capture

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
            "body_html": f'<p>avant</p><img src="cid:{PREVIEW_CID}"><p>après</p>',
            "attempts": 1,
            "attachment_content": PNG if self._avec_capture else None,
            "attachment_filename": (
                "capture-email-neutralisee.png" if self._avec_capture else None
            ),
            "attachment_content_type": "image/png" if self._avec_capture else None,
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


async def _envoyer(avec_capture: bool):
    from sentimail_v3.conversation.assistant import _send_outbox

    envois: list[object] = []

    async def _capture(message, **kwargs):
        envois.append(message)
        return {}

    settings = SimpleNamespace(
        assistant_token_secret="secret",
        action_address="maia@sentinel.mondomaine.example",
        relay_host="relay",
        relay_port=25,
    )
    with patch("sentimail_v3.conversation.assistant.aiosmtplib.send", new=_capture):
        await _send_outbox(_Pool(avec_capture), settings)  # type: ignore[arg-type]
    assert envois, "aucun message envoyé"
    return envois[0]


class CaptureIntegreeTests(unittest.IsolatedAsyncioTestCase):
    """La capture était une pièce jointe : l'avis parlait d'un message invisible.

    Elle doit maintenant être rattachée au corps sous l'identifiant que la page
    HTML référence, sans quoi le client de messagerie affiche une image cassée.
    """

    async def test_la_capture_porte_l_identifiant_reference_par_la_page(self) -> None:
        message = await _envoyer(True)
        identifiants = [
            part.get("Content-ID")
            for part in message.walk()
            if part.get("Content-ID")
        ]
        self.assertIn(f"<{PREVIEW_CID}>", identifiants)

    async def test_la_capture_reste_atteignable_comme_fichier(self) -> None:
        # Un client qui n'affiche pas les images doit quand même pouvoir
        # l'ouvrir : la partie garde donc un nom de fichier.
        message = await _envoyer(True)
        noms = [part.get_filename() for part in message.walk()]
        self.assertIn("capture-email-neutralisee.png", noms)

    async def test_la_capture_n_est_pas_envoyee_deux_fois(self) -> None:
        message = await _envoyer(True)
        images = [
            part for part in message.walk() if part.get_content_type() == "image/png"
        ]
        self.assertEqual(len(images), 1, "la capture est dupliquée dans le message")

    async def test_la_page_html_accompagne_la_capture(self) -> None:
        message = await _envoyer(True)
        types = {part.get_content_type() for part in message.walk()}
        self.assertIn("text/html", types)
        self.assertIn("text/plain", types)

    async def test_sans_capture_le_message_part_quand_meme(self) -> None:
        message = await _envoyer(False)
        types = {part.get_content_type() for part in message.walk()}
        self.assertIn("text/html", types)
        self.assertNotIn("image/png", types)


if __name__ == "__main__":
    unittest.main()
