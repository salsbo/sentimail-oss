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
        if "instance_identity" in str(query):
            # Pas d'identité posée en base : celle des réglages sert.
            return None
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

    with patch("sentimail_v3.conversation.assistant.aiosmtplib.send", new=_capture):
        await _send_outbox(_Pool(avec_capture), _reglages())  # type: ignore[arg-type]
    assert envois, "aucun message envoyé"
    return envois[0]


def _reglages() -> SimpleNamespace:
    from sentimail_v3.identity import reset_cache

    reset_cache()
    return SimpleNamespace(
        assistant_token_secret="secret",
        action_address="maia@sentinel.mondomaine.example",
        action_aliases=(),
        assistant_sender="MAIA <maia@mondomaine.example>",
        probe_recipient="sonde@mondomaine.example",
        relay_host="relay",
        relay_port=25,
    )


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


class _PoolAvecMiniature(_Pool):
    """La miniature dans le corps, la capture pleine en pièce jointe."""

    async def fetchrow(self, query, *args):
        item = await super().fetchrow(query, *args)
        if item is None:
            return None
        item["inline_content"] = b"\xff\xd8\xff" + b"m" * 16
        item["inline_content_type"] = "image/jpeg"
        item["inline_filename"] = "apercu-email.jpg"
        return item


class CapturePleineJointeTests(unittest.IsolatedAsyncioTestCase):
    """La miniature sert à reconnaître ; pour lire, il faut l'image entière.

    Demande du 6 septembre 2026 : pouvoir agrandir la capture. Une image
    rattachée au corps ne s'ouvre pas en grand dans tous les clients ; la
    capture pleine repart donc en pièce jointe, à côté de la miniature.
    """

    async def _envoyer_avec_miniature(self):
        from sentimail_v3.conversation.assistant import _send_outbox

        envois: list[object] = []

        async def _capture(message, **kwargs):
            envois.append(message)
            return {}

        with patch("sentimail_v3.conversation.assistant.aiosmtplib.send", new=_capture):
            await _send_outbox(_PoolAvecMiniature(True), _reglages())  # type: ignore[arg-type]
        return envois[0]

    async def test_la_miniature_est_dans_le_corps_et_la_capture_en_piece_jointe(self) -> None:
        message = await self._envoyer_avec_miniature()
        inline = [p for p in message.walk() if p.get("Content-ID") == f"<{PREVIEW_CID}>"]
        self.assertEqual(len(inline), 1)
        self.assertEqual(inline[0].get_content_type(), "image/jpeg")
        jointes = [
            p for p in message.walk()
            if p.get_content_disposition() == "attachment" and p.get_content_type() == "image/png"
        ]
        self.assertEqual(len(jointes), 1)
        self.assertEqual(jointes[0].get_filename(), "message-en-grand.png")
        self.assertEqual(jointes[0].get_payload(decode=True), PNG)
