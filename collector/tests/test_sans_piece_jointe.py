from __future__ import annotations

import unittest
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from types import SimpleNamespace
from unittest.mock import patch

from sentimail_v3.conversation.review_notice import PREVIEW_CID

ORIGINAL = b"\x89PNG\r\n\x1a\n" + b"O" * 4096
MINIATURE = b"\xff\xd8\xff" + b"m" * 256


class _Pool:
    async def fetchrow(self, query, *args):
        if "instance_identity" in str(query):
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
            "body_html": f'<p>a</p><img src="cid:{PREVIEW_CID}"><p>b</p>',
            "attempts": 1,
            "attachment_content": ORIGINAL,
            "attachment_filename": "capture-email-neutralisee.png",
            "attachment_content_type": "image/png",
            "inline_content": MINIATURE,
            "inline_filename": "apercu-email.jpg",
            "inline_content_type": "image/jpeg",
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


async def _envoyer():
    from sentimail_v3.conversation.assistant import _send_outbox

    envois = []

    async def _capture(message, **kwargs):
        envois.append(message)
        return {}

    from sentimail_v3.identity import reset_cache

    reset_cache()
    settings = SimpleNamespace(
        assistant_token_secret="secret",
        action_address="maia@sentinel.mondomaine.example",
        action_aliases=(),
        assistant_sender="MAIA <maia@mondomaine.example>",
        probe_recipient="sonde@mondomaine.example",
        relay_host="relay",
        relay_port=25,
    )
    with patch("sentimail_v3.conversation.assistant.aiosmtplib.send", new=_capture):
        await _send_outbox(_Pool(), settings)  # type: ignore[arg-type]
    return envois[0]


class PieceJointeEnGrandTests(unittest.IsolatedAsyncioTestCase):
    """La miniature dans le corps pour reconnaitre, l'original joint pour lire.

    L'original avait cesse de partir : il doublait le poids d'un avis pour un
    fichier que personne n'ouvrait. Le 6 septembre 2026 il est redemande - la
    miniature ne se lit pas et ne s'agrandit pas dans tous les clients. Il
    repart donc, une seule fois, sous un nom qui dit a quoi il sert.
    """

    async def test_la_seule_piece_jointe_est_le_message_en_grand(self) -> None:
        message = await _envoyer()
        jointes = [
            p for p in message.walk() if p.get_content_disposition() == "attachment"
        ]
        self.assertEqual([p.get_filename() for p in jointes], ["message-en-grand.png"])

    async def test_la_miniature_reste_affichee_dans_le_corps(self) -> None:
        message = await _envoyer()
        corps = [p for p in message.walk() if p.get("Content-ID") == f"<{PREVIEW_CID}>"]
        self.assertEqual(len(corps), 1)
        self.assertEqual(corps[0].get_payload(decode=True), MINIATURE)

    async def test_l_original_voyage_une_seule_fois(self) -> None:
        message = await _envoyer()
        charges = [p.get_payload(decode=True) for p in message.walk()]
        self.assertEqual(charges.count(ORIGINAL), 1)


class EnveloppeIndesirableTests(unittest.TestCase):
    """L'avis d'un message classé montre la photo et joint la capture pleine."""

    def _enveloppe(self, miniature=MINIATURE):
        from sentimail_v3.execution.delivery import build_junk_envelope

        brut = (
            b"From: Promo <promo@exemple.test>\r\nTo: moi@mondomaine.example\r\n"
            b"Subject: Offre\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body><p>x</p></body></html>\r\n"
        )
        rendu = build_junk_envelope(
            brut, "spam", reasons=["Aucune authentification."], lessons=[],
            preview=miniature, preview_content_type="image/jpeg",
            action_address="maia@sentinel.mondomaine.example",
            assistant_sender="MAIA <maia@mondomaine.example>", recipient="moi@mondomaine.example",
        )
        return BytesParser(policy=policy.default).parsebytes(rendu)

    def test_la_capture_est_dans_le_corps(self) -> None:
        corps = [
            p for p in self._enveloppe().walk()
            if p.get("Content-ID") == f"<{PREVIEW_CID}>"
        ]
        self.assertEqual(len(corps), 1)

    def test_sans_capture_pleine_aucune_piece_jointe(self) -> None:
        jointes = [
            p for p in self._enveloppe().walk()
            if p.get_content_disposition() == "attachment"
        ]
        self.assertEqual(jointes, [])

    def test_la_capture_pleine_est_jointe_pour_etre_lue_en_grand(self) -> None:
        from sentimail_v3.execution.delivery import build_junk_envelope

        brut = (
            b"From: Promo <promo@exemple.test>\r\nTo: moi@mondomaine.example\r\n"
            b"Subject: Offre\r\nContent-Type: text/plain\r\n\r\nx\r\n"
        )
        rendu = build_junk_envelope(
            brut, "spam", reasons=["r"], lessons=[], preview=MINIATURE,
            preview_content_type="image/jpeg", full_preview=ORIGINAL,
            action_address="maia@sentinel.mondomaine.example",
            assistant_sender="MAIA <maia@mondomaine.example>", recipient="moi@mondomaine.example",
        )
        enveloppe = BytesParser(policy=policy.default).parsebytes(rendu)
        jointes = [p for p in enveloppe.walk() if p.get_content_disposition() == "attachment"]
        self.assertEqual([p.get_filename() for p in jointes], ["message-en-grand.png"])
        self.assertEqual(jointes[0].get_payload(decode=True), ORIGINAL)
        html = enveloppe.get_body(preferencelist=("html",)).get_content()
        self.assertIn(">Objet<", html)
        self.assertIn("pièce jointe", html)
        texte = enveloppe.get_body(preferencelist=("plain",)).get_content()
        self.assertIn("L’image jointe est une photo inerte", texte)
        self.assertIn("A - Livrer dans ma boîte", texte)

    def test_sans_capture_l_enveloppe_part_quand_meme(self) -> None:
        # Le transfert est encodé : on lit la partie, pas la source brute.
        enveloppe = self._enveloppe(miniature=None)
        html = enveloppe.get_body(preferencelist=("html",))
        self.assertIn(">Motifs</div>", html.get_content())


if __name__ == "__main__":
    unittest.main()
