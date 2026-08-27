from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from aiosmtplib.errors import (
    SMTPRecipientRefused,
    SMTPRecipientsRefused,
    SMTPServerDisconnected,
)

from sentimail_v3.conversation.assistant import _send_outbox


def _item() -> dict[str, object]:
    return {
        "id": 1,
        "action_id": "11111111-1111-1111-1111-111111111111",
        "conversation_id": "22222222-2222-2222-2222-222222222222",
        "recipient": "millou@example.fr",
        "sender": "MAIA <maia@sentinel.example.org>",
        "reply_to": "maia@sentinel.example.org",
        "subject": "[SentiMail] Ton avis",
        "body_text": "corps",
        "body_html": None,
        "attempts": 1,
        "attachment_content": None,
        "attachment_filename": None,
        "attachment_content_type": None,
    }


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        assistant_token_secret="secret",
        action_address="maia@sentinel.example.org",
        relay_host="relay",
        relay_port=25,
    )


class _Pool:
    """Pool minimal : retient les écritures, sert un dossier au gardien."""

    def __init__(self, message_id: str | None = "message-id") -> None:
        self.message_id = message_id
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    async def fetchrow(self, query: str, *args: object) -> dict[str, object]:
        self.calls.append((query, args))
        return _item()

    async def execute(self, query: str, *args: object) -> str:
        self.calls.append((query, args))
        return "UPDATE 1"

    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        return self.message_id

    def wrote(self, fragment: str) -> list[tuple[str, tuple[object, ...]]]:
        return [call for call in self.calls if fragment in call[0]]


class OutboxPermanentRejectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_avis_refuse_definitivement_nest_plus_reessaye(self) -> None:
        pool = _Pool()
        refusal = SMTPRecipientsRefused(
            [SMTPRecipientRefused(550, "5.1.1 User unknown", "millou@example.fr")]
        )
        with patch(
            "sentimail_v3.conversation.assistant.aiosmtplib.send",
            new=AsyncMock(side_effect=refusal),
        ):
            await _send_outbox(pool, _settings())  # type: ignore[arg-type]

        written = pool.wrote("UPDATE assistant_outbox SET status=")
        self.assertTrue(written)
        for _, args in written:
            self.assertIn("undeliverable", args)

    async def test_un_avis_refuse_definitivement_clot_le_dossier(self) -> None:
        pool = _Pool()
        refusal = SMTPRecipientsRefused(
            [SMTPRecipientRefused(550, "5.1.1 User unknown", "millou@example.fr")]
        )
        with patch(
            "sentimail_v3.conversation.assistant.aiosmtplib.send",
            new=AsyncMock(side_effect=refusal),
        ):
            await _send_outbox(pool, _settings())  # type: ignore[arg-type]

        transitions = pool.wrote("UPDATE messages")
        self.assertEqual(len(transitions), 1)
        self.assertIn("undeliverable", transitions[0][1])

    async def test_une_coupure_du_relais_reste_a_reessayer(self) -> None:
        pool = _Pool()
        with patch(
            "sentimail_v3.conversation.assistant.aiosmtplib.send",
            new=AsyncMock(side_effect=SMTPServerDisconnected("coupure")),
        ):
            await _send_outbox(pool, _settings())  # type: ignore[arg-type]

        written = pool.wrote("UPDATE assistant_outbox SET status=")
        self.assertEqual(len(written), 1)
        self.assertIn("error", written[0][1])
        self.assertEqual(pool.wrote("UPDATE messages"), [])


if __name__ == "__main__":
    unittest.main()
