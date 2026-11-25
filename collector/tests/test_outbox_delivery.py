from __future__ import annotations

from contextlib import asynccontextmanager
import unittest
import json
from email import message_from_bytes
from urllib.parse import unquote
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from aiosmtplib.errors import (
    SMTPRecipientRefused,
    SMTPRecipientsRefused,
    SMTPServerDisconnected,
)

from sentimail_v3.conversation.assistant import _send_outbox
from sentimail_v3.conversation.action_tokens import ACTION_MARKER_RE


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

    @asynccontextmanager
    async def acquire(self):
        yield self

    @asynccontextmanager
    async def transaction(self):
        yield self

    async def fetchrow(self, query: str, *args: object) -> dict[str, object]:
        self.calls.append((query, args))
        if "FROM instance_identity" in query:
            return {"action_address": "maia@sentinel.example.org", "action_aliases": [],
                    "assistant_sender": "MAIA <maia@sentinel.example.org>",
                    "probe_recipient": "probe@example.org"}
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
    async def test_les_liens_de_lots_sont_authentifies_avant_le_smtp(self):
        pool = _Pool()
        item = dict(_item(), body_html=(
            '<a href="mailto:maia@example.org?subject=Re%20S3-BALLOT-1-TOKEN-PLACEHOLDER&amp;body=un">1</a>'
            '<a href="mailto:maia@example.org?subject=Re%20S3-BALLOT-2-TOKEN-PLACEHOLDER&amp;body=deux">2</a>'
        ))
        context = {"purpose": "daily_digest", "conversation_id": item["conversation_id"],
                   "digest_ref": "D-abcdef", "digest": {"1": "message1", "2": "message2"}}
        pool.fetchval = AsyncMock(side_effect=[json.dumps(context), "child1", "child2"])
        async def inspect_smtp(raw, **kwargs):
            email = message_from_bytes(raw) if isinstance(raw, bytes) else raw
            html = next(part for part in email.walk() if part.get_content_type() == "text/html")
            rendered = html.get_payload(decode=True).decode("utf-8")
            self.assertEqual(len(set(ACTION_MARKER_RE.findall(unquote(rendered)))), 2)
            self.assertNotIn("TOKEN-PLACEHOLDER", rendered)
            # Le transport est simulé : aucun courrier ne part dans ce test.
            raise SMTPServerDisconnected("simulation")
        with patch("sentimail_v3.conversation.assistant._claim_outbox", AsyncMock(return_value=item)), patch(
            "sentimail_v3.conversation.assistant.aiosmtplib.send", AsyncMock(side_effect=inspect_smtp)
        ) as smtp:
            await _send_outbox(pool, _settings())
        smtp.assert_awaited_once()

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


class ObjetSurUneLigneTests(unittest.IsolatedAsyncioTestCase):
    """Un objet repris d'un message piégé ne fait plus tomber le service.

    L'objet de l'avis reprend celui du message retenu. Un mot encodé décodé en
    saut de ligne y restait : la bibliothèque refusait de poser l'en-tête,
    hors de tout bloc de rattrapage, et c'est le service assistant entier qui
    s'arrêtait, cinq fois de suite.
    """

    async def test_un_objet_a_saut_de_ligne_part_sur_une_ligne(self) -> None:
        pool = _Pool()
        item = dict(_item(), subject="[SentiMail] Ton avis sur : Voyage\n\n")
        with patch(
            "sentimail_v3.conversation.assistant._claim_outbox",
            AsyncMock(return_value=item),
        ), patch(
            "sentimail_v3.conversation.assistant.aiosmtplib.send",
            AsyncMock(return_value=({}, "250 2.0.0 Ok: queued as ABC123")),
        ) as smtp:
            await _send_outbox(pool, _settings())  # type: ignore[arg-type]

        smtp.assert_awaited_once()
        envoye = smtp.await_args.args[0]
        self.assertEqual(str(envoye["Subject"]), "[SentiMail] Ton avis sur : Voyage")


if __name__ == "__main__":
    unittest.main()
