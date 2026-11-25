from __future__ import annotations

import asyncio
import re
import socket
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from aiosmtpd.smtp import SMTP

from sentimail_v3.observation import recipient_check
from sentimail_v3.observation.recipient_check import (
    PROBE_LOCAL_PART,
    UNKNOWN_RECIPIENT_REPLY,
    UNVERIFIED_PROBE_REPLY,
    ProbeResult,
    downstream_answer,
    is_probe,
    probe_outcome,
)
from sentimail_v3.observation.smtp_server import Handler

PROBE_SENDER = "sentimail-verification@mx.example"
MAIN_CF = Path(__file__).resolve().parents[2] / "infra" / "postfix" / "main.cf.tmpl"


class _Downstream:
    """Serveur de boîtes factice : une réponse par partie locale."""

    def __init__(self) -> None:
        self.senders: list[str] = []

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        del server, session, mail_options
        self.senders.append(address)
        envelope.mail_from = address
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        del server, session, rcpt_options
        local = address.partition("@")[0]
        if local == "unknown":
            return "550 5.1.1 <unknown@example.org>: User unknown"
        if local == "policy":
            return "554 5.7.1 <policy@example.org>: Relay access denied"
        if local == "busy":
            return "451 4.3.0 try later"
        if local == "slow":
            await asyncio.sleep(2)
        envelope.rcpt_tos.append(address)
        return "250 OK"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class DownstreamAnswerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.downstream = _Downstream()
        loop = asyncio.get_running_loop()
        self.server = await loop.create_server(
            lambda: SMTP(self.downstream, hostname="boites.example"),
            host="127.0.0.1",
            port=0,
        )
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def _answer(self, local: str, timeout: float = 4.0):
        return await downstream_answer(
            f"{local}@example.org", host="127.0.0.1", port=self.port, timeout=timeout
        )

    async def test_answers_are_reported_with_code_and_text(self) -> None:
        self.assertEqual((await self._answer("someone"))[0], 250)
        code, message = await self._answer("unknown")
        self.assertEqual(code, 550)
        self.assertTrue(message.startswith("5.1.1"))
        self.assertEqual((await self._answer("policy"))[0], 554)
        self.assertEqual((await self._answer("busy"))[0], 451)
        # La question est posée sans expéditeur : aucun avis ne peut en naître.
        self.assertEqual(self.downstream.senders, ["<>"] * 4)

    async def test_whole_exchange_is_bounded(self) -> None:
        started = time.monotonic()
        self.assertIsNone(await self._answer("slow", timeout=0.5))
        # Sans réponse, la connexion est coupée sans QUIT : la borne tient.
        self.assertLess(time.monotonic() - started, 0.8)

    async def test_mute_relay_is_bounded(self) -> None:
        async def mute(reader, writer):
            await asyncio.sleep(5)
            writer.close()

        server = await asyncio.start_server(mute, host="127.0.0.1", port=0)
        port = server.sockets[0].getsockname()[1]
        started = time.monotonic()
        try:
            answer = await downstream_answer(
                "someone@example.org", host="127.0.0.1", port=port, timeout=0.5
            )
        finally:
            server.close()
        self.assertIsNone(answer)
        self.assertLess(time.monotonic() - started, 0.8)

    async def test_internationalised_address_is_not_asked(self) -> None:
        self.assertIsNone(
            await downstream_answer("josé@example.org", host="127.0.0.1", port=self.port)
        )
        self.assertEqual(self.downstream.senders, [])

    async def test_unreachable_relay_gives_no_answer(self) -> None:
        answer = await downstream_answer(
            "someone@example.org", host="127.0.0.1", port=_free_port(), timeout=1.0
        )
        self.assertIsNone(answer)


class ProbeOutcomeTests(unittest.IsolatedAsyncioTestCase):
    def _deps(self, *, protected: bool = True, own: bool = False):
        pool = SimpleNamespace(fetchval=AsyncMock(return_value=1 if protected else None))
        conversations = SimpleNamespace(is_action_recipient=AsyncMock(return_value=own))
        return pool, conversations

    async def _ask(self, pool, conversations, *, sender=PROBE_SENDER, answer=(250, "2.1.5 Ok")):
        with patch.object(
            recipient_check, "downstream_answer", AsyncMock(return_value=answer)
        ) as asked:
            result = await probe_outcome(
                pool,
                conversations,
                sender=sender,
                address="person@example.org",
                relay_host="relay",
                relay_port=10027,
            )
        return result, asked

    def test_probe_sender_is_recognised_by_local_part(self) -> None:
        self.assertTrue(is_probe("sentimail-verification@mx.example"))
        self.assertTrue(is_probe("Sentimail-Verification@other.example"))
        self.assertFalse(is_probe(""))
        self.assertFalse(is_probe("<>"))
        self.assertFalse(is_probe("sender@example.net"))
        self.assertFalse(is_probe("double-bounce@mx.example"))

    def test_probe_sender_matches_the_mx_configuration(self) -> None:
        if not MAIN_CF.exists():
            self.skipTest("configuration Postfix absente de cet environnement")
        text = MAIN_CF.read_text(encoding="utf-8")
        match = re.search(r"^address_verify_sender\s*=\s*(\S+)", text, re.M)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), PROBE_LOCAL_PART)
        # L'expéditeur réservé à l'entrée du MX est le même.
        self.assertIn(
            f"check_sender_access regexp:{{{{/^{PROBE_LOCAL_PART}@/ REJECT", text
        )

    async def test_real_message_is_never_checked(self) -> None:
        pool, conversations = self._deps()
        result, asked = await self._ask(
            pool, conversations, sender="x@example.net", answer=(550, "5.1.1 unknown")
        )
        self.assertEqual(result.outcome, "not_probe")
        asked.assert_not_awaited()
        pool.fetchval.assert_not_awaited()

    async def test_only_a_definitive_address_refusal_is_unknown(self) -> None:
        pool, conversations = self._deps()
        cases = {
            (550, "5.1.1 <person@example.org>: User unknown"): "unknown",
            (250, "2.1.5 Ok"): "known",
            (554, "5.7.1 Relay access denied"): "unverified",
            (550, "mailbox unavailable"): "unverified",
            (451, "4.3.0 try later"): "unverified",
            None: "unverified",
        }
        for answer, expected in cases.items():
            result, _ = await self._ask(pool, conversations, answer=answer)
            self.assertEqual(result.outcome, expected, answer)
        result, _ = await self._ask(pool, conversations, answer=(550, "5.1.1 User unknown"))
        self.assertEqual(result.detail, "550 5.1.1")
        # Sans statut étendu, le premier mot peut être l'adresse : il n'est pas gardé.
        result, _ = await self._ask(
            pool, conversations, answer=(550, "<person@example.org>: User unknown")
        )
        self.assertEqual(result.detail, "550")

    async def test_unprotected_domain_and_own_address_are_not_asked(self) -> None:
        pool, conversations = self._deps(protected=False)
        result, asked = await self._ask(pool, conversations, answer=(550, "5.1.1 x"))
        self.assertEqual(result.outcome, "not_protected")
        asked.assert_not_awaited()

        pool, conversations = self._deps(own=True)
        result, asked = await self._ask(pool, conversations, answer=(550, "5.1.1 x"))
        self.assertEqual(result.outcome, "own_address")
        asked.assert_not_awaited()

    async def test_database_failure_lets_the_recipient_through(self) -> None:
        pool = SimpleNamespace(fetchval=AsyncMock(side_effect=OSError("db down")))
        conversations = SimpleNamespace(is_action_recipient=AsyncMock(return_value=False))
        result, asked = await self._ask(pool, conversations, answer=(550, "5.1.1 x"))
        self.assertEqual(result, ProbeResult("error", "OSError"))
        asked.assert_not_awaited()


class HandlerRcptTests(unittest.IsolatedAsyncioTestCase):
    def _handler(self) -> Handler:
        store = SimpleNamespace(pool=SimpleNamespace())
        conversations = SimpleNamespace()
        settings = SimpleNamespace(relay_host="relay", relay_port=10027)
        return Handler(store, conversations, SimpleNamespace(), settings)  # type: ignore[arg-type]

    @staticmethod
    def _envelope(sender: str) -> SimpleNamespace:
        return SimpleNamespace(mail_from=sender, rcpt_tos=[], rcpt_options=[])

    async def _rcpt(self, envelope, outcome, address="person@example.org"):
        with patch("sentimail_v3.observation.smtp_server.probe_outcome", outcome):
            return await self._handler().handle_RCPT(
                None, None, envelope, address, ["NOTIFY=NEVER"]  # type: ignore[arg-type]
            )

    async def test_unknown_probe_recipient_is_refused(self) -> None:
        envelope = self._envelope(PROBE_SENDER)
        reply = await self._rcpt(
            envelope,
            AsyncMock(return_value=ProbeResult("unknown", "550 5.1.1")),
            address="unknown@example.org",
        )
        self.assertEqual(reply, UNKNOWN_RECIPIENT_REPLY)
        self.assertEqual(envelope.rcpt_tos, [])

    async def test_other_outcomes_accept_as_before(self) -> None:
        for outcome in ("not_probe", "known", "own_address", "not_protected"):
            envelope = self._envelope("x@example.net")
            reply = await self._rcpt(envelope, AsyncMock(return_value=ProbeResult(outcome)))
            self.assertEqual(reply, "250 OK", outcome)
            self.assertEqual(envelope.rcpt_tos, ["person@example.org"])
            self.assertEqual(envelope.rcpt_options, ["NOTIFY=NEVER"])

    async def test_probe_without_sure_answer_is_deferred_never_accepted(self) -> None:
        # Un 250 ferait tenir l'adresse pour connue 31 jours par le MX.
        for outcome in ("unverified", "error"):
            envelope = self._envelope(PROBE_SENDER)
            reply = await self._rcpt(envelope, AsyncMock(return_value=ProbeResult(outcome)))
            self.assertEqual(reply, UNVERIFIED_PROBE_REPLY, outcome)
            self.assertTrue(reply.startswith("4"))
            self.assertEqual(envelope.rcpt_tos, [])

    async def test_unexpected_exception_never_becomes_a_refusal(self) -> None:
        failure = UnicodeEncodeError("ascii", "josé", 3, 4, "ordinal not in range")
        envelope = self._envelope(PROBE_SENDER)
        reply = await self._rcpt(envelope, AsyncMock(side_effect=failure))
        self.assertEqual(reply, UNVERIFIED_PROBE_REPLY)

        envelope = self._envelope("x@example.net")
        reply = await self._rcpt(envelope, AsyncMock(side_effect=failure))
        self.assertEqual(reply, "250 OK")
        self.assertEqual(envelope.rcpt_tos, ["person@example.org"])

if __name__ == "__main__":
    unittest.main()
