from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from sentimail_v3.observation.smtp_server import Handler
from sentimail_v3.observation.storage import CaptureResult


class SmtpDecisionTests(unittest.IsolatedAsyncioTestCase):
    async def test_multi_recipient_transaction_creates_one_case_per_recipient(self) -> None:
        store = SimpleNamespace(capture=AsyncMock())
        store.capture.side_effect = [
            CaptureResult("00000000-0000-0000-0000-000000000001", "captured", True),
            CaptureResult("00000000-0000-0000-0000-000000000002", "captured", True),
        ]
        conversations = SimpleNamespace(is_action_recipient=AsyncMock(return_value=False))
        settings = SimpleNamespace(decision_mode=True)
        handler = Handler(store, conversations, SimpleNamespace(), settings)
        session = SimpleNamespace(
            peer=("93.184.216.1", 2525),
            host_name="mx.example",
            extended_smtp=True,
            ssl=None,
            authenticated=False,
        )
        envelope = SimpleNamespace(
            original_content=(
                b"From: sender@example.net\r\n"
                b"To: one@example.org, two@example.org\r\n"
                b"Subject: test\r\n\r\nMessage\r\n"
            ),
            content=None,
            mail_from="sender@example.net",
            rcpt_tos=["one@example.org", "two@example.org"],
            mail_options=[],
            rcpt_options=[],
        )

        response = await handler.handle_DATA(None, session, envelope)  # type: ignore[arg-type]

        self.assertEqual(response, "250 2.0.0 stocke pour analyse par MAIA")
        self.assertEqual(store.capture.await_count, 2)
        self.assertEqual(store.capture.await_args_list[0].args[2], ["one@example.org"])
        self.assertEqual(store.capture.await_args_list[1].args[2], ["two@example.org"])


if __name__ == "__main__":
    unittest.main()
