from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from sentimail_v3.supervision import probe
from sentimail_v3.supervision.probe import MARKER, _message, run_probe


def _settings(**overrides: object) -> SimpleNamespace:
    base = dict(
        probe_enabled=True,
        probe_recipient="sentinel-probe@mondomaine.example",
        probe_timeout_seconds=2,
        action_address="maia@sentinel.mondomaine.example",
        action_aliases=(),
        assistant_sender="MAIA <maia@mondomaine.example>",
        watchdog_ingress_host="collector",
        watchdog_ingress_port=2525,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class ProbeMessageTests(unittest.TestCase):
    def test_the_probe_carries_its_marker_and_a_technical_sender(self) -> None:
        raw = _message("abc123", "maia@sentinel.mondomaine.example", "sentinel-probe@mondomaine.example")
        self.assertIn(f"Subject: {MARKER} abc123", raw)
        self.assertIn("X-Sentinel-Probe: heartbeat", raw)
        self.assertIn("maia@sentinel.mondomaine.example", raw)
        # CRLF partout : un MTA n'aime pas les fins de ligne nues.
        self.assertNotIn("\n\n", raw.replace("\r\n", "\n").replace("\n", "\r\n"))


class ProbeRunTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_disabled_probe_does_nothing(self) -> None:
        pool = SimpleNamespace(fetchval=AsyncMock(), execute=AsyncMock())
        result = await run_probe(pool, _settings(probe_enabled=False))
        self.assertEqual(result["status"], "disabled")
        pool.execute.assert_not_awaited()

    async def test_a_captured_message_is_a_success_and_is_erased(self) -> None:
        pool = SimpleNamespace(
            fetchval=AsyncMock(return_value="msg-id"), execute=AsyncMock()
        )
        with patch.object(probe.aiosmtplib, "send", AsyncMock()):
            result = await run_probe(pool, _settings())
        self.assertEqual(result["status"], "ok")
        self.assertIn("latency_ms", result)
        # Le nettoyage part quoi qu'il arrive.
        pool.execute.assert_awaited_once()
        self.assertIn(MARKER, pool.execute.await_args.args[1])

    async def test_a_refused_send_is_a_down_result(self) -> None:
        pool = SimpleNamespace(fetchval=AsyncMock(), execute=AsyncMock())
        with patch.object(
            probe.aiosmtplib, "send", AsyncMock(side_effect=ConnectionError())
        ):
            result = await run_probe(pool, _settings())
        self.assertEqual(result["status"], "down")
        self.assertEqual(result["phase"], "send")
        # Envoi refusé : rien n'a été capturé, donc rien à nettoyer.
        pool.execute.assert_not_awaited()

    async def test_a_message_never_captured_is_down_and_still_cleaned(self) -> None:
        pool = SimpleNamespace(
            fetchval=AsyncMock(return_value=None), execute=AsyncMock()
        )
        with (
            patch.object(probe.aiosmtplib, "send", AsyncMock()),
            patch.object(probe.asyncio, "sleep", AsyncMock()),
        ):
            result = await run_probe(pool, _settings(probe_timeout_seconds=0))
        self.assertEqual(result["status"], "down")
        self.assertEqual(result["phase"], "capture")
        pool.execute.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
