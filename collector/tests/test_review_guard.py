from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from sentimail_v3.execution.review_guard import (
    abandon_undeliverable_notice,
    fail_open_for_exhausted_outbox,
    hold_with_review_or_fail_open,
    reconcile_one_review_hold,
)


class _RecordingPool:
    """Un pool qui retient ce qui a été écrit, sans base derrière."""

    def __init__(self, message_id: str | None) -> None:
        self.message_id = message_id
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    async def execute(self, query: str, *args: object) -> str:
        self.calls.append((query, args))
        return "UPDATE 1"

    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        return self.message_id

    def wrote(self, fragment: str) -> list[tuple[str, tuple[object, ...]]]:
        return [call for call in self.calls if fragment in call[0]]


class UndeliverableNoticeTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_avis_refuse_definitivement_clot_le_dossier(self) -> None:
        """Sans boîte où écrire, on ferme : ni nouvel envoi, ni attente sans fin."""
        pool = _RecordingPool("message-id")

        result = await abandon_undeliverable_notice(
            pool,  # type: ignore[arg-type]
            "action-id",
            error="550 5.1.1 User unknown",
        )

        self.assertEqual(result, "undeliverable")
        transitions = pool.wrote("UPDATE messages")
        self.assertEqual(len(transitions), 1)
        self.assertIn("undeliverable", transitions[0][1])
        self.assertTrue(pool.wrote("UPDATE smtp_actions"))
        self.assertTrue(pool.wrote("INSERT INTO audit_log"))

    async def test_un_avis_sans_dossier_ouvert_ne_clot_rien(self) -> None:
        pool = _RecordingPool(None)

        result = await abandon_undeliverable_notice(
            pool,  # type: ignore[arg-type]
            "action-id",
            error="550 5.1.1 User unknown",
        )

        self.assertIsNone(result)
        self.assertEqual(pool.wrote("UPDATE messages"), [])


class ReviewGuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_successful_notice_protects_hold(self) -> None:
        pool = SimpleNamespace(execute=AsyncMock())
        invitations = SimpleNamespace(queue_invitation=AsyncMock(return_value=True))

        result = await hold_with_review_or_fail_open(
            pool,  # type: ignore[arg-type]
            SimpleNamespace(),  # type: ignore[arg-type]
            invitations,  # type: ignore[arg-type]
            "message-id",
        )

        self.assertEqual(result, "review_notice_queued")
        invitations.queue_invitation.assert_awaited_once_with(
            "message-id", decision_mode=True
        )

    async def test_notice_construction_failure_delivers_original_fail_open(self) -> None:
        pool = SimpleNamespace(execute=AsyncMock())
        invitations = SimpleNamespace(
            queue_invitation=AsyncMock(side_effect=NameError("renderer failed"))
        )
        with patch(
            "sentimail_v3.execution.review_guard.fail_open_held_message",
            new=AsyncMock(return_value="released"),
        ) as fail_open:
            result = await hold_with_review_or_fail_open(
                pool,  # type: ignore[arg-type]
                SimpleNamespace(),  # type: ignore[arg-type]
                invitations,  # type: ignore[arg-type]
                "message-id",
            )

        self.assertEqual(result, "released")
        fail_open.assert_awaited_once()
        self.assertEqual(
            fail_open.await_args.kwargs["reason"],
            "review_notice_queue_failed_fail_open",
        )

    async def test_false_queue_result_delivers_original_fail_open(self) -> None:
        pool = SimpleNamespace(execute=AsyncMock())
        invitations = SimpleNamespace(queue_invitation=AsyncMock(return_value=False))
        with patch(
            "sentimail_v3.execution.review_guard.fail_open_held_message",
            new=AsyncMock(return_value="released"),
        ) as fail_open:
            result = await hold_with_review_or_fail_open(
                pool,  # type: ignore[arg-type]
                SimpleNamespace(),  # type: ignore[arg-type]
                invitations,  # type: ignore[arg-type]
                "message-id",
            )

        self.assertEqual(result, "released")
        self.assertEqual(
            fail_open.await_args.kwargs["reason"],
            "review_notice_not_queued_fail_open",
        )

    async def test_reconciler_recreates_a_missing_review_notice(self) -> None:
        pool = SimpleNamespace(
            fetchval=AsyncMock(return_value="message-id"),
            fetchrow=AsyncMock(),
            execute=AsyncMock(),
        )
        invitations = SimpleNamespace(queue_invitation=AsyncMock(return_value=True))

        worked = await reconcile_one_review_hold(
            pool,  # type: ignore[arg-type]
            SimpleNamespace(),  # type: ignore[arg-type]
            invitations,  # type: ignore[arg-type]
        )

        self.assertTrue(worked)
        invitations.queue_invitation.assert_awaited_once_with(
            "message-id", decision_mode=True
        )

    async def test_exhausted_review_delivery_releases_original(self) -> None:
        pool = SimpleNamespace(fetchval=AsyncMock(return_value="message-id"))
        with patch(
            "sentimail_v3.execution.review_guard.fail_open_held_message",
            new=AsyncMock(return_value="released"),
        ) as fail_open:
            result = await fail_open_for_exhausted_outbox(
                pool,  # type: ignore[arg-type]
                SimpleNamespace(),  # type: ignore[arg-type]
                "action-id",
            )

        self.assertEqual(result, "released")
        self.assertEqual(
            fail_open.await_args.kwargs["reason"],
            "review_notice_delivery_exhausted_fail_open",
        )


if __name__ == "__main__":
    unittest.main()
