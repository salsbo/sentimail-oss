from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from aiosmtplib.errors import (
    SMTPRecipientRefused,
    SMTPRecipientsRefused,
    SMTPServerDisconnected,
)

from sentimail_v3.execution.delivery import (
    close_undeliverable_message,
    release_original,
)


class _Connection:
    def __init__(self, pool: "_Pool") -> None:
        self.pool = pool

    def transaction(self) -> "_Connection":
        return self

    async def __aenter__(self) -> "_Connection":
        return self

    async def __aexit__(self, *args: object) -> bool:
        return False

    async def fetchrow(self, query: str, *args: object) -> dict[str, object]:
        self.pool.calls.append((query, args))
        return {
            "delivery_status": "held",
            "raw_eml": b"Subject: test\r\n\r\ncorps\r\n",
            "envelope_from": "expediteur@example.com",
            "envelope_recipients": ["millou@example.fr"],
            "case_id": "case-id",
            "participant_email": "millou@example.fr",
        }

    async def execute(self, query: str, *args: object) -> str:
        return await self.pool.execute(query, *args)

    async def fetchval(self, query: str, *args: object) -> object:
        return await self.pool.fetchval(query, *args)


class _Pool:
    def __init__(self, moved: bool = True, current_status: str = "held") -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.moved = moved
        self.current_status = current_status

    def acquire(self) -> _Connection:
        return _Connection(self)

    async def execute(self, query: str, *args: object) -> str:
        self.calls.append((query, args))
        if "UPDATE messages" in query and not self.moved:
            return "UPDATE 0"
        return "UPDATE 1"

    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        return self.current_status

    def wrote(self, fragment: str) -> list[tuple[str, tuple[object, ...]]]:
        return [call for call in self.calls if fragment in call[0]]


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        raw_eml_key_file=None,
        assistant_token_secret="",
        relay_host="relay",
        relay_port=25,
        action_address="maia@sentinel.mondomaine.example",
        action_aliases=(),
        assistant_sender="MAIA <maia@mondomaine.example>",
        probe_recipient="probe@sentinel.mondomaine.example",
    )


def _permanent_refusal() -> SMTPRecipientsRefused:
    return SMTPRecipientsRefused(
        [SMTPRecipientRefused(550, "5.1.1 User unknown", "millou@example.fr")]
    )


class CloseUndeliverableTests(unittest.IsolatedAsyncioTestCase):
    async def test_la_cloture_solde_les_avis_du_dossier(self) -> None:
        """Un dossier clos ne doit plus laisser d'avis en erreur derrière lui."""
        pool = _Pool()

        result = await close_undeliverable_message(
            pool,  # type: ignore[arg-type]
            "message-id",
            reason="original_recipient_rejected",
        )

        self.assertEqual(result, "undeliverable")
        soldes = pool.wrote("UPDATE assistant_outbox")
        self.assertEqual(len(soldes), 1)
        self.assertIn("undeliverable", soldes[0][1])

    async def test_la_cloture_termine_un_dossier_deja_ferme(self) -> None:
        """Rejouée sur un dossier déjà clos, elle finit ce qui restait ouvert."""
        pool = _Pool(moved=False, current_status="undeliverable")

        result = await close_undeliverable_message(
            pool,  # type: ignore[arg-type]
            "message-id",
            reason="original_recipient_rejected",
        )

        self.assertEqual(result, "undeliverable")
        self.assertTrue(pool.wrote("UPDATE assistant_outbox"))

    async def test_la_cloture_ne_touche_pas_un_message_livre(self) -> None:
        pool = _Pool(moved=False, current_status="delivered")

        result = await close_undeliverable_message(
            pool,  # type: ignore[arg-type]
            "message-id",
            reason="original_recipient_rejected",
        )

        self.assertIsNone(result)
        self.assertEqual(pool.wrote("UPDATE assistant_outbox"), [])


class ReleaseOriginalFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_destinataire_inexistant_conclut_au_lieu_de_differer(self) -> None:
        """Différer un envoi que le relais refuse à jamais n'aboutit jamais."""
        pool = _Pool()
        with patch(
            "sentimail_v3.execution.delivery.aiosmtplib.send",
            new=AsyncMock(side_effect=_permanent_refusal()),
        ):
            with self.assertRaises(SMTPRecipientsRefused):
                await release_original(
                    pool,  # type: ignore[arg-type]
                    _settings(),  # type: ignore[arg-type]
                    "message-id",
                    reason="test",
                )

        transitions = pool.wrote("UPDATE messages")
        self.assertIn("undeliverable", transitions[-1][1])
        self.assertNotIn("deferred", transitions[-1][1])

    async def test_une_coupure_du_relais_reste_differee(self) -> None:
        pool = _Pool()
        with patch(
            "sentimail_v3.execution.delivery.aiosmtplib.send",
            new=AsyncMock(side_effect=SMTPServerDisconnected("coupure")),
        ):
            with self.assertRaises(SMTPServerDisconnected):
                await release_original(
                    pool,  # type: ignore[arg-type]
                    _settings(),  # type: ignore[arg-type]
                    "message-id",
                    reason="test",
                )

        transitions = pool.wrote("UPDATE messages")
        self.assertIn("deferred", transitions[-1][1])


if __name__ == "__main__":
    unittest.main()
