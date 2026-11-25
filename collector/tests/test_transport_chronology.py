from __future__ import annotations

import unittest

from sentimail_v3.observation.dossier.hooks.transport import TransportHook
from sentimail_v3.observation.dossier.models import InvestigationContext
from sentimail_v3.observation.parser import parse_message


def _context(raw: bytes) -> InvestigationContext:
    return InvestigationContext(
        raw, parse_message(raw), "sender@example.org", ["me@mondomaine.example"]
    )


def _message(received: list[str]) -> bytes:
    lignes = "".join(f"Received: {value}\r\n" for value in received)
    return (
        lignes
        + "From: Expediteur <sender@example.org>\r\n"
        "To: Me <me@mondomaine.example>\r\n"
        "Date: Fri, 25 Sep 2026 12:51:20 +0000\r\n"
        "Message-ID: <one@example.org>\r\n"
        "\r\n"
        "corps\r\n"
    ).encode()


async def _codes(received: list[str]) -> dict[str, int]:
    clues, _ = await TransportHook().observe(_context(_message(received)))
    return {clue.clue_code: clue.strength for clue in clues}


class ChronologyToleranceTests(unittest.IsolatedAsyncioTestCase):
    async def test_decalage_infra_minute_tolere(self) -> None:
        # Cas M-6b35d8 (Huawei) : un relais tamponne 31 s avant celui d'avant,
        # horloges internes désynchronisées. En dessous d'une minute, on ne
        # compte pas d'incohérence.
        recu = await _codes(
            [
                "from a by b for <me@mondomaine.example>; "
                "Fri, 25 Sep 2026 20:50:49 +0800",
                "from c by a for <me@mondomaine.example>; "
                "Fri, 25 Sep 2026 20:51:20 +0800",
            ]
        )
        self.assertNotIn("RECEIVED_CHRONOLOGY_INCONSISTENT", recu)

    async def test_saut_franc_encore_detecte(self) -> None:
        # Un vrai saut en arrière (ici plus de deux minutes) reste signalé.
        recu = await _codes(
            [
                "from a by b for <me@mondomaine.example>; "
                "Fri, 25 Sep 2026 12:48:00 +0000",
                "from c by a for <me@mondomaine.example>; "
                "Fri, 25 Sep 2026 12:51:20 +0000",
            ]
        )
        self.assertIn("RECEIVED_CHRONOLOGY_INCONSISTENT", recu)

    async def test_ordre_normal_sans_incoherence(self) -> None:
        recu = await _codes(
            [
                "from a by b for <me@mondomaine.example>; "
                "Fri, 25 Sep 2026 12:51:25 +0000",
                "from c by a for <me@mondomaine.example>; "
                "Fri, 25 Sep 2026 12:51:20 +0000",
            ]
        )
        self.assertNotIn("RECEIVED_CHRONOLOGY_INCONSISTENT", recu)


if __name__ == "__main__":
    unittest.main()
