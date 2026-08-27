from __future__ import annotations

import json
import os
import unittest

import asyncpg
from sentimail_v3.observation.deep_analysis import _learned_signals
from sentimail_v3.observation.storage import Store
from test_parser import RAW

SMTP = {
    "peer_ip": "172.20.0.13",
    "peer_port": 25,
    "helo": "mx.example",
    "protocol": "ESMTP",
    "tls": {},
    "authenticated": False,
    "mail_options": [],
    "rcpt_options": {},
}
PARTICIPANT = "learning@example.org"


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class LearnedSignalsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        self.created: list[str] = []

    async def asyncTearDown(self) -> None:
        await self.pool.execute(
            "DELETE FROM labels WHERE participant_email=$1", PARTICIPANT
        )
        await self.pool.execute(
            "DELETE FROM messages WHERE id = ANY($1::uuid[])", self.created
        )
        await self.pool.close()

    async def _message(self, recipient: str) -> str:
        result = await Store(self.pool).capture(
            RAW, "bounce@sender.example", [recipient], SMTP
        )
        self.created.append(result.message_id)
        return result.message_id

    async def _label(self, sender: str, label: str, signals: list[str]) -> None:
        await self.pool.execute(
            """
            INSERT INTO labels (
                source, label, confidence, is_ground_truth, context,
                sender_normalized, participant_email, subject
            ) VALUES ('smtp_feedback_user',$1,1,true,$2::jsonb,$3,$4,'témoin')
            """,
            label,
            json.dumps({"signals": signals}),
            sender,
            PARTICIPANT,
        )

    async def test_a_signal_confirmed_on_other_senders_is_reported(self) -> None:
        message_id = await self._message(PARTICIPANT)
        observed = [
            str(row["clue_code"])
            for row in await self.pool.fetch(
                """
                SELECT DISTINCT c.clue_code FROM clues c
                JOIN investigations i ON i.id=c.investigation_id
                WHERE i.message_id=$1::uuid AND c.direction <> 'neutral'
                """,
                message_id,
            )
        ]
        self.assertTrue(observed, "le message témoin doit porter des indices")
        code = observed[0]

        # Deux qualifications humaines portant ce meme indice, sur deux
        # expediteurs differents de celui du message courant.
        await self._label("first@spam.example", "spam", [code])
        await self._label("second@spam.example", "spam", [code])

        learned = await _learned_signals(self.pool, message_id, PARTICIPANT)
        reported = {item["clue_code"]: item for item in learned}
        self.assertIn(code, reported)
        self.assertEqual(reported[code]["confirmed_adverse"], 2)
        self.assertEqual(reported[code]["confirmed_legitimate"], 0)
        self.assertEqual(reported[code]["distinct_senders"], 2)

    async def test_a_single_confirmation_is_not_yet_a_profile(self) -> None:
        message_id = await self._message("learning-single@example.org")
        code = await self.pool.fetchval(
            """
            SELECT c.clue_code FROM clues c
            JOIN investigations i ON i.id=c.investigation_id
            WHERE i.message_id=$1::uuid AND c.direction <> 'neutral' LIMIT 1
            """,
            message_id,
        )
        await self._label("only@spam.example", "spam", [str(code)])
        learned = await _learned_signals(self.pool, message_id, PARTICIPANT)
        self.assertNotIn(str(code), {item["clue_code"] for item in learned})

    async def test_a_signal_present_everywhere_teaches_nothing(self) -> None:
        message_id = await self._message("learning-common@example.org")
        code = await self.pool.fetchval(
            """
            SELECT c.clue_code FROM clues c
            JOIN investigations i ON i.id=c.investigation_id
            WHERE i.message_id=$1::uuid AND c.direction <> 'neutral' LIMIT 1
            """,
            message_id,
        )
        # Autant de qualifications favorables que défavorables : l'indice
        # accompagne tout, il ne distingue rien.
        for index in range(3):
            await self._label(f"legit{index}@example.org", "legitimate", [str(code)])
            await self._label(f"spam{index}@example.org", "spam", [str(code)])
        learned = await _learned_signals(self.pool, message_id, PARTICIPANT)
        self.assertNotIn(str(code), {item["clue_code"] for item in learned})

    async def test_signals_never_leak_between_recipients(self) -> None:
        message_id = await self._message("learning-isolation@example.org")
        code = await self.pool.fetchval(
            """
            SELECT c.clue_code FROM clues c
            JOIN investigations i ON i.id=c.investigation_id
            WHERE i.message_id=$1::uuid AND c.direction <> 'neutral' LIMIT 1
            """,
            message_id,
        )
        await self._label("a@spam.example", "spam", [str(code)])
        await self._label("b@spam.example", "spam", [str(code)])
        learned = await _learned_signals(
            self.pool, message_id, "someone-else@example.org"
        )
        self.assertEqual(learned, [])


if __name__ == "__main__":
    unittest.main()


class LienMortTests(unittest.TestCase):
    def test_un_domaine_qui_ne_resout_pas_est_un_constat(self) -> None:
        from sentimail_v3.observation.deep_analysis import (
            _is_definitive_target_failure,
        )

        self.assertTrue(
            _is_definitive_target_failure("blocked_url:dns_resolution_failed")
        )

    def test_une_panne_de_notre_cote_reste_une_incompletude(self) -> None:
        from sentimail_v3.observation.deep_analysis import (
            _is_definitive_target_failure,
        )

        # Un timeout ou un refus de connexion peut venir de nous ou du reseau :
        # le doute reste, et la garantie de completude aussi.
        for erreur in ("ConnectError", "timeout", "blocked_url:private_network", None, ""):
            self.assertFalse(_is_definitive_target_failure(erreur), erreur)
