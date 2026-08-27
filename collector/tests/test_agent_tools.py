from __future__ import annotations

import os
import unittest

import asyncpg
from sentimail_v3.conversation.agent_tools import TOOLS, catalogue, run_tool
from sentimail_v3.observation.storage import Store
from test_parser import RAW

SMTP = {
    "peer_ip": "172.20.0.21",
    "peer_port": 25,
    "helo": "mx.example",
    "protocol": "ESMTP",
    "tls": {},
    "authenticated": False,
    "mail_options": [],
    "rcpt_options": {},
}
MINE = "moi@agent.test"
OTHER = "voisin@agent.test"


class CatalogueTests(unittest.TestCase):
    def test_every_tool_is_described(self) -> None:
        text = catalogue()
        for name in TOOLS:
            self.assertIn(name, text)

    def test_no_tool_can_write(self) -> None:
        # Le contrat tient dans les noms : rien qui suggere une mutation.
        for name in TOOLS:
            for verb in ("delete", "update", "release", "send", "set_", "import"):
                self.assertNotIn(verb, name)


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class ToolIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        self.created: list[str] = []
        self.mine = await self._message(MINE, "Facture de mon fournisseur")
        self.theirs = await self._message(OTHER, "Dossier confidentiel du voisin")

    async def asyncTearDown(self) -> None:
        await self.pool.execute(
            "DELETE FROM messages WHERE id = ANY($1::uuid[])", self.created
        )
        await self.pool.execute(
            "DELETE FROM sender_policies WHERE participant_email LIKE '%@agent.test'"
        )
        await self.pool.close()

    async def _message(self, recipient: str, subject: str) -> str:
        # Chaque boite recoit un message qui lui est propre : sans cela, le
        # test ne prouverait rien sur l'isolation.
        raw = (
            f"From: Expediteur <exp@{recipient.rsplit('@', 1)[-1]}>\r\n"
            f"To: {recipient}\r\n"
            f"Subject: {subject}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\n"
            "Corps sans importance.\r\n"
        ).encode()
        result = await Store(self.pool).capture(
            raw, f"bounce-{recipient}", [recipient], SMTP
        )
        self.created.append(result.message_id)
        return result.message_id

    async def test_a_tool_never_reaches_another_mailbox(self) -> None:
        mine = await run_tool(self.pool, "recent_messages", {}, participant=MINE)
        subjects = {item["subject"] for item in mine["messages"]}
        self.assertIn("Facture de mon fournisseur", subjects)
        # Le message du voisin existe bel et bien, mais pas ici.
        self.assertNotIn("Dossier confidentiel du voisin", subjects)
        theirs = await run_tool(self.pool, "recent_messages", {}, participant=OTHER)
        self.assertIn(
            "Dossier confidentiel du voisin",
            {item["subject"] for item in theirs["messages"]},
        )

    async def test_statistics_count_only_my_own_mail(self) -> None:
        mine = await run_tool(self.pool, "statistics", {}, participant=MINE)
        self.assertEqual(mine["received"], 1)

    async def test_explaining_someone_elses_message_finds_nothing(self) -> None:
        # Le fragment designe un message reel, mais d'une autre boite.
        answer = await run_tool(
            self.pool,
            "explain_message",
            {"subject": "Dossier confidentiel"},
            participant=MINE,
        )
        self.assertIn("error", answer)
        # Son proprietaire, lui, obtient bien son dossier.
        owner = await run_tool(
            self.pool,
            "explain_message",
            {"subject": "Dossier confidentiel"},
            participant=OTHER,
        )
        self.assertNotIn("error", owner)

    async def test_rules_are_never_shared_between_recipients(self) -> None:
        await self.pool.execute(
            """
            INSERT INTO sender_policies (
                participant_email, scope, value_normalized, action, active, source
            ) VALUES ($1,'sender','spam@ailleurs.test','hold',true,'test')
            """,
            OTHER,
        )
        mine = await run_tool(self.pool, "my_rules", {}, participant=MINE)
        self.assertEqual(mine["lists"], [])
        theirs = await run_tool(self.pool, "my_rules", {}, participant=OTHER)
        self.assertEqual(len(theirs["lists"]), 1)

    async def test_an_unknown_tool_is_refused(self) -> None:
        answer = await run_tool(self.pool, "drop_everything", {}, participant=MINE)
        self.assertIn("error", answer)

    async def test_without_an_identity_nothing_is_served(self) -> None:
        answer = await run_tool(self.pool, "recent_messages", {}, participant="")
        self.assertIn("error", answer)

    async def test_no_tool_returns_message_content(self) -> None:
        for name in TOOLS:
            answer = await run_tool(
                self.pool, name, {"subject": "Test"}, participant=MINE
            )
            serialized = str(answer)
            for leak in ("body_text", "body_html", "raw_eml"):
                self.assertNotIn(leak, serialized)


if __name__ == "__main__":
    unittest.main()
