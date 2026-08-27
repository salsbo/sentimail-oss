from __future__ import annotations

import os
import unittest
from dataclasses import replace

import asyncpg
from sentimail_v3.code.tenancy import Quota, forget_cache, quota_of
from sentimail_v3.config import load_settings
from sentimail_v3.conversation.assistant import _reserve_llm_call

DEFAULTS = Quota(
    assistant_hourly=20, assistant_daily=100, verdict_hourly=100, verdict_daily=500
)
GOURMAND = "gourmand.test"
VOISIN = "voisin.test"


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class QuotaResolutionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        forget_cache()
        await self.pool.execute(
            """
            INSERT INTO domains (fqdn, status, verified_at, assistant_hourly_limit)
            VALUES ($1,'active',now(),3)
            ON CONFLICT (fqdn) DO UPDATE SET assistant_hourly_limit=3
            """,
            GOURMAND,
        )
        await self.pool.execute(
            """
            INSERT INTO domains (fqdn, status, verified_at)
            VALUES ($1,'active',now()) ON CONFLICT (fqdn) DO NOTHING
            """,
            VOISIN,
        )

    async def asyncTearDown(self) -> None:
        await self.pool.execute(
            "DELETE FROM domains WHERE fqdn = ANY($1::text[])", [GOURMAND, VOISIN]
        )
        forget_cache()
        await self.pool.close()

    async def test_a_domain_without_limits_inherits_those_of_the_instance(self) -> None:
        quota = await quota_of(self.pool, VOISIN, DEFAULTS)
        self.assertEqual(quota, DEFAULTS)

    async def test_a_null_limit_is_not_an_absence_of_limit(self) -> None:
        # Le domaine gourmand n'a fixé que son plafond horaire : le reste suit
        # l'instance, il n'est pas illimité.
        quota = await quota_of(self.pool, GOURMAND, DEFAULTS)
        self.assertEqual(quota.assistant_hourly, 3)
        self.assertEqual(quota.assistant_daily, DEFAULTS.assistant_daily)
        self.assertEqual(quota.verdict_hourly, DEFAULTS.verdict_hourly)

    async def test_an_unknown_domain_gets_the_defaults(self) -> None:
        self.assertEqual(await quota_of(self.pool, "inconnu.test", DEFAULTS), DEFAULTS)
        self.assertEqual(await quota_of(self.pool, "", DEFAULTS), DEFAULTS)


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class QuotaIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        forget_cache()
        self.settings = replace(
            load_settings(),
            assistant_llm_hourly_limit=100,
            assistant_llm_daily_limit=500,
            assistant_llm_conversation_limit=100,
        )
        await self.pool.execute(
            """
            INSERT INTO domains (fqdn, status, verified_at, assistant_hourly_limit)
            VALUES ($1,'active',now(),2)
            ON CONFLICT (fqdn) DO UPDATE SET assistant_hourly_limit=2
            """,
            GOURMAND,
        )
        await self.pool.execute(
            """
            INSERT INTO domains (fqdn, status, verified_at)
            VALUES ($1,'active',now()) ON CONFLICT (fqdn) DO NOTHING
            """,
            VOISIN,
        )
        self.conversations: list[str] = []

    async def asyncTearDown(self) -> None:
        await self.pool.execute(
            "DELETE FROM conversations WHERE id = ANY($1::uuid[])", self.conversations
        )
        await self.pool.execute(
            "DELETE FROM domains WHERE fqdn = ANY($1::text[])", [GOURMAND, VOISIN]
        )
        forget_cache()
        await self.pool.close()

    async def _conversation(self, participant: str) -> str:
        value = await self.pool.fetchval(
            "INSERT INTO conversations (participant_email, status) "
            "VALUES ($1,'processing') RETURNING id::text",
            participant,
        )
        self.conversations.append(value)
        return value

    async def test_a_hungry_domain_never_starves_its_neighbour(self) -> None:
        # Deux utilisateurs distincts du domaine gourmand : le plafond est
        # commun, sans quoi il suffirait d'ouvrir des adresses pour le doubler.
        for address in (f"un@{GOURMAND}", f"deux@{GOURMAND}"):
            conversation = await self._conversation(address)
            event, refusal = await _reserve_llm_call(
                self.pool, self.settings, conversation, address
            )
            self.assertIsNone(refusal)
            self.assertIsNotNone(event)

        conversation = await self._conversation(f"trois@{GOURMAND}")
        event, refusal = await _reserve_llm_call(
            self.pool, self.settings, conversation, f"trois@{GOURMAND}"
        )
        self.assertEqual(refusal, "domain_hourly")
        self.assertIsNone(event)

        # Le voisin, lui, n'a rien consommé et reste servi.
        conversation = await self._conversation(f"quelqu-un@{VOISIN}")
        event, refusal = await _reserve_llm_call(
            self.pool, self.settings, conversation, f"quelqu-un@{VOISIN}"
        )
        self.assertIsNone(refusal)
        self.assertIsNotNone(event)

    async def test_the_user_ceiling_still_applies_inside_a_domain(self) -> None:
        settings = replace(self.settings, assistant_llm_hourly_limit=1)
        address = f"bavard@{VOISIN}"
        conversation = await self._conversation(address)
        _, refusal = await _reserve_llm_call(
            self.pool, settings, conversation, address
        )
        self.assertIsNone(refusal)
        conversation = await self._conversation(address)
        _, refusal = await _reserve_llm_call(
            self.pool, settings, conversation, address
        )
        self.assertEqual(refusal, "user_hourly")

    async def test_the_domain_is_recorded_on_the_event(self) -> None:
        address = f"trace@{VOISIN}"
        conversation = await self._conversation(address)
        await _reserve_llm_call(self.pool, self.settings, conversation, address)
        stored = await self.pool.fetchval(
            "SELECT domain_fqdn FROM llm_call_events WHERE conversation_id=$1::uuid",
            conversation,
        )
        # Sans cette colonne, aucun comptage par domaine n'est possible.
        self.assertEqual(stored, VOISIN)


if __name__ == "__main__":
    unittest.main()
