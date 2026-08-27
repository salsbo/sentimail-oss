from __future__ import annotations

import os
import unittest

import asyncpg
from sentimail_v3.code.tenancy import (
    domain_admin,
    domain_of,
    forget_cache,
    is_protected,
    protected_recipient,
)


class DomainOfTests(unittest.TestCase):
    def test_the_domain_is_read_from_any_written_form(self) -> None:
        self.assertEqual(domain_of("Alice <ALICE@Example.ORG>"), "example.org")
        self.assertEqual(domain_of("alice@example.org"), "example.org")
        self.assertEqual(domain_of(""), "")
        self.assertEqual(domain_of(None), "")
        self.assertEqual(domain_of("pas-une-adresse"), "")


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class TenancyIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        await self.pool.execute(
            "DELETE FROM domains WHERE fqdn LIKE '%.tenancy.test'"
        )
        forget_cache()

    async def asyncTearDown(self) -> None:
        await self.pool.execute(
            "DELETE FROM domains WHERE fqdn LIKE '%.tenancy.test'"
        )
        forget_cache()
        await self.pool.close()

    async def _enrol(self, fqdn: str, status: str, admin: str | None = None) -> None:
        await self.pool.execute(
            """
            INSERT INTO domains (fqdn, status, admin_email, verified_at)
            VALUES ($1,$2,$3,now())
            ON CONFLICT (fqdn) DO UPDATE SET status=EXCLUDED.status,
                admin_email=EXCLUDED.admin_email
            """,
            fqdn,
            status,
            admin,
        )
        forget_cache()

    async def test_every_recipient_of_an_active_domain_is_protected(self) -> None:
        await self._enrol("active.tenancy.test", "active", "admin@active.tenancy.test")
        self.assertTrue(await is_protected(self.pool, "someone@active.tenancy.test"))
        self.assertTrue(await is_protected(self.pool, "Autre <AUTRE@Active.Tenancy.Test>"))

    async def test_a_pending_or_suspended_domain_protects_nobody(self) -> None:
        await self._enrol("pending.tenancy.test", "pending")
        await self._enrol("stopped.tenancy.test", "suspended")
        self.assertFalse(await is_protected(self.pool, "a@pending.tenancy.test"))
        self.assertFalse(await is_protected(self.pool, "a@stopped.tenancy.test"))

    async def test_an_unknown_domain_is_never_protected(self) -> None:
        self.assertFalse(await is_protected(self.pool, "a@inconnu.tenancy.test"))

    async def test_the_conversation_belongs_to_the_protected_recipient(self) -> None:
        await self._enrol("active.tenancy.test", "active")
        chosen = await protected_recipient(
            self.pool,
            ["tiers@ailleurs.tenancy.test", "moi@active.tenancy.test"],
        )
        self.assertEqual(chosen, "moi@active.tenancy.test")

    async def test_without_any_active_domain_nobody_is_designated(self) -> None:
        self.assertIsNone(
            await protected_recipient(
                self.pool, ["a@inconnu.tenancy.test", "b@autre.tenancy.test"]
            )
        )

    async def test_each_domain_carries_its_own_contact(self) -> None:
        await self._enrol("first.tenancy.test", "active", "chef@first.tenancy.test")
        await self._enrol("second.tenancy.test", "active", "chef@second.tenancy.test")
        self.assertEqual(
            await domain_admin(self.pool, "user@first.tenancy.test"),
            "chef@first.tenancy.test",
        )
        self.assertEqual(
            await domain_admin(self.pool, "user@second.tenancy.test"),
            "chef@second.tenancy.test",
        )
        self.assertIsNone(await domain_admin(self.pool, "user@inconnu.tenancy.test"))

    async def test_an_unproven_domain_protects_nobody(self) -> None:
        await self.pool.execute(
            """
            INSERT INTO domains (fqdn, status, verified_at)
            VALUES ('unproven.tenancy.test','active',NULL)
            ON CONFLICT (fqdn) DO UPDATE SET status='active', verified_at=NULL
            """
        )
        forget_cache()
        self.assertFalse(await is_protected(self.pool, "a@unproven.tenancy.test"))

    async def test_activation_takes_effect_without_a_restart(self) -> None:
        self.assertFalse(await is_protected(self.pool, "a@late.tenancy.test"))
        await self._enrol("late.tenancy.test", "active")
        self.assertTrue(await is_protected(self.pool, "a@late.tenancy.test"))


if __name__ == "__main__":
    unittest.main()
