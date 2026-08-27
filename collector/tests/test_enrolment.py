from __future__ import annotations

import os
import unittest

import asyncpg
from sentimail_v3.code.enrolment import (
    NXDOMAIN,
    RESOLUTION_FAILED,
    TOKEN_ABSENT,
    TOKEN_MISMATCH,
    UNKNOWN_DOMAIN,
    VERIFIED,
    load_domain,
    matches_token,
    normalize_fqdn,
    verify_domain,
)

# Valeur factice : le jeton reel est genere en base, jamais ecrit ici.
TOKEN = "jeton-de-verification-factice"  # gitleaks:allow


class FakePool:
    """Assez de base de données pour la vérification : une ligne, et l'audit écrit."""

    def __init__(self, row: dict[str, object] | None) -> None:
        self.row = row
        self.executed: list[tuple[str, tuple[object, ...]]] = []

    async def fetchrow(self, query: str, *args: object) -> dict[str, object] | None:
        return self.row

    async def execute(self, query: str, *args: object) -> None:
        self.executed.append((query, args))

    def audits(self) -> list[tuple[object, ...]]:
        return [args for query, args in self.executed if "audit_log" in query]

    def updates(self) -> list[tuple[object, ...]]:
        return [args for query, args in self.executed if "UPDATE domains" in query]


def domain_row(status: str = "pending") -> dict[str, object]:
    return {
        "id": "11111111-1111-1111-1111-111111111111",
        "fqdn": "exemple.test",
        "status": status,
        "verification_token": TOKEN,
        "verified_at": None,
    }


def resolver_returning(status: str, values: list[str]):
    async def _resolve(name: str) -> tuple[str, list[str]]:
        assert name == "_sentimail.exemple.test"
        return (status, values)

    return _resolve


class PureFunctionTests(unittest.TestCase):
    def test_a_domain_name_is_compared_case_and_dot_insensitively(self) -> None:
        self.assertEqual(normalize_fqdn(" Exemple.TEST. "), "exemple.test")
        self.assertEqual(normalize_fqdn(None), "")

    def test_a_token_pasted_with_a_panel_prefix_still_matches(self) -> None:
        self.assertTrue(matches_token([f"sentimail-verification={TOKEN}"], TOKEN))
        self.assertTrue(matches_token(["autre-chose", TOKEN], TOKEN))
        self.assertFalse(matches_token([], TOKEN))
        self.assertFalse(matches_token([TOKEN], ""))


class VerifyDomainTests(unittest.IsolatedAsyncioTestCase):
    async def test_the_published_token_proves_the_domain(self) -> None:
        pool = FakePool(domain_row())
        result = await verify_domain(
            pool, "Exemple.Test", resolver=resolver_returning("ok", [TOKEN])
        )
        self.assertEqual(result.outcome, VERIFIED)
        self.assertTrue(result.verified)
        self.assertEqual(len(pool.updates()), 1)
        self.assertEqual(len(pool.audits()), 1)
        self.assertEqual(pool.audits()[0][1], "domain.verified")

    async def test_proving_the_domain_never_activates_it(self) -> None:
        pool = FakePool(domain_row())
        await verify_domain(
            pool, "exemple.test", resolver=resolver_returning("ok", [TOKEN])
        )
        for query, _ in pool.executed:
            self.assertNotIn("status=", query.replace(" ", ""))

    async def test_a_name_without_any_txt_is_not_a_refusal(self) -> None:
        pool = FakePool(domain_row())
        result = await verify_domain(
            pool, "exemple.test", resolver=resolver_returning(TOKEN_ABSENT, [])
        )
        self.assertEqual(result.outcome, TOKEN_ABSENT)
        self.assertFalse(result.verified)
        self.assertEqual(pool.updates(), [])
        self.assertEqual(pool.audits()[0][1], "domain.verification_failed")

    async def test_an_unpublished_record_is_reported_as_nxdomain(self) -> None:
        pool = FakePool(domain_row())
        result = await verify_domain(
            pool, "exemple.test", resolver=resolver_returning(NXDOMAIN, [])
        )
        self.assertEqual(result.outcome, NXDOMAIN)
        self.assertEqual(pool.updates(), [])

    async def test_another_token_is_distinguished_from_an_absent_one(self) -> None:
        pool = FakePool(domain_row())
        result = await verify_domain(
            pool,
            "exemple.test",
            resolver=resolver_returning("ok", ["v=spf1 -all", "deadbeef"]),
        )
        self.assertEqual(result.outcome, TOKEN_MISMATCH)
        self.assertEqual(result.published, ["v=spf1 -all", "deadbeef"])
        self.assertEqual(pool.updates(), [])

    async def test_an_unknown_domain_is_refused_without_touching_dns(self) -> None:
        async def _never_called(name: str) -> tuple[str, list[str]]:
            raise AssertionError("un domaine inconnu ne justifie aucune requête DNS")

        pool = FakePool(None)
        result = await verify_domain(pool, "inconnu.test", resolver=_never_called)
        self.assertEqual(result.outcome, UNKNOWN_DOMAIN)
        self.assertIsNone(result.status)
        self.assertEqual(pool.audits()[0][1], "domain.verification_failed")

    async def test_a_dns_outage_is_a_non_constat_not_a_fraud(self) -> None:
        pool = FakePool(domain_row())
        result = await verify_domain(
            pool,
            "exemple.test",
            resolver=resolver_returning(f"{RESOLUTION_FAILED}:LifetimeTimeout", []),
        )
        self.assertEqual(result.outcome, RESOLUTION_FAILED)
        self.assertIn("LifetimeTimeout", result.detail)
        self.assertEqual(pool.updates(), [])
        self.assertEqual(len(pool.audits()), 1)


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class EnrolmentIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        await self.pool.execute(
            "DELETE FROM domains WHERE fqdn LIKE '%.enrolment.test'"
        )
        self.token = await self.pool.fetchval(
            """
            INSERT INTO domains (fqdn, admin_email)
            VALUES ('a.enrolment.test', 'admin@a.enrolment.test')
            RETURNING verification_token
            """
        )

    async def asyncTearDown(self) -> None:
        await self.pool.execute(
            "DELETE FROM domains WHERE fqdn LIKE '%.enrolment.test'"
        )
        await self.pool.close()

    async def test_verification_writes_the_date_but_leaves_the_status_pending(
        self,
    ) -> None:
        async def _resolve(name: str) -> tuple[str, list[str]]:
            return ("ok", [str(self.token)])

        result = await verify_domain(self.pool, "a.enrolment.test", resolver=_resolve)
        self.assertTrue(result.verified)
        row = await load_domain(self.pool, "a.enrolment.test")
        assert row is not None
        self.assertIsNotNone(row["verified_at"])
        self.assertEqual(row["status"], "pending")


if __name__ == "__main__":
    unittest.main()
