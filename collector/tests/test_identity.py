from __future__ import annotations

import unittest
from unittest.mock import patch

from sentimail_v3.identity import Identity, instance_identity, reset_cache


class _FakeSettings:
    action_address = "maia@sentinel.mondomaine.example"
    action_aliases = ("kitt@sentinel.mondomaine.example",)
    assistant_sender = "MAIA - SentiMail <maia@mondomaine.example>"
    probe_recipient = "sonde@sentinel.mondomaine.example"


class _FakePool:
    def __init__(self, row):
        self._row = row
        self.calls = 0

    async def fetchrow(self, sql, *args):
        self.calls += 1
        return self._row


class _RaisingPool:
    def __init__(self) -> None:
        self.calls = 0

    async def fetchrow(self, sql, *args):
        self.calls += 1
        raise RuntimeError("base indisponible")


class InstanceIdentityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        reset_cache()

    async def test_table_vide_rend_l_environnement(self) -> None:
        identity = await instance_identity(_FakePool(None), _FakeSettings())
        self.assertEqual(
            identity,
            Identity(
                action_address="maia@sentinel.mondomaine.example",
                action_aliases=("kitt@sentinel.mondomaine.example",),
                assistant_sender="MAIA - SentiMail <maia@mondomaine.example>",
                probe_recipient="sonde@sentinel.mondomaine.example",
            ),
        )

    async def test_la_ligne_prime_sur_l_environnement(self) -> None:
        row = {
            "action_address": "maia@client.mondomaine.example",
            "action_aliases": ["kitt@client.mondomaine.example", "assist@client.mondomaine.example"],
            "assistant_sender": "MAIA <maia@client.mondomaine.example>",
            "probe_recipient": "sonde@client.mondomaine.example",
        }
        identity = await instance_identity(_FakePool(row), _FakeSettings())
        self.assertEqual(identity.action_address, "maia@client.mondomaine.example")
        self.assertEqual(
            identity.action_aliases,
            ("kitt@client.mondomaine.example", "assist@client.mondomaine.example"),
        )
        self.assertEqual(identity.assistant_sender, "MAIA <maia@client.mondomaine.example>")
        self.assertEqual(identity.probe_recipient, "sonde@client.mondomaine.example")

    async def test_une_erreur_sql_rend_l_environnement(self) -> None:
        pool = _RaisingPool()
        identity = await instance_identity(pool, _FakeSettings())
        self.assertEqual(identity.action_address, "maia@sentinel.mondomaine.example")
        self.assertEqual(identity.probe_recipient, "sonde@sentinel.mondomaine.example")
        self.assertEqual(pool.calls, 1)

    async def test_le_cache_evite_la_requete_pendant_60s(self) -> None:
        pool = _FakePool(None)
        with patch("sentimail_v3.identity.time.monotonic", return_value=1000.0):
            await instance_identity(pool, _FakeSettings())
            await instance_identity(pool, _FakeSettings())
        self.assertEqual(pool.calls, 1)
        with patch("sentimail_v3.identity.time.monotonic", return_value=1000.0 + 61):
            await instance_identity(pool, _FakeSettings())
        self.assertEqual(pool.calls, 2)


if __name__ == "__main__":
    unittest.main()
