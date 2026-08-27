from __future__ import annotations

import os
import unittest
from dataclasses import replace

import asyncpg
from sentimail_v3.config import load_settings
from sentimail_v3.execution.delivery import retry_one_release


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class RetryQueryTests(unittest.IsolatedAsyncioTestCase):
    """La requête de reprise doit être valide contre le schéma réel.

    Un UndefinedColumnError (colonne messages.updated_at inexistante) est passé
    en production faute d'exécuter cette requête en test : ce cas la couvre.
    """

    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        self.settings = replace(load_settings(), raw_eml_key_file=None)

    async def asyncTearDown(self) -> None:
        await self.pool.close()

    async def test_retry_on_an_empty_queue_runs_and_returns_false(self) -> None:
        # Aucune reprise en attente : la requête s'exécute, ne trouve rien,
        # rend False - sans jamais lever d'erreur SQL.
        self.assertFalse(await retry_one_release(self.pool, self.settings))


if __name__ == "__main__":
    unittest.main()
