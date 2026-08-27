from __future__ import annotations

import unittest

from sentimail_v3.execution.delivery_state import TERMINAL
from sentimail_v3.supervision.caretaker import _replay_errored


class _Pool:
    def __init__(self) -> None:
        self.args: tuple[object, ...] = ()

    async def fetch(self, query: str, *args: object) -> list[object]:
        self.args = args
        return []


class ReplayScopeTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_dossier_clos_nest_jamais_rejoue(self) -> None:
        """Les états terminaux ont une seule définition : celle de delivery_state."""
        from types import SimpleNamespace

        pool = _Pool()

        await _replay_errored(
            pool, SimpleNamespace(raw_eml_key_file=None)  # type: ignore[arg-type]
        )

        excluded = next(
            (value for value in pool.args if isinstance(value, list)),
            None,
        )
        self.assertIsNotNone(excluded)
        self.assertEqual(set(excluded or []), set(TERMINAL))


if __name__ == "__main__":
    unittest.main()
