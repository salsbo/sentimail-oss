from __future__ import annotations

import unittest

from sentimail_v3.supervision.adjudication import adjudicate


class _Connection:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.fetches = 0

    async def fetchrow(self, query: str, *args: object):
        self.fetches += 1
        if self.fetches == 1:
            return {"id": 42, "message_id": None, "kind": "ground_truth"}
        return {"id": 7, "created_at": "maintenant"}

    async def fetchval(self, query: str, *args: object):
        return 43

    async def execute(self, query: str, *args: object):
        self.executed.append((query, args))
        return "OK"


class AdjudicationTests(unittest.IsolatedAsyncioTestCase):
    async def test_an_expert_label_supersedes_only_an_expert_label(self) -> None:
        connection = _Connection()
        sample_id, label_id = await adjudicate(
            connection,
            sample_id=42,
            label="legitimate",
            reason_code="confirmed_legitimate",
            operator="reviewer",
        )
        self.assertEqual(sample_id, 42)
        self.assertEqual(label_id, 7)
        sql = " ".join(query for query, _ in connection.executed)
        self.assertIn("a.authority='expert'", sql)
        self.assertIn("training.sample_adjudicated", sql)

    async def test_a_free_form_reason_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            await adjudicate(
                _Connection(),
                sample_id=42,
                label="spam",
                reason_code="le client Jean a dit ceci",
                operator="reviewer",
            )


if __name__ == "__main__":
    unittest.main()
