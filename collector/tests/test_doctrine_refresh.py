from __future__ import annotations

import unittest

from sentimail_v3.code.doctrine_learning import refresh_learned_doctrine


class _Pool:
    def __init__(self, labels: list[dict[str, object]]) -> None:
        self.labels = labels
        self.written: list[str] = []

    async def fetch(self, query: str, *args: object) -> list[dict[str, object]]:
        if "GROUP BY" in query:
            return [{"participant_email": "operateur@mondomaine.example", "total": len(self.labels)}]
        return self.labels

    async def fetchval(self, query: str, *args: object) -> object:
        self.written.append(query)
        return 1

    async def execute(self, query: str, *args: object) -> str:
        return "OK"


class RefreshTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_motif_recurrent_produit_une_fiche(self) -> None:
        pool = _Pool(
            [
                {"label": "spam", "sender_normalized": f"a{i}@x.fr",
                 "message_id": str(i), "observed_on": "2026-08-15",
                 "signals": ["IDENTITY_BRAND_MISMATCH", "AUTH_DMARC_FAIL"]}
                for i in range(3)
            ]
        )

        ecrites = await refresh_learned_doctrine(pool)  # type: ignore[arg-type]

        self.assertEqual(len(ecrites), 1)

    async def test_sans_motif_aucune_fiche_n_est_ecrite(self) -> None:
        pool = _Pool(
            [
                {"label": "spam", "sender_normalized": "a@x.fr", "message_id": "1",
                 "observed_on": "2026-08-15", "signals": ["UN_SEUL"]}
            ]
        )

        self.assertEqual(await refresh_learned_doctrine(pool), [])  # type: ignore[arg-type]
