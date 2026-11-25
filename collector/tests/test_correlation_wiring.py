from __future__ import annotations

import json
import unittest

from sentimail_v3.observation.deep_analysis import persist_signals


class _Connection:
    def __init__(self, existing: list[str]) -> None:
        self.existing = existing
        self.inserted: list[tuple[str, tuple[object, ...]]] = []

    def transaction(self) -> "_Connection":
        return self

    async def __aenter__(self) -> "_Connection":
        return self

    async def __aexit__(self, *args: object) -> bool:
        return False

    async def fetchval(self, query: str, *args: object) -> object:
        if "EXISTS" in query:
            return False
        if "INSERT INTO hook_runs" in query:
            return 1
        if "edition_id" in query:
            return 1
        return None

    async def fetch(self, query: str, *args: object) -> list[dict[str, object]]:
        if "FROM clues" in query:
            return [{"clue_code": code, "facts": {}} for code in self.existing]
        return []

    async def fetchrow(self, query: str, *args: object) -> dict[str, object]:
        return {
            "from_header": "Seafy <no-reply@seafy.com>",
            "envelope_from": "bounce-123@mg.seafy.com",
            "reply_to": None,
        }

    async def execute(self, query: str, *args: object) -> str:
        self.inserted.append((query, args))
        return "INSERT 1"


class _Pool:
    def __init__(self, existing: list[str]) -> None:
        self.connection = _Connection(existing)

    def acquire(self) -> _Connection:
        return self.connection


class CorrelationWiringTests(unittest.IsolatedAsyncioTestCase):
    async def test_les_convergences_sont_enregistrees_comme_indices(self) -> None:
        """Une corrélation non persistée n'existe ni pour le juge ni pour l'apprentissage."""
        pool = _Pool(["IDENTITY_BRAND_MISMATCH", "AUTH_DMARC_FAIL"])

        await persist_signals(pool, "11111111-1111-1111-1111-111111111111", {})  # type: ignore[arg-type]

        clues = [
            args
            for query, args in pool.connection.inserted
            if "INSERT INTO clues" in query
        ]
        codes = {value for args in clues for value in args if isinstance(value, str)}
        self.assertIn("CORRELATION_BRAND_SPOOFING", codes)

    async def test_sans_faisceau_aucune_convergence_n_est_ecrite(self) -> None:
        pool = _Pool(["AUTH_DMARC_PASS", "STRUCT_PARSEABLE"])

        await persist_signals(pool, "11111111-1111-1111-1111-111111111111", {})  # type: ignore[arg-type]

        codes = {
            value
            for query, args in pool.connection.inserted
            if "INSERT INTO clues" in query
            for value in args
            if isinstance(value, str)
        }
        self.assertFalse({code for code in codes if code.startswith("CORRELATION_")})

    async def test_le_faisceau_compte_detourne_conserve_les_identites(self) -> None:
        pool = _Pool(
            ["SENDER_ACTIVITY_INCOHERENT", "HISTORY_FIRST_OBSERVATION", "AUTH_DMARC_PASS"]
        )

        await persist_signals(pool, "11111111-1111-1111-1111-111111111111", {})  # type: ignore[arg-type]

        facts = [
            json.loads(str(args[8]))
            for query, args in pool.connection.inserted
            if "INSERT INTO clues" in query
            and "CORRELATION_COMPROMISED_SENDER" in args
        ]
        self.assertEqual(facts[0]["identity"]["displayed_email"], "no-reply@seafy.com")


if __name__ == "__main__":
    unittest.main()


class CoherenceSignalPersistenceTests(unittest.IsolatedAsyncioTestCase):
    """Un indice déjà jugé doit être écrit tel quel, pas ignoré."""

    async def test_l_incoherence_metier_devient_un_indice_en_base(self) -> None:
        pool = _Pool([])
        analyse = {
            "signals": [
                {
                    "article_code": "DEEP-019",
                    "clue_code": "SENDER_ACTIVITY_INCOHERENT",
                    "direction": "adverse",
                    "strength": 55,
                    "confidence": 0.75,
                    "statement": "Le propos est étranger à l’activité publiée.",
                    "facts": {"sender_apex": "fioresrl.com"},
                }
            ]
        }

        await persist_signals(pool, "11111111-1111-1111-1111-111111111111", analyse)  # type: ignore[arg-type]

        codes = {
            value
            for query, args in pool.connection.inserted
            if "INSERT INTO clues" in query
            for value in args
            if isinstance(value, str)
        }
        self.assertIn("SENDER_ACTIVITY_INCOHERENT", codes)
