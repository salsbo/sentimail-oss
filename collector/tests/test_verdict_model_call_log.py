"""Un échec d'appel au modèle laisse une ligne de journal.

Le 14 septembre, l'appel Flash suspendu 901 s n'a laissé aucune trace dans le
journal du juge : seule la colonne `routing_reason` en base portait
« economy_error:LlmError ». Une panne de palier doit se lire dans les
journaux, avec le palier, le modèle, la durée et le type d'erreur.
"""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from sentimail_v3.llm import LlmError
from sentimail_v3.judgment import model_calls as verdict_engine


class _Pool:
    def __init__(self) -> None:
        self.execute = AsyncMock()


class JournalDesAppelsTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_echec_du_palier_est_journalise(self) -> None:
        run = {
            "id": "run-1",
            "message_id": "28f2c85e-fc76-4851-abac-654c07d55ebf",
            "attempts": 1,
        }
        with (
            patch.object(
                verdict_engine, "_reserve_verdict_call", AsyncMock(return_value=(7, None))
            ),
            patch.object(
                verdict_engine,
                "provider_chat_json",
                AsyncMock(side_effect=LlmError("délai total de 120 s dépassé")),
            ),
            self.assertLogs("sentimail-v3-verdict", level="ERROR") as journal,
        ):
            with self.assertRaises(LlmError):
                await verdict_engine._call_verdict_model(
                    _Pool(),  # type: ignore[arg-type]
                    object(),  # type: ignore[arg-type]
                    SimpleNamespace(economy_llm_deadline_seconds=30),  # type: ignore[arg-type]
                    run,  # type: ignore[arg-type]
                    {"clues": []},
                    model_name="deepseek-v4-flash",
                    stage="economy",
                )
        lignes = [json.loads(record.getMessage()) for record in journal.records]
        echec = next(l for l in lignes if l["event"] == "verdict.model_call.error")
        self.assertEqual(echec["stage"], "economy")
        self.assertEqual(echec["model"], "deepseek-v4-flash")
        self.assertEqual(echec["error_type"], "LlmError")
        self.assertIn("duration_ms", echec)
        self.assertEqual(echec["message_id"], run["message_id"])


class BudgetParPalierTests(unittest.IsolatedAsyncioTestCase):
    async def _appel(self, stage: str) -> dict:
        run = {"id": "run-1", "message_id": "28f2c85e-fc76-4851-abac-654c07d55ebf", "attempts": 1}
        settings = SimpleNamespace(economy_llm_deadline_seconds=30)
        appel = AsyncMock(return_value=("{}", {"provider": "openai_compatible"}))
        with (
            patch.object(
                verdict_engine, "_reserve_verdict_call", AsyncMock(return_value=(7, None))
            ),
            patch.object(verdict_engine, "provider_chat_json", appel),
        ):
            await verdict_engine._call_verdict_model(
                _Pool(),  # type: ignore[arg-type]
                object(),  # type: ignore[arg-type]
                settings,  # type: ignore[arg-type]
                run,  # type: ignore[arg-type]
                {"clues": []},
                model_name="deepseek-v4-flash" if stage == "economy" else "deepseek-v4-pro",
                stage=stage,
            )
        return appel.await_args.kwargs

    async def test_flash_est_coupe_a_son_budget_court(self) -> None:
        self.assertEqual((await self._appel("economy"))["deadline_seconds"], 30)

    async def test_pro_garde_le_budget_commun(self) -> None:
        self.assertIsNone((await self._appel("premium"))["deadline_seconds"])

