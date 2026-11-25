"""Premières exécutions et qualifications sur PostgreSQL local jetable.

EVALUATION_TEST_DATABASE_URL désigne une base de test locale. Les tables
temporaires d'une connexion isolent ces cas des autres suites concurrentes.
"""

from __future__ import annotations

import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import asyncpg

from sentimail_v3.supervision import evaluation_report as report

DSN = os.environ.get("EVALUATION_TEST_DATABASE_URL", "")
END = datetime(2026, 10, 30, 13, 50, tzinfo=timezone.utc)


@unittest.skipUnless(DSN, "base PostgreSQL locale jetable requise")
class PremieresExecutionsPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        target = urlsplit(DSN)
        self.assertIn(target.hostname, ("127.0.0.1", "localhost"))
        self.assertIn("test", target.path)
        self.connection = await asyncpg.connect(DSN)
        await self.connection.execute("""
            CREATE TEMP TABLE messages (
                id uuid PRIMARY KEY, captured_at timestamptz, delivery_status text);
            CREATE TEMP TABLE delivery_cases (
                id uuid PRIMARY KEY, message_id uuid UNIQUE, state text);
            CREATE TEMP TABLE delivery_events (
                id bigserial PRIMARY KEY, case_id uuid, event_type text,
                created_at timestamptz);
            CREATE TEMP TABLE labels (
                id bigserial PRIMARY KEY, message_id uuid, label text,
                is_ground_truth boolean, active boolean, created_at timestamptz);
        """)

    async def asyncTearDown(self) -> None:
        await self.connection.close()

    async def message(self, status: str, *, state: str = "closed",
                      captured: datetime | None = None, case: bool = True) -> tuple:
        message_id, case_id = uuid.uuid4(), uuid.uuid4()
        await self.connection.execute("INSERT INTO messages VALUES($1,$2,$3)",
                                      message_id, captured or END-timedelta(days=1), status)
        if case:
            await self.connection.execute("INSERT INTO delivery_cases VALUES($1,$2,$3)",
                                          case_id, message_id, state)
        return message_id, case_id

    async def event(self, case_id: uuid.UUID, kind: str, *, age: int = 0) -> None:
        await self.connection.execute(
            "INSERT INTO delivery_events(case_id,event_type,created_at) VALUES($1,$2,$3)",
            case_id, kind, END-timedelta(hours=1, seconds=age))

    async def label(self, message_id: uuid.UUID, label: str, *, active: bool = True,
                    truth: bool = True) -> None:
        await self.connection.execute(
            """INSERT INTO labels(message_id,label,is_ground_truth,active,created_at)
               VALUES($1,$2,$3,$4,$5)""", message_id, label, truth, active, END)

    async def collect(self) -> dict:
        return await report.collect(self.connection, as_of=END)  # type: ignore[arg-type]

    async def test_avis_puis_indesirables_reste_avis_et_ignore_les_erreurs(self) -> None:
        _, case_id = await self.message("delivered", state="original_filed_as_junk")
        await self.event(case_id, "error", age=20)
        await self.event(case_id, "review_notice_delivered", age=10)
        await self.event(case_id, "original_filed_as_junk")
        result = await self.collect()
        self.assertEqual(result["executions"]["ask_user"], 1)
        self.assertEqual(result["executions"]["filed_as_junk"], 0)
        self.assertEqual(result["final_statuses"], {"delivered": 1})

    async def test_un_avis_gagne_a_date_egale_selon_identifiant(self) -> None:
        _, case_id = await self.message("delivered")
        await self.event(case_id, "review_notice_delivered")
        await self.event(case_id, "original_released")
        self.assertEqual((await self.collect())["executions"]["ask_user"], 1)

    async def test_suppressions_echecs_attentes_et_preuves_absentes_sont_distincts(self) -> None:
        _, case_id = await self.message("suppressed", state="policy_suppressed")
        await self.event(case_id, "policy_suppressed")
        await self.message("undeliverable")
        await self.message("captured", state="analysis_pending", case=False)
        await self.message("delivered")
        await self.message("consumed", case=False)
        result = await self.collect()
        self.assertEqual(result["population"]["captured"], 5)
        self.assertEqual(result["population"]["consumed_excluded"], 1)
        self.assertEqual(result["population"]["protected"], 4)
        self.assertEqual(result["population"]["quality_evaluated"], 0)
        self.assertEqual(result["population"]["quality_exclusions"], {
            "suppressed": 1, "undeliverable": 1, "pending": 1, "unconfirmed": 1})
        self.assertEqual(result["residuals"]["delivered_without_event"], 1)
        self.assertEqual(result["residuals"]["missing_case"], 1)
        self.assertEqual(result["residuals"]["without_execution_event"], 3)
        self.assertEqual(result["matrix"]["total"], 0)

    async def test_abandon_conserve_la_sollicitation_sans_inventer_ni_effacer_label(self) -> None:
        _, unlabelled = await self.message("held", state="ignored")
        await self.event(unlabelled, "review_notice_delivered")
        message_id, labelled = await self.message("held", state="ignored")
        await self.event(labelled, "review_notice_delivered")
        await self.label(message_id, "legitimate")
        await self.label(message_id, "dangerous", active=False)
        await self.label(message_id, "spam", truth=False)
        result = await self.collect()
        self.assertEqual(result["matrix"]["rows"]["ask_user"]["legitimate"], 1)
        self.assertEqual(result["matrix"]["rows"]["ask_user"]["unknown"], 1)
        self.assertEqual(result["hold_precision"]["labelled"], 1)
        self.assertEqual(result["population"]["ignored_with_notice"], 2)

    async def test_la_derniere_qualification_active_est_deterministe(self) -> None:
        message_id, case_id = await self.message("delivered")
        await self.event(case_id, "original_delivered")
        await self.label(message_id, "legitimate")
        await self.label(message_id, "dangerous")
        result = await self.collect()
        self.assertEqual(result["matrix"]["rows"]["deliver"]["spam"], 1)

    async def test_la_fenetre_inclut_le_debut_et_exclut_la_fin(self) -> None:
        _, start_case = await self.message("delivered", captured=END-timedelta(days=30))
        await self.event(start_case, "original_delivered")
        await self.message("captured", captured=END, case=False)
        await self.message("captured", captured=END-timedelta(days=30, microseconds=1), case=False)
        result = await self.collect()
        self.assertEqual(result["population"]["captured"], 1)
        self.assertEqual(result["matrix"]["total"], 1)
