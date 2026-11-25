"""Essais espacés du juge, vérifiés sur une vraie base jetable.

La prise en charge, l'échéance, la reprise après redémarrage et ce que voient
le superviseur et l'agent d'entretien sont des requêtes SQL : seule une base
PostgreSQL portant toutes les migrations dit ce qu'elles comptent. La base est
nommée explicitement et doit être locale, jamais celle de la production.

    VERDICT_RETRY_TEST_DATABASE_URL=postgresql://...@127.0.0.1:PORT/sentimail_retry_test
"""

from __future__ import annotations

import os
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import asyncpg

from sentimail_v3.judgment import workflow as verdict_engine
from sentimail_v3.judgment.core_compare import reference
from sentimail_v3.judgment.verdict_engine import (
    ENGINE,
    PROMPT_VERSION,
    _claim,
    _mark_error,
    resume_interrupted_runs,
)
from sentimail_v3.llm import LlmError
from sentimail_v3.supervision import caretaker
from sentimail_v3.supervision.caretaker_letter import actions_requises, lettre
from sentimail_v3.supervision.watchdog import _snapshot
from test_watchdog import _FreshBackup, _snapshot_settings

DSN = os.environ.get("VERDICT_RETRY_TEST_DATABASE_URL", "")
DELAI = LlmError("délai total de 120 s dépassé")
SETTINGS = SimpleNamespace(
    verdict_not_before=None,
    deepseek_verdict_model="deepseek-v4-pro",
    decision_mode=True,
    analysis_wait_seconds=30,
)


@unittest.skipUnless(DSN, "base PostgreSQL jetable requise")
class _Base(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        cible = urlsplit(DSN)
        self.assertEqual(cible.hostname, "127.0.0.1")
        self.assertEqual(cible.path, "/sentimail_retry_test")
        self.pool = await asyncpg.create_pool(DSN, min_size=1, max_size=4)
        await self.pool.execute(
            "TRUNCATE messages, investigations, verdict_runs, audit_log CASCADE"
        )

    async def asyncTearDown(self) -> None:
        await self.pool.close()

    async def dossier(
        self, *, status: str = "analyzing", age: timedelta = timedelta(hours=2)
    ) -> str:
        message_id = await self.pool.fetchval(
            """
            INSERT INTO messages (
                ingest_key, envelope_from, envelope_recipients, raw_eml,
                raw_sha256, raw_size_bytes, headers_size_bytes, body_size_bytes,
                line_count, max_line_length, contains_8bit, contains_nul,
                line_ending, root_content_type, parser_version, subject,
                delivery_status, captured_at
            ) VALUES (
                'retry-' || gen_random_uuid(), 'sender@example.test', '{}',
                'test', repeat('a',64), 4, 0, 4, 1, 4, false, false, 'CRLF',
                'text/plain', 'test', 'Re: Votre Kit Médical Gratuit', $1,
                now() - $2::interval
            ) RETURNING id::text
            """,
            status,
            age,
        )
        await self.pool.execute(
            """
            INSERT INTO investigations (message_id, edition_id, status, started_at, completed_at)
            SELECT $1::uuid, id, 'complete', now() - $2::interval, now() - $2::interval
            FROM code_editions ORDER BY created_at LIMIT 1
            """,
            message_id,
            age,
        )
        await self.pool.execute(
            "INSERT INTO delivery_cases (message_id, state) VALUES ($1::uuid, 'analysis_pending')",
            message_id,
        )
        return message_id

    async def prendre(self) -> asyncpg.Record | None:
        return await _claim(self.pool, SETTINGS)  # type: ignore[arg-type]

    async def echouer(self, exc: Exception) -> tuple[asyncpg.Record, object]:
        run = await self.prendre()
        self.assertIsNotNone(run)
        assert run is not None
        return run, await _mark_error(self.pool, run, exc)

    async def avancer_l_horloge(self) -> None:
        """L'échéance arrive : on recule l'échéance plutôt que d'attendre."""
        await self.pool.execute(
            "UPDATE verdict_runs SET next_attempt_at = now() - interval '1 second' "
            "WHERE status='error' AND completed_at IS NULL AND next_attempt_at IS NOT NULL"
        )

    async def etat(self) -> asyncpg.Record:
        return await self.pool.fetchrow(
            """
            SELECT status, attempts, completed_at, next_attempt_at,
                   extract(epoch FROM next_attempt_at - now()) AS dans
            FROM verdict_runs
            """
        )


class PlanificationPostgresTests(_Base):
    async def test_quinze_minutes_une_heure_quatre_heures_puis_epuise(self) -> None:
        await self.dossier()
        for tentative, delai in ((1, 15 * 60), (2, 3600), (3, 4 * 3600)):
            run, plan = await self.echouer(DELAI)
            self.assertEqual(run["attempts"], tentative)
            self.assertEqual(plan.kind, "scheduled")
            etat = await self.etat()
            self.assertEqual(etat["status"], "error")
            self.assertIsNone(etat["completed_at"])
            self.assertAlmostEqual(float(etat["dans"]), delai, delta=30)
            # Pas d'essai avant l'échéance.
            self.assertIsNone(await self.prendre())
            await self.avancer_l_horloge()
        run, plan = await self.echouer(DELAI)
        self.assertEqual(run["attempts"], 4)
        self.assertTrue(plan.exhausted)
        etat = await self.etat()
        self.assertIsNotNone(etat["completed_at"])
        self.assertIsNone(etat["next_attempt_at"])
        await self.avancer_l_horloge()
        self.assertIsNone(await self.prendre())

    async def test_l_essai_planifie_survit_au_redemarrage(self) -> None:
        await self.dossier()
        await self.echouer(DELAI)
        avant = await self.etat()
        await resume_interrupted_runs(self.pool)
        apres = await self.etat()
        self.assertEqual(avant["next_attempt_at"], apres["next_attempt_at"])
        self.assertIsNone(await self.prendre())
        await self.avancer_l_horloge()
        run = await self.prendre()
        assert run is not None
        self.assertEqual(run["attempts"], 2)

    async def test_un_essai_echu_pendant_l_arret_est_repris_au_demarrage(self) -> None:
        await self.dossier()
        await self.echouer(DELAI)
        await self.pool.execute(
            "UPDATE verdict_runs SET next_attempt_at = now() - interval '2 hours'"
        )
        await resume_interrupted_runs(self.pool)
        run = await self.prendre()
        assert run is not None
        self.assertEqual(run["attempts"], 2)

    async def test_un_essai_planifie_interrompu_est_repris_au_demarrage(self) -> None:
        await self.dossier()
        await self.echouer(DELAI)
        await self.avancer_l_horloge()
        en_cours = await self.prendre()
        assert en_cours is not None
        self.assertEqual(en_cours["attempts"], 2)
        await resume_interrupted_runs(self.pool)
        run = await self.prendre()
        assert run is not None
        self.assertEqual(run["attempts"], 3)

    async def test_un_troisieme_essai_interrompu_n_est_plus_abandonne(self) -> None:
        # Avant : interrompu au troisième essai, le run passait en erreur sans
        # date de fin, hors de portée de la prise en charge (attempts < 3) et
        # sans escalade. Le dossier restait en analyse indéfiniment.
        await self.dossier()
        for _ in range(2):
            await self.echouer(ValueError("JSON"))
            await self.pool.execute(
                "UPDATE verdict_runs SET started_at = started_at - interval '1 minute'"
            )
        troisieme = await self.prendre()
        assert troisieme is not None
        self.assertEqual(troisieme["attempts"], 3)
        await resume_interrupted_runs(self.pool)
        await self.pool.execute(
            "UPDATE verdict_runs SET started_at = started_at - interval '1 minute'"
        )
        repris = await self.prendre()
        assert repris is not None
        self.assertEqual(repris["attempts"], 4)

    async def test_une_erreur_non_passagere_garde_sa_cadence(self) -> None:
        await self.dossier()
        run, plan = await self.echouer(ValueError("JSON"))
        self.assertEqual(plan.kind, "immediate")
        self.assertIsNone((await self.etat())["next_attempt_at"])
        # La cadence historique : quinze secondes par essai déjà fait.
        self.assertIsNone(await self.prendre())
        await self.pool.execute(
            "UPDATE verdict_runs SET started_at = started_at - interval '16 seconds'"
        )
        run = await self.prendre()
        assert run is not None
        self.assertEqual(run["attempts"], 2)
        await _mark_error(self.pool, run, ValueError("JSON"))
        await self.pool.execute(
            "UPDATE verdict_runs SET started_at = started_at - interval '31 seconds'"
        )
        run, plan = await self.echouer(ValueError("JSON"))
        self.assertEqual(run["attempts"], 3)
        self.assertTrue(plan.exhausted)
        self.assertIsNotNone((await self.etat())["completed_at"])

    async def test_les_dossiers_epuises_de_la_nuit_ne_sont_pas_rejoues(self) -> None:
        # État de M-e4b2cb et des six autres au 15 octobre : trois échecs,
        # date de fin posée, message retenu avec avis. Aucune reprise.
        for statut in ("held", "analyzing"):
            message_id = await self.dossier(status=statut)
            await self.pool.execute(
                """
                INSERT INTO verdict_runs (
                    investigation_id, engine, model_name, prompt_version,
                    status, attempts, error_type, error_detail,
                    started_at, completed_at
                )
                SELECT i.id, $2, 'deepseek-v4-pro', $3, 'error', 3, 'LlmError',
                       'délai total de 120 s dépassé',
                       now() - interval '12 hours', now() - interval '12 hours'
                FROM investigations i WHERE i.message_id=$1::uuid
                """,
                message_id,
                ENGINE,
                PROMPT_VERSION,
            )
        self.assertIsNone(await self.prendre())


class _Supervision(_Base):
    async def en_attente(self) -> str:
        message_id = await self.dossier()
        await self.echouer(DELAI)
        return message_id

    async def en_retard(self) -> str:
        message_id = await self.en_attente()
        await self.pool.execute(
            "UPDATE verdict_runs SET next_attempt_at = now() - interval '20 minutes'"
        )
        return message_id

    async def epuise(self) -> str:
        message_id = await self.dossier()
        for _ in range(4):
            await self.echouer(DELAI)
            await self.avancer_l_horloge()
        # L'escalade actuelle : retenu, avis parti.
        await self.pool.execute(
            "UPDATE messages SET delivery_status='held' WHERE id=$1::uuid", message_id
        )
        await self.pool.execute(
            "UPDATE delivery_cases SET state='awaiting_reply' WHERE message_id=$1::uuid",
            message_id,
        )
        return message_id

    async def releve(self) -> dict[str, object]:
        with patch("sentimail_v3.supervision.watchdog.BACKUP_HEARTBEAT", _FreshBackup()):
            snapshot = await _snapshot(self.pool, _snapshot_settings())  # type: ignore[arg-type]
        return snapshot["details"]  # type: ignore[return-value]


class SuperviseurPostgresTests(_Supervision):
    async def test_une_attente_planifiee_n_immobilise_rien(self) -> None:
        await self.en_attente()
        details = await self.releve()
        for compteur in (
            "analysis_backlog",
            "accepted_without_terminal_outcome",
            "verdict_retries_overdue",
            "verdict_retries_exhausted",
            "verdict_errors_last_hour",
        ):
            with self.subTest(compteur=compteur):
                self.assertEqual(details[compteur], 0)
        self.assertEqual(details["stalled_messages"], [])
        for raison in (
            "analysis_backlog",
            "accepted_without_terminal_outcome",
            "verdict_retries_overdue",
            "verdict_retries_exhausted",
        ):
            self.assertNotIn(raison, details["observed_reasons"])

    async def test_un_essai_planifie_en_cours_n_immobilise_rien(self) -> None:
        await self.en_attente()
        await self.avancer_l_horloge()
        self.assertIsNotNone(await self.prendre())
        details = await self.releve()
        self.assertEqual(details["analysis_backlog"], 0)
        self.assertEqual(details["accepted_without_terminal_outcome"], 0)
        self.assertEqual(details["stalled_messages"], [])

    async def test_le_troisieme_echec_planifie_n_est_pas_un_echec_definitif(self) -> None:
        await self.dossier()
        for _ in range(3):
            await self.echouer(DELAI)
            await self.avancer_l_horloge()
        await self.pool.execute(
            "UPDATE verdict_runs SET next_attempt_at = now() + interval '4 hours'"
        )
        details = await self.releve()
        self.assertEqual(details["verdict_errors_last_hour"], 0)
        self.assertEqual(details["verdict_retries_exhausted"], 0)
        self.assertEqual(details["analysis_backlog"], 0)

    async def test_un_essai_planifie_en_retard_est_signale(self) -> None:
        await self.en_retard()
        details = await self.releve()
        self.assertEqual(details["verdict_retries_overdue"], 1)
        self.assertEqual(details["analysis_backlog"], 1)
        self.assertEqual(details["accepted_without_terminal_outcome"], 1)
        self.assertIn("verdict_retries_overdue", details["observed_reasons"])
        [attente] = details["stalled_messages"]  # type: ignore[misc]
        self.assertGreaterEqual(attente["retry_overdue_seconds"], 20 * 60 - 30)

    async def test_un_essai_planifie_qui_s_eternise_est_signale(self) -> None:
        await self.en_attente()
        await self.avancer_l_horloge()
        self.assertIsNotNone(await self.prendre())
        await self.pool.execute(
            "UPDATE verdict_runs SET started_at = now() - interval '20 minutes'"
        )
        details = await self.releve()
        self.assertEqual(details["verdict_retries_overdue"], 1)
        self.assertEqual(details["analysis_backlog"], 1)

    async def test_des_essais_epuises_sont_signales(self) -> None:
        await self.epuise()
        details = await self.releve()
        self.assertEqual(details["verdict_retries_exhausted"], 1)
        self.assertEqual(details["verdict_errors_last_hour"], 1)
        self.assertIn("verdict_retries_exhausted", details["observed_reasons"])


class EntretienPostgresTests(_Supervision):
    async def test_silencieux_pendant_une_attente_planifiee(self) -> None:
        await self.en_attente()
        state = await caretaker.collect(self.pool)
        self.assertEqual(state["dossiers_coinces"], 0)
        self.assertEqual(state["verdicts_en_erreur_24h"], 0)
        self.assertEqual(state["erreurs_de_verdict_24h"], [])
        self.assertFalse(caretaker.worth_reporting(state))
        self.assertFalse(caretaker.mail_worthy(state))

    async def test_une_erreur_sans_echeance_reste_comptee(self) -> None:
        # Le refus définitif d'une livraison laisse un run en erreur, sans
        # date de fin ni échéance : il était compté, il doit le rester.
        message_id = await self.dossier(status="undeliverable")
        await self.pool.execute(
            """
            INSERT INTO verdict_runs (
                investigation_id, engine, model_name, prompt_version,
                status, attempts, error_type, error_detail, started_at
            )
            SELECT i.id, $2, 'deepseek-v4-pro', $3, 'error', 1,
                   'SMTPRecipientsRefused', '550 5.1.1 user unknown', now()
            FROM investigations i WHERE i.message_id=$1::uuid
            """,
            message_id,
            ENGINE,
            PROMPT_VERSION,
        )
        state = await caretaker.collect(self.pool)
        self.assertEqual(state["verdicts_en_erreur_24h"], 1)
        self.assertEqual(len(state["erreurs_de_verdict_24h"]), 1)

    async def test_signale_un_essai_planifie_en_retard(self) -> None:
        await self.en_retard()
        state = await caretaker.collect(self.pool)
        self.assertEqual(state["dossiers_coinces"], 1)
        self.assertTrue(caretaker.mail_worthy(state))
        sujet = lettre(state, {}, {}).subject
        self.assertIn("immobilisé", sujet)

    async def test_signale_des_essais_epuises(self) -> None:
        await self.epuise()
        state = await caretaker.collect(self.pool)
        self.assertEqual(state["verdicts_en_erreur_24h"], 1)
        self.assertTrue(caretaker.worth_reporting(state))
        self.assertTrue(caretaker.actionable_signals(state))
        self.assertTrue(
            any("analyse reste en échec" in ligne for ligne in actions_requises(state, {}))
        )

    async def test_le_rejeu_automatique_respecte_l_echeance(self) -> None:
        # Le troisième échec planifie le quatrième essai à +4 h : le rejeu de
        # l'entretien supprimerait le run et relancerait aussitôt le dossier.
        await self.dossier()
        for _ in range(3):
            await self.echouer(DELAI)
            await self.avancer_l_horloge()
        await self.pool.execute(
            "UPDATE verdict_runs SET next_attempt_at = now() + interval '4 hours'"
        )
        rejeu = AsyncMock()
        with (
            patch("sentimail_v3.supervision.replay.replay_case", rejeu),
            patch.object(caretaker, "load_key", lambda _path: None),
        ):
            fait = await caretaker._replay_errored(
                self.pool, SimpleNamespace(raw_eml_key_file=None)  # type: ignore[arg-type]
            )
        self.assertEqual(fait, 0)
        rejeu.assert_not_awaited()

    async def test_le_rejeu_automatique_reprend_un_dossier_epuise(self) -> None:
        message_id = await self.epuise()
        rejeu = AsyncMock()
        with (
            patch("sentimail_v3.supervision.replay.replay_case", rejeu),
            patch.object(caretaker, "load_key", lambda _path: None),
        ):
            fait = await caretaker._replay_errored(
                self.pool, SimpleNamespace(raw_eml_key_file=None)  # type: ignore[arg-type]
            )
        self.assertEqual(fait, 1)
        self.assertEqual(rejeu.await_args.args[1], message_id)


class EscaladePostgresTests(_Base):
    async def test_l_escalade_attend_l_echec_du_quatrieme_essai(self) -> None:
        await self.dossier(status="captured")
        escalade = AsyncMock(return_value="review_notice_queued")
        with (
            patch.object(verdict_engine, "_express_judgment", AsyncMock(side_effect=DELAI)),
            patch.object(verdict_engine, "hold_with_review_or_fail_open", escalade),
            patch.object(reference(), "_express_judgment", AsyncMock(side_effect=DELAI)),
            patch.object(reference(), "hold_with_review_or_fail_open", escalade),
        ):
            for tentative in range(1, 5):
                self.assertTrue(
                    await verdict_engine._process_one(
                        self.pool,
                        None,  # type: ignore[arg-type]
                        SETTINGS,  # type: ignore[arg-type]
                        SimpleNamespace(queue_invitation=AsyncMock()),  # type: ignore[arg-type]
                    )
                )
                statut = await self.pool.fetchval("SELECT delivery_status FROM messages")
                # Le message reste retenu dans le pipeline : ni livré, ni perdu.
                self.assertEqual(statut, "analyzing")
                if tentative < 4:
                    escalade.assert_not_awaited()
                    self.assertFalse(
                        await verdict_engine._process_one(
                            self.pool, None, SETTINGS, SimpleNamespace()  # type: ignore[arg-type]
                        )
                    )
                    await self.avancer_l_horloge()
        escalade.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
