"""Les essais du juge s'espacent quand le fournisseur traîne.

Nuit du 15 octobre 2026 : entre 1 h et 5 h UTC, l'API du modèle répondait
`HTTP 200` puis ne terminait jamais sa réponse. Le dossier M-e4b2cb a épuisé
ses trois essais en 37 minutes, tous pendant la même lenteur, puis il est
resté bloqué. Un essai repris aussitôt après un dépassement de délai retombe
sur la même panne : il consomme un appel et rapproche l'abandon sans rien
apprendre de plus.

Après un échec passager du modèle, le nouvel essai attend donc 15 minutes,
puis 1 heure, puis 4 heures. L'escalade vers l'humain ne vient qu'après
l'échec du quatrième essai. Les autres erreurs gardent leur cadence : trois
essais rapprochés, puis l'escalade.
"""

from __future__ import annotations

import inspect
import json
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

from sentimail_v3 import llm
from sentimail_v3.judgment import workflow as verdict_engine, verdict_retry
from sentimail_v3.judgment.verdict_engine import VerdictQuotaExceeded
from sentimail_v3.judgment.verdict_retry import is_transient, plan_retry
from sentimail_v3.llm import LlmError

DELAI = LlmError("délai total de 120 s dépassé")


class CalendrierTests(unittest.TestCase):
    def test_le_premier_echec_passager_planifie_un_essai_dans_15_minutes(self) -> None:
        plan = plan_retry(1, DELAI)
        self.assertEqual(plan.kind, "scheduled")
        self.assertEqual(plan.delay, timedelta(minutes=15))
        self.assertFalse(plan.exhausted)

    def test_le_deuxieme_echec_passager_planifie_un_essai_dans_une_heure(self) -> None:
        plan = plan_retry(2, DELAI)
        self.assertEqual(plan.kind, "scheduled")
        self.assertEqual(plan.delay, timedelta(hours=1))

    def test_le_troisieme_echec_passager_planifie_un_essai_dans_quatre_heures(self) -> None:
        plan = plan_retry(3, DELAI)
        self.assertEqual(plan.kind, "scheduled")
        self.assertEqual(plan.delay, timedelta(hours=4))

    def test_l_echec_du_quatrieme_essai_epuise_le_dossier(self) -> None:
        plan = plan_retry(4, DELAI)
        self.assertEqual(plan.kind, "exhausted")
        self.assertIsNone(plan.delay)
        self.assertTrue(plan.exhausted)

    def test_un_essai_de_plus_apres_un_redemarrage_reste_epuise(self) -> None:
        # Un essai interrompu par un redémarrage compte : le compteur peut
        # dépasser quatre, il ne relance jamais le calendrier.
        self.assertTrue(plan_retry(5, DELAI).exhausted)

    def test_quatre_essais_au_total_sur_cinq_heures_quinze_d_attente(self) -> None:
        self.assertEqual(verdict_retry.MAX_TRANSIENT_ATTEMPTS, 4)
        attente = sum(
            (plan_retry(n, DELAI).delay for n in range(1, 4)), timedelta()
        )
        self.assertEqual(attente, timedelta(hours=5, minutes=15))


class ErreursNonPassageresTests(unittest.TestCase):
    """Les erreurs non passagères gardent leur cadence historique."""

    CAS = (
        ValueError("verdict JSON invalide"),
        KeyError("classification"),
        VerdictQuotaExceeded("global_hourly"),
        RuntimeError("authenticated suppression was not applied"),
        LlmError("LLM HTTP 402"),
        LlmError("LLM HTTP 401"),
        LlmError("LLM HTTP 400"),
        LlmError("Anthropic HTTP 403"),
        LlmError("aucun fournisseur LLM n'est configuré"),
        LlmError("fichier de secret fournisseur refusé"),
    )

    def test_deux_essais_rapproches_puis_l_escalade_au_troisieme(self) -> None:
        for exc in self.CAS:
            with self.subTest(exc=repr(exc)):
                self.assertEqual(plan_retry(1, exc).kind, "immediate")
                self.assertEqual(plan_retry(2, exc).kind, "immediate")
                self.assertTrue(plan_retry(3, exc).exhausted)

    def test_le_plafond_historique_reste_trois(self) -> None:
        self.assertEqual(verdict_retry.MAX_ATTEMPTS, 3)
        self.assertEqual(verdict_engine.MAX_ATTEMPTS, 3)


class ClassificationTests(unittest.TestCase):
    def test_les_pannes_passageres_du_modele(self) -> None:
        for message in (
            "délai total de 120 s dépassé",
            "délai total de 30 s dépassé",
            "LLM HTTP 429",
            "LLM HTTP 500",
            "LLM HTTP 502",
            "LLM HTTP 503",
            "LLM HTTP 504",
            "LLM HTTP 408",
            "Anthropic HTTP 529",
            "réponse LLM invalide",
            "réponse LLM vide",
        ):
            with self.subTest(message=message):
                self.assertTrue(is_transient(LlmError(message)))

    def test_un_refus_ou_une_configuration_n_est_pas_passager(self) -> None:
        for message in (
            "LLM HTTP 402",
            "LLM HTTP 400",
            "LLM HTTP 401",
            "LLM HTTP 403",
            "LLM HTTP 404",
            "LLM HTTP 422",
            "aucun fournisseur LLM n'est configuré",
            "fichier de secret fournisseur refusé",
            "aucune adresse de modèle local configurée",
        ):
            with self.subTest(message=message):
                self.assertFalse(is_transient(LlmError(message)))

    def test_seule_une_llm_error_peut_etre_passagere(self) -> None:
        # Le périmètre validé : l'échec du modèle. Une erreur de transport
        # brute n'est pas convertie ici ; elle garde la cadence historique.
        self.assertFalse(is_transient(RuntimeError("délai total de 120 s dépassé")))
        self.assertFalse(is_transient(httpx.ConnectError("refused")))

    def test_les_marques_de_configuration_existent_dans_le_client(self) -> None:
        # Si llm.py reformule un de ces messages, la classification
        # tomberait en « passager » sans que rien ne casse : ce test casse.
        source = inspect.getsource(llm)
        for marque in verdict_retry.CONFIGURATION_FAILURES:
            with self.subTest(marque=marque):
                self.assertIn(marque, source)


class _Pool:
    def __init__(self) -> None:
        self.execute = AsyncMock()
        self.fetchval = AsyncMock(return_value="e4b2cb16-4e3f-4e0a-a08e-849366869596")


def _run(attempts: int) -> dict[str, object]:
    return {
        "id": "78936160-3e99-48b3-9599-30cdc0e92277",
        "investigation_id": "e8e8de50-dff4-46f0-8d72-5586c8692035",
        "message_id": "e4b2cb16-4e3f-4e0a-a08e-849366869596",
        "model_name": "deepseek-v4-pro",
        "attempts": attempts,
    }


class EscaladeTests(unittest.IsolatedAsyncioTestCase):
    """L'escalade humaine suit le plan rendu par `_mark_error`, et lui seul."""

    async def _echoue(self, attempts: int, exc: Exception) -> tuple[AsyncMock, dict]:
        escalade = AsyncMock(return_value="review_notice_queued")
        with (
            patch.object(verdict_engine, "_claim", AsyncMock(return_value=_run(attempts))),
            patch.object(verdict_engine, "move", AsyncMock()),
            patch.object(verdict_engine, "_express_judgment", AsyncMock(side_effect=exc)),
            patch.object(verdict_engine, "hold_with_review_or_fail_open", escalade),
            self.assertLogs("sentimail-v3-verdict", level="ERROR") as journal,
        ):
            traite = await verdict_engine._process_one(
                _Pool(),  # type: ignore[arg-type]
                None,  # type: ignore[arg-type]
                SimpleNamespace(decision_mode=True),  # type: ignore[arg-type]
                SimpleNamespace(queue_invitation=AsyncMock()),  # type: ignore[arg-type]
            )
        self.assertTrue(traite)
        lignes = [json.loads(record.getMessage()) for record in journal.records]
        return escalade, next(l for l in lignes if l["event"] == "verdict.error")

    async def test_aucune_escalade_tant_qu_un_essai_espace_reste(self) -> None:
        for attempts in (1, 2, 3):
            with self.subTest(attempts=attempts):
                escalade, ligne = await self._echoue(attempts, DELAI)
                escalade.assert_not_awaited()
                self.assertEqual(ligne["retry"], "scheduled")
                self.assertEqual(
                    ligne["retry_in_seconds"],
                    int(plan_retry(attempts, DELAI).delay.total_seconds()),
                )

    async def test_l_escalade_vient_apres_l_echec_du_quatrieme_essai(self) -> None:
        escalade, ligne = await self._echoue(4, DELAI)
        escalade.assert_awaited_once()
        self.assertEqual(ligne["retry"], "exhausted")

    async def test_une_erreur_non_passagere_garde_son_escalade_au_troisieme(self) -> None:
        escalade, ligne = await self._echoue(2, ValueError("JSON"))
        escalade.assert_not_awaited()
        self.assertEqual(ligne["retry"], "immediate")
        escalade, ligne = await self._echoue(3, ValueError("JSON"))
        escalade.assert_awaited_once()
        self.assertEqual(ligne["retry"], "exhausted")

    async def test_un_refus_de_credit_n_est_pas_espace(self) -> None:
        escalade, ligne = await self._echoue(3, LlmError("LLM HTTP 402"))
        escalade.assert_awaited_once()
        self.assertEqual(ligne["retry"], "exhausted")


class LettreDuSuperviseurTests(unittest.TestCase):
    def test_les_deux_signaux_sont_dits_en_francais_avec_un_geste(self) -> None:
        from sentimail_v3.supervision.watchdog import (
            DEGRADED_THRESHOLDS,
            SOFT_FAILURE_COUNTERS,
        )
        from sentimail_v3.supervision.watchdog_letter import _CONSIGNES, _RAISONS

        for code in ("verdict_retries_overdue", "verdict_retries_exhausted"):
            with self.subTest(code=code):
                self.assertEqual(DEGRADED_THRESHOLDS[code], 1)
                self.assertIn(code, _RAISONS)
                self.assertIn(code, _CONSIGNES)
        # Chaque nouvel épuisement réalerte ; un retard est un état.
        self.assertIn("verdict_retries_exhausted", SOFT_FAILURE_COUNTERS)
        self.assertNotIn("verdict_retries_overdue", SOFT_FAILURE_COUNTERS)

    def test_l_etape_dit_l_echeance_manquee(self) -> None:
        from sentimail_v3.supervision.watchdog_letter import _etape

        texte = _etape(
            {
                "run_status": "error",
                "run_attempts": 2,
                "run_error_type": "LlmError",
                "retry_overdue_seconds": 1260,
            }
        )
        self.assertIn("échoué 2 fois", texte)
        self.assertIn("il y a 21 min", texte)
        self.assertEqual(
            _etape({"run_status": "error", "run_attempts": 3, "run_error_type": "ValueError"}),
            "le juge a échoué 3 fois (ValueError)",
        )


class SuperviseurSansBaseTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_essai_en_retard_degrade_apres_deux_releves(self) -> None:
        from test_watchdog import _FreshBackup, _SnapshotPool, _snapshot_settings

        from sentimail_v3.supervision.watchdog import _snapshot

        with patch("sentimail_v3.supervision.watchdog.BACKUP_HEARTBEAT", _FreshBackup()):
            snapshot = await _snapshot(
                _SnapshotPool(verdict_retries_overdue=1),  # type: ignore[arg-type]
                _snapshot_settings(),  # type: ignore[arg-type]
                previously_observed=frozenset({"verdict_retries_overdue"}),
            )
        self.assertEqual(snapshot["details"]["verdict_retries_overdue"], 1)
        self.assertIn("verdict_retries_overdue", snapshot["details"]["reasons"])
        self.assertEqual(snapshot["status"], "degraded")


if __name__ == "__main__":
    unittest.main()
