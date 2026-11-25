from __future__ import annotations

from contextlib import asynccontextmanager
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from sentimail_v3.supervision.watchdog import (
    DEGRADED_THRESHOLDS,
    FAIL_CLOSED_SQL,
    FEEDBACK_INTEGRITY_SQL,
    SOFT_FAILURE_COUNTERS,
    _check,
    _confirmed_reasons,
    _counter_reasons,
    _increased_failure_counts,
    _smtp_envelope_preflight,
    _snapshot,
)


class _Counters:
    """Une ligne de compteurs : tout vaut zéro, sauf ce qu'on force."""

    def __init__(self, **values: int) -> None:
        self.values = values

    def __getitem__(self, key: str) -> int:
        return self.values.get(key, 0)


class _SnapshotPool:
    def __init__(self, **counters: int) -> None:
        self.counters = counters

    async def fetchrow(self, query: str, *args: object) -> _Counters | dict[str, object] | None:
        # instance_identity interroge sa propre table : sans ligne posée, elle
        # doit retomber sur l'environnement (settings), pas sur les compteurs.
        if "instance_identity" in query:
            return None
        if "core_rollout_config" in query:
            return {"mode": "legacy", "canary_percent": 0, "qualification_id": None}
        if "core_rollout_qualifications" in query:
            return None
        if "legacy_runs_inflight" in query:
            return {"legacy_runs_inflight": 0, "legacy_unclaimed": 0}
        return _Counters(**self.counters)

    async def fetchval(self, query: str, *args: object) -> int:
        for name, value in self.counters.items():
            if name in query:
                return value
        return 0

    async def fetch(self, query: str, *args: object) -> list[object]:
        return []


def _snapshot_settings() -> SimpleNamespace:
    return SimpleNamespace(
        watchdog_smtp_preflight_enabled=False,
        probe_enabled=False,
        verdict_llm_hourly_limit=100,
        verdict_llm_daily_limit=1000,
        retention_enabled=False,
        retention_redact_after_days=30,
        # Repli d'instance_identity quand aucune ligne n'est posée en base.
        action_address="maia@sentinel.mondomaine.example",
        action_aliases=(),
        assistant_sender="MAIA <maia@mondomaine.example>",
        probe_recipient="probe@sentinel.mondomaine.example",
    )


def _check_settings() -> SimpleNamespace:
    """Réglages minimaux pour `_check` : identity retombe sur l'environnement."""
    return SimpleNamespace(
        action_address="maia@sentinel.mondomaine.example",
        action_aliases=(),
        assistant_sender="MAIA <maia@mondomaine.example>",
        probe_recipient="probe@sentinel.mondomaine.example",
    )


def _tx_pool(**attrs: object) -> SimpleNamespace:
    """Faux pool qui supporte `async with pool.acquire() as conn, conn.transaction():`."""
    pool = SimpleNamespace(**attrs)

    @asynccontextmanager
    async def _acquire():
        yield pool

    @asynccontextmanager
    async def _transaction():
        yield pool

    pool.acquire = _acquire
    pool.transaction = _transaction
    return pool


def _fetchrow_side_effect(previous_row: object):
    """`fetchrow` de `_check` : la ligne `operational_status`, puis None pour
    `instance_identity` afin que le repli sur l'environnement s'applique."""

    async def _fetchrow(query: str, *args: object) -> object:
        if "instance_identity" in query:
            return None
        return previous_row

    return _fetchrow


class _FreshBackup:
    def exists(self) -> bool:
        return True

    def stat(self) -> SimpleNamespace:
        import time

        return SimpleNamespace(st_mtime=time.time())


class WatchdogTests(unittest.IsolatedAsyncioTestCase):
    def test_supervisor_never_ignores_a_broken_workflow(self) -> None:
        """Une rupture du flux se signale dès la première occurrence."""
        reasons = _counter_reasons(
            {
                "smtp_events_without_queue_id": 1,
                "verdict_execution_mismatches": 1,
                "feedback_application_mismatches": 1,
                "verdict_provider_credit_exhausted": 1,
                "silent_holds": 1,
                "unprotected_holds": 1,
                "outbox_errors": 1,
                "suppressed_without_event": 1,
            }
        )
        self.assertIn("smtp_events_without_queue_id", reasons)
        self.assertIn("verdict_execution_mismatches", reasons)
        self.assertIn("feedback_application_mismatches", reasons)
        self.assertIn("verdict_provider_credit_exhausted", reasons)
        self.assertIn("silent_holds", reasons)
        self.assertIn("unprotected_holds", reasons)
        self.assertIn("outbox_errors", reasons)
        self.assertIn("suppressed_without_event", reasons)

    async def test_un_solde_llm_epuise_est_mesure_explicitement(self) -> None:
        pool = _SnapshotPool(verdict_provider_credit_exhausted=1)
        with patch(
            "sentimail_v3.supervision.watchdog.BACKUP_HEARTBEAT", _FreshBackup()
        ):
            snapshot = await _snapshot(
                pool,  # type: ignore[arg-type]
                _snapshot_settings(),  # type: ignore[arg-type]
                previously_observed=frozenset({"verdict_provider_credit_exhausted"}),
            )

        self.assertEqual(
            snapshot["details"]["verdict_provider_credit_exhausted"], 1
        )
        self.assertIn(
            "verdict_provider_credit_exhausted", snapshot["details"]["reasons"]
        )

    async def test_un_retour_sans_effet_est_mesure_explicitement(self) -> None:
        pool = _SnapshotPool(feedback_application_mismatches=1)
        with patch(
            "sentimail_v3.supervision.watchdog.BACKUP_HEARTBEAT", _FreshBackup()
        ):
            snapshot = await _snapshot(
                pool,  # type: ignore[arg-type]
                _snapshot_settings(),  # type: ignore[arg-type]
                previously_observed=frozenset(
                    {"feedback_application_mismatches"}
                ),
            )

        self.assertEqual(
            snapshot["details"]["feedback_application_mismatches"], 1
        )
        self.assertIn(
            "feedback_application_mismatches", snapshot["details"]["reasons"]
        )

    async def test_les_messages_anterieurs_a_un_enqueteur_ne_l_accusent_pas(self) -> None:
        """Ajouter un enquêteur ne doit pas dénoncer le passé.

        Les messages analysés avant son déploiement n'ont évidemment pas sa
        trace : les compter ferait sonner l'alerte à chaque ajout, pendant
        toute la fenêtre d'observation.
        """
        import inspect

        from sentimail_v3.supervision.watchdog import _snapshot as snap

        source = inspect.getsource(snap)
        self.assertIn("MIN(hr.created_at)", source.replace("min(", "MIN("))

    async def test_un_enqueteur_profond_qui_ne_tourne_plus_est_signale(self) -> None:
        """Un contrôle qui cesse de tourner disparaît en silence, sans ceci."""
        pool = _SnapshotPool(missing_deep_hook_runs=1)
        with patch("sentimail_v3.supervision.watchdog.BACKUP_HEARTBEAT", _FreshBackup()):
            snapshot = await _snapshot(
                pool,  # type: ignore[arg-type]
                _snapshot_settings(),  # type: ignore[arg-type]
                previously_observed=frozenset({"missing_deep_hook_runs"}),
            )

        self.assertEqual(snapshot["details"]["missing_deep_hook_runs"], 1)
        self.assertIn("missing_deep_hook_runs", snapshot["details"]["reasons"])

    async def test_un_indesirable_livre_en_boite_de_reception_est_signale(self) -> None:
        """Le contraire du contrôle existant : un junk décidé, jamais classé."""
        pool = _SnapshotPool(junk_not_filed=1)
        with patch("sentimail_v3.supervision.watchdog.BACKUP_HEARTBEAT", _FreshBackup()):
            snapshot = await _snapshot(
                pool,  # type: ignore[arg-type]
                _snapshot_settings(),  # type: ignore[arg-type]
                previously_observed=frozenset({"junk_not_filed"}),
            )

        self.assertEqual(snapshot["details"]["junk_not_filed"], 1)
        self.assertIn("junk_not_filed", snapshot["details"]["reasons"])

    def test_un_echec_fail_soft_isole_ne_degrade_pas(self) -> None:
        """Un sous-module qui échoue sans casser le pipeline est nominal."""
        self.assertEqual(_counter_reasons({"hook_errors_last_hour": 1}), [])
        self.assertEqual(
            _counter_reasons({"external_analysis_service_errors_last_hour": 2}), []
        )

    def test_des_echecs_fail_soft_repetes_degradent(self) -> None:
        reasons = _counter_reasons(
            {
                "hook_errors_last_hour": 3,
                "external_analysis_service_errors_last_hour": 5,
            }
        )
        self.assertIn("hook_errors_last_hour", reasons)
        self.assertIn("external_analysis_service_errors_last_hour", reasons)

    def test_chaque_compteur_surveille_porte_un_seuil(self) -> None:
        """Aucun compteur ne doit sortir de la surveillance par oubli."""
        for counter in SOFT_FAILURE_COUNTERS:
            self.assertIn(counter, DEGRADED_THRESHOLDS)

    def test_une_degradation_vue_une_seule_fois_ne_declenche_rien(self) -> None:
        """Un pic résorbé dans la minute n'est pas une dégradation du service."""
        self.assertEqual(_confirmed_reasons(["analysis_backlog"], []), [])

    def test_une_degradation_qui_persiste_declenche(self) -> None:
        self.assertEqual(
            _confirmed_reasons(["analysis_backlog"], ["analysis_backlog"]),
            ["analysis_backlog"],
        )

    async def test_une_premiere_observation_reste_ok_mais_est_retenue(self) -> None:
        pool = _SnapshotPool(silent_holds=1)
        with patch("sentimail_v3.supervision.watchdog.BACKUP_HEARTBEAT", _FreshBackup()):
            snapshot = await _snapshot(
                pool,  # type: ignore[arg-type]
                _snapshot_settings(),  # type: ignore[arg-type]
                previously_observed=frozenset(),
            )

        self.assertEqual(snapshot["status"], "ok")
        self.assertEqual(snapshot["details"]["reasons"], [])
        self.assertIn("silent_holds", snapshot["details"]["observed_reasons"])

    async def test_une_seconde_observation_degrade(self) -> None:
        pool = _SnapshotPool(silent_holds=1)
        with patch("sentimail_v3.supervision.watchdog.BACKUP_HEARTBEAT", _FreshBackup()):
            snapshot = await _snapshot(
                pool,  # type: ignore[arg-type]
                _snapshot_settings(),  # type: ignore[arg-type]
                previously_observed=frozenset({"silent_holds"}),
            )

        self.assertEqual(snapshot["status"], "degraded")
        self.assertEqual(snapshot["details"]["reasons"], ["silent_holds"])

    def test_supervisor_detects_another_occurrence_of_an_existing_failure(self) -> None:
        increases = _increased_failure_counts(
            {"hook_errors_last_hour": 1, "missing_deep_evidence": 2},
            {"hook_errors_last_hour": 2, "missing_deep_evidence": 2},
        )
        self.assertEqual(increases, {"hook_errors_last_hour": 1})

    async def test_smtp_preflight_stops_before_data(self) -> None:
        smtp = SimpleNamespace(
            connect=AsyncMock(),
            ehlo=AsyncMock(),
            mail=AsyncMock(),
            rcpt=AsyncMock(),
            rset=AsyncMock(),
            quit=AsyncMock(),
        )
        constructor = MagicMock(return_value=smtp)
        with patch("sentimail_v3.supervision.watchdog.aiosmtplib.SMTP", constructor):
            result = await _smtp_envelope_preflight(
                "collector", 2525, "maia@example.org", "user@example.org"
            )

        self.assertEqual(result["status"], "ok")
        smtp.mail.assert_awaited_once_with("maia@example.org")
        smtp.rcpt.assert_awaited_once_with("user@example.org")
        smtp.rset.assert_awaited_once()
        self.assertFalse(hasattr(smtp, "data"))

    async def test_le_tick_transmet_ce_qui_avait_ete_observe(self) -> None:
        """Sans mémoire du tick précédent, aucune dégradation ne se confirme."""
        previous = {
            "status": "ok",
            "details": {"reasons": [], "observed_reasons": ["silent_holds"]},
        }
        pool = _tx_pool(
            fetchrow=AsyncMock(side_effect=_fetchrow_side_effect(previous)),
            fetchval=AsyncMock(return_value="ok"),
            execute=AsyncMock(),
        )
        snapshot = {"status": "ok", "details": {"reasons": [], "observed_reasons": []}}
        with (
            patch(
                "sentimail_v3.supervision.watchdog._snapshot",
                AsyncMock(return_value=snapshot),
            ) as snapshot_call,
            patch("sentimail_v3.supervision.watchdog.set_status"),
        ):
            await _check(pool, _check_settings())  # type: ignore[arg-type]

        self.assertEqual(
            set(snapshot_call.await_args.kwargs["previously_observed"]),
            {"silent_holds"},
        )

    async def test_first_degraded_snapshot_sends_an_alert(self) -> None:
        pool = _tx_pool(
            fetchrow=AsyncMock(side_effect=_fetchrow_side_effect(None)),
            fetchval=AsyncMock(return_value=None),
            execute=AsyncMock(),
        )
        snapshot = {"status": "degraded", "details": {"reasons": ["silent_holds"]}}
        with (
            patch("sentimail_v3.supervision.watchdog._snapshot", AsyncMock(return_value=snapshot)),
            patch("sentimail_v3.supervision.watchdog._notify", AsyncMock(return_value="QUEUE1")) as notify,
            patch("sentimail_v3.supervision.watchdog.set_status") as set_status,
        ):
            await _check(pool, _check_settings())  # type: ignore[arg-type]

        notify.assert_awaited_once()
        # Le superviseur publie sa propre sante : un systeme degrade ne le rend
        # pas muet, et son conteneur doit rester exploitable.
        set_status.assert_called_with("watchdog", "ok")
        historised = [
            call.args
            for call in pool.execute.await_args_list
            if "operational_events" in str(call.args[0])
        ]
        self.assertEqual(len(historised), 1)
        self.assertEqual(historised[0][1], "degraded")

    async def test_failed_alert_is_persisted_and_retried(self) -> None:
        pool = _tx_pool(
            fetchrow=AsyncMock(side_effect=_fetchrow_side_effect(None)),
            fetchval=AsyncMock(return_value=None),
            execute=AsyncMock(),
        )
        snapshot = {"status": "degraded", "details": {"reasons": ["relay_down"]}}
        with (
            patch("sentimail_v3.supervision.watchdog._snapshot", AsyncMock(return_value=snapshot)),
            patch(
                "sentimail_v3.supervision.watchdog._notify",
                AsyncMock(side_effect=RuntimeError("relay unavailable")),
            ) as notify,
            patch("sentimail_v3.supervision.watchdog.set_status") as set_status,
        ):
            with self.assertRaises(RuntimeError):
                await _check(pool, _check_settings())  # type: ignore[arg-type]

        notify.assert_awaited_once()
        set_status.assert_called_with("watchdog", "down")
        stored_payloads = [
            str(call.args)
            for call in pool.execute.await_args_list
            if "operational_status" in str(call.args[0])
        ]
        self.assertTrue(any("alert_pending" in payload for payload in stored_payloads))

    async def test_recovered_relay_reports_the_previously_pending_incident(self) -> None:
        previous = {
            "status": "down",
            "details": {"reasons": ["smtp_relay_preflight_failed"], "alert_pending": True},
        }
        pool = _tx_pool(
            fetchrow=AsyncMock(side_effect=_fetchrow_side_effect(previous)),
            fetchval=AsyncMock(return_value="down"),
            execute=AsyncMock(),
        )
        snapshot = {"status": "ok", "details": {"reasons": []}}
        with (
            patch("sentimail_v3.supervision.watchdog._snapshot", AsyncMock(return_value=snapshot)),
            patch("sentimail_v3.supervision.watchdog._notify", AsyncMock(return_value="QUEUE2")) as notify,
            patch("sentimail_v3.supervision.watchdog.set_status"),
        ):
            await _check(pool, _check_settings())  # type: ignore[arg-type]

        self.assertEqual(notify.await_args.args[3], "down")
        self.assertIn(
            "smtp_relay_preflight_failed",
            notify.await_args.args[4]["reasons"],
        )


if __name__ == "__main__":
    unittest.main()


class ApaisementDesAlertesTests(unittest.IsolatedAsyncioTestCase):
    """Une même dégradation ne réveille pas deux fois en six heures."""

    def _details(self, **history: object) -> dict:
        return {
            "reasons": ["external_analysis_service_errors_last_hour"],
            "external_analysis_service_errors_last_hour": 3,
            "alert_history": dict(history) if history else {},
        }

    async def _check_with(
        self, previous_status: str, previous_details: dict, snapshot: dict
    ) -> list[str]:
        from unittest.mock import AsyncMock, patch

        from sentimail_v3.supervision import watchdog as module

        sent: list[str] = []

        async def fake_notify(settings, action_address, assistant_sender, status, details):
            sent.append(status)
            return "QUEUE"

        previous_row = {"status": previous_status, "details": previous_details}

        async def fake_fetchrow(query: str, *args: object) -> object:
            # `_check` relit la ligne `operational_status`, puis
            # `instance_identity` relit son singleton : sans ligne posée, ce
            # dernier retombe sur `settings` (repli fail-soft).
            if "instance_identity" in query:
                return None
            return previous_row

        pool = AsyncMock()
        pool.fetchrow = AsyncMock(side_effect=fake_fetchrow)
        pool.execute = AsyncMock()
        settings = SimpleNamespace(
            action_address="maia@sentinel.mondomaine.example",
            action_aliases=(),
            assistant_sender="MAIA <maia@mondomaine.example>",
            probe_recipient="probe@sentinel.mondomaine.example",
        )
        with (
            patch.object(module, "_snapshot", AsyncMock(return_value=snapshot)),
            patch.object(module, "_notify", side_effect=fake_notify),
            patch.object(module, "_store_status", AsyncMock()),
            patch.object(module, "set_status"),
        ):
            await module._check(pool, settings)
        return sent

    async def test_la_premiere_degradation_alerte(self) -> None:
        sent = await self._check_with(
            "ok",
            {"reasons": []},
            {"status": "degraded", "details": self._details()},
        )
        self.assertEqual(sent, ["degraded"])

    async def test_la_meme_degradation_recente_se_tait(self) -> None:
        from datetime import datetime, timedelta, timezone

        recent = (datetime.now(timezone.utc) - timedelta(minutes=50)).isoformat()
        previous = self._details(
            degraded_signature="external_analysis_service_errors_last_hour",
            degraded_sent_at=recent,
            episode_alerted=True,
        )
        # Nouvel épisode identique : compteur reparti de zéro puis revenu.
        courant = {"status": "degraded", "details": self._details()}
        courant["details"]["external_analysis_service_errors_last_hour"] = 9
        sent = await self._check_with("ok", previous, courant)
        self.assertEqual(sent, [])

    async def test_une_raison_nouvelle_alerte_malgre_le_silence(self) -> None:
        from datetime import datetime, timedelta, timezone

        recent = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        previous = self._details(
            degraded_signature="external_analysis_service_errors_last_hour",
            degraded_sent_at=recent,
            episode_alerted=True,
        )
        courant = {
            "status": "degraded",
            "details": {
                "reasons": ["verdict_errors_last_hour"],
                "verdict_errors_last_hour": 1,
            },
        }
        sent = await self._check_with("degraded", previous, courant)
        self.assertEqual(sent, ["degraded"])

    async def test_la_remission_d_une_alerte_retenue_reste_silencieuse(self) -> None:
        previous = self._details(episode_alerted=False)
        sent = await self._check_with(
            "degraded", previous, {"status": "ok", "details": {"reasons": []}}
        )
        self.assertEqual(sent, [])

    async def test_la_remission_d_une_alerte_envoyee_est_annoncee(self) -> None:
        previous = self._details(episode_alerted=True)
        sent = await self._check_with(
            "degraded", previous, {"status": "ok", "details": {"reasons": []}}
        )
        self.assertEqual(sent, ["ok"])


class RetourAppliquePuisRevoqueTests(unittest.TestCase):
    """Une autorisation retirée après coup n'est pas un retour sans effet.

    Le 2 septembre 2026, un choix « ce message est légitime » a créé sa règle
    d'autorisation à la microseconde près. Le 9, un opérateur l'a révoquée -
    fraude constatée - et une révocation désactive la règle au lieu d'en
    poser une opposée. Le contrôle d'intégrité ne voyait plus aucune règle
    active et concluait que le retour n'avait jamais été appliqué :
    l'exploitation est restée dégradée huit jours sur un geste volontaire.

    Faute de harnais SQL exécutable dans cette suite, le garde porte sur la
    requête elle-même : c'est la clause d'échappement qui doit exister.
    """

    def test_la_regle_attendue_desactivee_apres_le_retour_est_un_changement_d_avis(
        self,
    ) -> None:
        clause = FEEDBACK_INTEGRITY_SQL[
            FEEDBACK_INTEGRITY_SQL.index("f.expected_policy IS NOT NULL") :
        ]
        self.assertIn("p.action=f.expected_policy", clause)
        self.assertIn("p.active=false", clause)
        self.assertIn("p.updated_at > f.created_at", clause)

    def test_une_regle_desactivee_avant_le_retour_ne_l_excuse_pas(self) -> None:
        # La borne est bien la date du retour : une règle éteinte depuis
        # longtemps ne prouve pas qu'il a été pris en compte.
        self.assertNotIn("p.active=false\n            AND p.updated_at <", FEEDBACK_INTEGRITY_SQL)
        self.assertNotIn("p.updated_at >= f.created_at", FEEDBACK_INTEGRITY_SQL)

    def test_la_regle_opposee_reste_un_changement_d_avis(self) -> None:
        # L'ancienne clause ne disparaît pas : poser l'inverse et retirer
        # l'attendue sont deux gestes distincts, tous deux postérieurs.
        self.assertIn("p.action<>f.expected_policy", FEEDBACK_INTEGRITY_SQL)


class _PoolAvecAttente(_SnapshotPool):
    """Le faux pool rend un message en attente à la requête qui les cherche."""

    async def fetch(self, query: str, *args: object) -> list[object]:
        if "stalled" in query:
            return [
                {
                    "message_id": "28f2c85e-fc76-4851-abac-654c07d55ebf",
                    "subject": "Your Gaia membership has been canceled.",
                    "delivery_status": "analyzing",
                    "waiting_seconds": 671,
                    "run_status": "running",
                    "run_attempts": 1,
                    "run_error_type": None,
                    "llm_model": "deepseek-v4-flash",
                    "llm_stage": "economy",
                    "llm_since_seconds": 610,
                }
            ]
        return []


class MessagesEnAttenteTests(unittest.IsolatedAsyncioTestCase):
    async def test_le_releve_nomme_les_messages_en_attente(self) -> None:
        with patch("sentimail_v3.supervision.watchdog.BACKUP_HEARTBEAT", _FreshBackup()):
            snapshot = await _snapshot(
                _PoolAvecAttente(analysis_backlog=1),  # type: ignore[arg-type]
                _snapshot_settings(),  # type: ignore[arg-type]
            )
        attente = snapshot["details"]["stalled_messages"]
        self.assertEqual(len(attente), 1)
        self.assertEqual(attente[0]["subject"], "Your Gaia membership has been canceled.")
        self.assertEqual(attente[0]["llm_model"], "deepseek-v4-flash")
        self.assertEqual(attente[0]["waiting_seconds"], 671)


class RemissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_la_remission_raconte_l_episode(self) -> None:
        from datetime import datetime, timedelta, timezone

        debut = (datetime.now(timezone.utc) - timedelta(seconds=304)).isoformat()
        previous = {
            "status": "degraded",
            "details": {
                "reasons": ["analysis_backlog"],
                "stalled_messages": [
                    {
                        "message_id": "28f2c85e-fc76-4851-abac-654c07d55ebf",
                        "subject": "Your Gaia membership has been canceled.",
                    }
                ],
                "alert_history": {
                    "degraded_sent_at": debut,
                    "degraded_signature": "analysis_backlog",
                    "episode_alerted": True,
                },
            },
        }
        pool = _tx_pool(
            fetchrow=AsyncMock(side_effect=_fetchrow_side_effect(previous)),
            fetchval=AsyncMock(return_value="degraded"),
            fetch=AsyncMock(
                return_value=[
                    {
                        "message_id": "28f2c85e-fc76-4851-abac-654c07d55ebf",
                        "subject": "Your Gaia membership has been canceled.",
                        "delivery_status": "delivered",
                        "waited_seconds": 953,
                    }
                ]
            ),
            execute=AsyncMock(),
        )
        snapshot = {"status": "ok", "details": {"reasons": []}}
        with (
            patch("sentimail_v3.supervision.watchdog._snapshot", AsyncMock(return_value=snapshot)),
            patch("sentimail_v3.supervision.watchdog._notify", AsyncMock(return_value="QUEUE3")) as notify,
            patch("sentimail_v3.supervision.watchdog.set_status"),
        ):
            await _check(pool, _check_settings())  # type: ignore[arg-type]

        self.assertEqual(notify.await_args.args[3], "ok")
        episode = notify.await_args.args[4]["episode"]
        self.assertGreaterEqual(episode["duration_seconds"], 300)
        self.assertEqual(episode["messages"][0]["delivery_status"], "delivered")
        self.assertEqual(episode["messages"][0]["waited_seconds"], 953)
        # Le sort des messages est demandé avec leurs identifiants.
        self.assertIn("28f2c85e-fc76-4851-abac-654c07d55ebf", str(pool.fetch.await_args))


class SecoursDesRetenuesTests(unittest.IsolatedAsyncioTestCase):
    """Les chemins d'échec se voient : retenue fermée, secours, repli d'enveloppe."""

    async def _degrade(self, compteur: str) -> dict[str, object]:
        pool = _SnapshotPool(**{compteur: 1})
        with patch(
            "sentimail_v3.supervision.watchdog.BACKUP_HEARTBEAT", _FreshBackup()
        ):
            return await _snapshot(
                pool,  # type: ignore[arg-type]
                _snapshot_settings(),  # type: ignore[arg-type]
                previously_observed=frozenset({compteur}),
            )

    async def test_une_retenue_fermee_est_signalee(self) -> None:
        snapshot = await self._degrade("fail_closed_holds")
        self.assertEqual(snapshot["details"]["fail_closed_holds"], 1)
        self.assertIn("fail_closed_holds", snapshot["details"]["reasons"])
        self.assertEqual(snapshot["status"], "degraded")

    async def test_un_secours_de_retenue_est_signale(self) -> None:
        snapshot = await self._degrade("review_fail_open_last_hour")
        self.assertEqual(snapshot["details"]["review_fail_open_last_hour"], 1)
        self.assertIn("review_fail_open_last_hour", snapshot["details"]["reasons"])

    async def test_un_repli_d_enveloppe_est_signale(self) -> None:
        snapshot = await self._degrade("junk_envelope_fallbacks_last_hour")
        self.assertEqual(snapshot["details"]["junk_envelope_fallbacks_last_hour"], 1)
        self.assertIn(
            "junk_envelope_fallbacks_last_hour", snapshot["details"]["reasons"]
        )

    def test_une_retenue_fermee_n_est_pas_un_echec_passager(self) -> None:
        # Rien ne la résorbe seul : un compteur d'intégrité, comme les
        # retenues non protégées et silencieuses.
        self.assertNotIn("fail_closed_holds", SOFT_FAILURE_COUNTERS)
        self.assertEqual(DEGRADED_THRESHOLDS["fail_closed_holds"], 1)
        for compteur in (
            "review_fail_open_last_hour",
            "junk_envelope_fallbacks_last_hour",
        ):
            self.assertIn(compteur, SOFT_FAILURE_COUNTERS)
            self.assertEqual(DEGRADED_THRESHOLDS[compteur], 1)

    def test_la_retenue_fermee_ne_depend_pas_de_l_horodatage(self) -> None:
        # Chaque retentative réhorodate le dossier : un filtre sur l'heure
        # ferait clignoter le compteur, et l'alerte avec lui.
        self.assertNotIn("updated_at", FAIL_CLOSED_SQL)
        self.assertIn("fail_closed_holds", FAIL_CLOSED_SQL)
        self.assertIn("'ignored','closed'", FAIL_CLOSED_SQL)

    def test_verdict_execution_mismatches_ignore_une_retenue_fermee(self) -> None:
        # Le contrôle ne compare que la décision du verdict et celle du
        # jugement en base, que les chemins d'échec ne touchent pas. Pour
        # 'junk', rien ne regarde l'état de livraison : une retenue fermée,
        # un repli annoté ou un secours ne le font pas trébucher.
        import inspect

        from sentimail_v3.supervision.watchdog import _snapshot as snap

        source = inspect.getsource(snap)
        debut = source.index("verdict_execution_mismatches = await pool.fetchval(")
        fin = source.index("feedback_application_mismatches = await", debut)
        bloc = source[debut:fin]
        self.assertNotIn("'junk'", bloc)
        self.assertNotIn("review_guard", bloc)
        self.assertNotIn("junk_envelope", bloc)

    def test_l_exemple_d_audit_ne_casse_pas_le_releve(self) -> None:
        # Un identifiant d'audit mal formé ferait échouer la conversion en
        # uuid, donc tout le relevé du superviseur.
        import inspect

        from sentimail_v3.supervision.watchdog import _snapshot as snap

        source = inspect.getsource(snap)
        self.assertIn("al.payload->>'message_id' ~ '^[0-9a-f-]{36}$'", source)

