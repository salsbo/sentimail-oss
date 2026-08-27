from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from sentimail_v3.supervision.watchdog import (
    DEGRADED_THRESHOLDS,
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

    async def fetchrow(self, query: str, *args: object) -> _Counters | None:
        # instance_identity interroge sa propre table : sans ligne posée, elle
        # doit retomber sur l'environnement (settings), pas sur les compteurs.
        if "instance_identity" in query:
            return None
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
                "silent_holds": 1,
                "unprotected_holds": 1,
                "outbox_errors": 1,
            }
        )
        self.assertIn("smtp_events_without_queue_id", reasons)
        self.assertIn("verdict_execution_mismatches", reasons)
        self.assertIn("silent_holds", reasons)
        self.assertIn("unprotected_holds", reasons)
        self.assertIn("outbox_errors", reasons)

    async def test_les_messages_anterieurs_a_un_enqueteur_ne_l_accusent_pas(self) -> None:
        """Ajouter un enquêteur ne doit pas dénoncer le passé.

        Les messages analysés avant son déploiement n'ont évidemment pas sa
        trace : les compter ferait sonner l'alerte à chaque ajout, pendant
        toute la fenêtre d'observation.
        """
        from sentimail_v3.supervision.watchdog import _snapshot as snap

        import inspect

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
        pool = SimpleNamespace(
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
        pool = SimpleNamespace(
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
        pool = SimpleNamespace(
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
        pool = SimpleNamespace(
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
