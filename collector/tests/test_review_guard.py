from __future__ import annotations

from contextlib import asynccontextmanager
import json
import re
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from sentimail_v3.execution.review_guard import (
    FAIL_CLOSED_RETRIES,
    FAIL_CLOSED_RETRY_SECONDS,
    MISSING_NOTICE_GRACE_SECONDS,
    NOTICE_QUEUE_ATTEMPTS,
    abandon_undeliverable_notice,
    fail_open_for_exhausted_outbox,
    fail_open_held_message,
    hold_with_review_or_fail_open,
    reconcile_one_review_hold,
)


class _RecordingPool:
    """Un pool qui retient ce qui a été écrit, sans base derrière."""

    def __init__(self, message_id: str | None) -> None:
        self.message_id = message_id
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    @asynccontextmanager
    async def acquire(self):
        yield self

    @asynccontextmanager
    async def transaction(self):
        yield self

    async def execute(self, query: str, *args: object) -> str:
        self.calls.append((query, args))
        return "UPDATE 1"

    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        return self.message_id

    def wrote(self, fragment: str) -> list[tuple[str, tuple[object, ...]]]:
        return [call for call in self.calls if fragment in call[0]]


class UndeliverableNoticeTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_avis_refuse_definitivement_clot_le_dossier(self) -> None:
        """Sans boîte où écrire, on ferme : ni nouvel envoi, ni attente sans fin."""
        pool = _RecordingPool("message-id")

        result = await abandon_undeliverable_notice(
            pool,  # type: ignore[arg-type]
            "action-id",
            error="550 5.1.1 User unknown",
        )

        self.assertEqual(result, "undeliverable")
        transitions = pool.wrote("UPDATE messages")
        self.assertEqual(len(transitions), 1)
        self.assertIn("undeliverable", transitions[0][1])
        self.assertTrue(pool.wrote("UPDATE smtp_actions"))
        self.assertTrue(pool.wrote("INSERT INTO audit_log"))

    async def test_un_avis_sans_dossier_ouvert_ne_clot_rien(self) -> None:
        pool = _RecordingPool(None)

        result = await abandon_undeliverable_notice(
            pool,  # type: ignore[arg-type]
            "action-id",
            error="550 5.1.1 User unknown",
        )

        self.assertIsNone(result)
        self.assertEqual(pool.wrote("UPDATE messages"), [])


class ReviewGuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_successful_notice_protects_hold(self) -> None:
        pool = SimpleNamespace(execute=AsyncMock())
        invitations = SimpleNamespace(queue_invitation=AsyncMock(return_value=True))

        result = await hold_with_review_or_fail_open(
            pool,  # type: ignore[arg-type]
            SimpleNamespace(),  # type: ignore[arg-type]
            invitations,  # type: ignore[arg-type]
            "message-id",
        )

        self.assertEqual(result, "review_notice_queued")
        invitations.queue_invitation.assert_awaited_once_with(
            "message-id", decision_mode=True
        )

    async def test_notice_construction_failure_delivers_original_fail_open(self) -> None:
        pool = SimpleNamespace(execute=AsyncMock())
        invitations = SimpleNamespace(
            queue_invitation=AsyncMock(side_effect=NameError("renderer failed"))
        )
        with patch(
            "sentimail_v3.execution.review_guard.fail_open_held_message",
            new=AsyncMock(return_value="released"),
        ) as fail_open, patch(
            "sentimail_v3.execution.review_guard.asyncio.sleep", new=AsyncMock()
        ):
            result = await hold_with_review_or_fail_open(
                pool,  # type: ignore[arg-type]
                SimpleNamespace(),  # type: ignore[arg-type]
                invitations,  # type: ignore[arg-type]
                "message-id",
            )

        self.assertEqual(result, "released")
        self.assertEqual(
            invitations.queue_invitation.await_count, NOTICE_QUEUE_ATTEMPTS
        )
        fail_open.assert_awaited_once()
        self.assertEqual(
            fail_open.await_args.kwargs["reason"],
            "review_notice_queue_failed_fail_open",
        )

    async def test_false_queue_result_delivers_original_fail_open(self) -> None:
        pool = SimpleNamespace(execute=AsyncMock())
        invitations = SimpleNamespace(queue_invitation=AsyncMock(return_value=False))
        with patch(
            "sentimail_v3.execution.review_guard.fail_open_held_message",
            new=AsyncMock(return_value="released"),
        ) as fail_open:
            result = await hold_with_review_or_fail_open(
                pool,  # type: ignore[arg-type]
                SimpleNamespace(),  # type: ignore[arg-type]
                invitations,  # type: ignore[arg-type]
                "message-id",
            )

        self.assertEqual(result, "released")
        self.assertEqual(
            fail_open.await_args.kwargs["reason"],
            "review_notice_not_queued_fail_open",
        )

    async def test_reconciler_recreates_a_missing_review_notice(self) -> None:
        pool = SimpleNamespace(
            fetchval=AsyncMock(return_value="message-id"),
            fetchrow=AsyncMock(),
            execute=AsyncMock(),
        )
        invitations = SimpleNamespace(queue_invitation=AsyncMock(return_value=True))

        worked = await reconcile_one_review_hold(
            pool,  # type: ignore[arg-type]
            SimpleNamespace(),  # type: ignore[arg-type]
            invitations,  # type: ignore[arg-type]
        )

        self.assertTrue(worked)
        invitations.queue_invitation.assert_awaited_once_with(
            "message-id", decision_mode=True
        )

    async def test_exhausted_review_delivery_releases_original(self) -> None:
        pool = SimpleNamespace(fetchval=AsyncMock(return_value="message-id"))
        with patch(
            "sentimail_v3.execution.review_guard.fail_open_held_message",
            new=AsyncMock(return_value="released"),
        ) as fail_open:
            result = await fail_open_for_exhausted_outbox(
                pool,  # type: ignore[arg-type]
                SimpleNamespace(),  # type: ignore[arg-type]
                "action-id",
            )

        self.assertEqual(result, "released")
        self.assertEqual(
            fail_open.await_args.kwargs["reason"],
            "review_notice_delivery_exhausted_fail_open",
        )


class _GuardPool:
    """Un pool qui répond selon la requête, comme le relevé du superviseur.

    Le dossier est décrit par sa classification, son état de livraison et
    l'existence d'une preuve matérielle ; tout ce qui s'écrit est retenu.
    """

    def __init__(
        self,
        *,
        classification: str | None = None,
        status: str = "analyzing",
        material: bool = False,
        missing: str | None = None,
    ) -> None:
        self.classification = classification
        self.status = status
        self.material = material
        self.missing = missing
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    @asynccontextmanager
    async def acquire(self):
        yield self

    @asynccontextmanager
    async def transaction(self):
        yield self

    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        if "'final_judgment'->>'classification'" in query:
            return self.classification
        if "delivery_barrier" in query:
            return self.material
        if "FROM messages m" in query and "review_notice_pending" in query:
            return self.missing
        if "delivery_status" in query and "FROM messages" in query:
            return self.status
        return None

    async def fetchrow(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        if "verdict_runs" in query:
            return {"rationale": "Plusieurs indices concordants.", "techniques": "[]"}
        return None

    async def fetch(self, query: str, *args: object) -> list[dict[str, object]]:
        self.calls.append((query, args))
        if "FROM clues c" in query:
            return [
                {
                    "clue_code": "NOUVEL_INDICE",
                    "statement": "Le message insiste pour obtenir une réponse immédiate.",
                    "facts": {},
                }
            ]
        return []

    async def execute(self, query: str, *args: object) -> str:
        self.calls.append((query, args))
        return "UPDATE 1"

    def writes(self, fragment: str) -> list[tuple[str, tuple[object, ...]]]:
        return [
            call
            for call in self.calls
            if call[0].lstrip().startswith(("UPDATE", "INSERT"))
            and (fragment in call[0] or any(fragment in str(arg) for arg in call[1]))
        ]

    def audits(self, action: str) -> list[dict[str, object]]:
        return [
            json.loads(str(args[1]))
            for query, args in self.calls
            if "INSERT INTO audit_log" in query and args and args[0] == action
        ]


class NouvelleTentativeTests(unittest.IsolatedAsyncioTestCase):
    """Une panne passagère de mise en file ne déclenche plus le secours d'emblée."""

    async def test_une_panne_passagere_de_mise_en_file_est_retentee(self) -> None:
        pool = _GuardPool()
        invitations = SimpleNamespace(
            queue_invitation=AsyncMock(side_effect=[RuntimeError("base"), True])
        )
        with patch(
            "sentimail_v3.execution.review_guard.fail_open_held_message",
            new=AsyncMock(),
        ) as secours, patch(
            "sentimail_v3.execution.review_guard.asyncio.sleep", new=AsyncMock()
        ) as sleep:
            result = await hold_with_review_or_fail_open(
                pool,  # type: ignore[arg-type]
                SimpleNamespace(),  # type: ignore[arg-type]
                invitations,  # type: ignore[arg-type]
                "message-id",
            )

        self.assertEqual(result, "review_notice_queued")
        secours.assert_not_awaited()
        sleep.assert_awaited_once_with(1.0)
        self.assertEqual(pool.audits("review.hold_protected")[0]["attempts"], 2)

    async def test_un_refus_de_mise_en_file_n_est_pas_retente(self) -> None:
        pool = _GuardPool()
        invitations = SimpleNamespace(queue_invitation=AsyncMock(return_value=False))
        with patch(
            "sentimail_v3.execution.review_guard.fail_open_held_message",
            new=AsyncMock(return_value="held_fail_closed"),
        ) as secours, patch(
            "sentimail_v3.execution.review_guard.asyncio.sleep", new=AsyncMock()
        ) as sleep:
            await hold_with_review_or_fail_open(
                pool,  # type: ignore[arg-type]
                SimpleNamespace(),  # type: ignore[arg-type]
                invitations,  # type: ignore[arg-type]
                "message-id",
            )

        invitations.queue_invitation.assert_awaited_once()
        sleep.assert_not_awaited()
        self.assertEqual(
            secours.await_args.kwargs["reason"], "review_notice_not_queued_fail_open"
        )

    async def test_les_tentatives_sont_bornees(self) -> None:
        pool = _GuardPool()
        panne = RuntimeError("base")
        invitations = SimpleNamespace(queue_invitation=AsyncMock(side_effect=panne))
        with patch(
            "sentimail_v3.execution.review_guard.fail_open_held_message",
            new=AsyncMock(return_value="held_fail_closed"),
        ) as secours, patch(
            "sentimail_v3.execution.review_guard.asyncio.sleep", new=AsyncMock()
        ) as sleep:
            await hold_with_review_or_fail_open(
                pool,  # type: ignore[arg-type]
                SimpleNamespace(),  # type: ignore[arg-type]
                invitations,  # type: ignore[arg-type]
                "message-id",
            )

        self.assertEqual(invitations.queue_invitation.await_count, 3)
        self.assertEqual([c.args for c in sleep.await_args_list], [(1.0,), (3.0,)])
        self.assertEqual(
            secours.await_args.kwargs["reason"], "review_notice_queue_failed_fail_open"
        )
        self.assertIs(secours.await_args.kwargs["error"], panne)

    async def test_un_avis_retrouve_leve_la_retenue_fermee(self) -> None:
        pool = _GuardPool()
        invitations = SimpleNamespace(queue_invitation=AsyncMock(return_value=True))

        await hold_with_review_or_fail_open(
            pool,  # type: ignore[arg-type]
            SimpleNamespace(),  # type: ignore[arg-type]
            invitations,  # type: ignore[arg-type]
            "message-id",
        )

        leve = [
            query
            for query, _ in pool.calls
            if '"review_guard":"recovered"' in query and "'fail_closed'" in query
        ]
        self.assertEqual(len(leve), 1)


class RouteDeSecoursTests(unittest.IsolatedAsyncioTestCase):
    """Le secours relit le dernier jugement avant d'agir, sans jamais le retoucher."""

    async def _secours(
        self, pool: _GuardPool, *, material: bool = False
    ) -> tuple[str, AsyncMock]:
        with patch(
            "sentimail_v3.execution.review_guard.release_original",
            new=AsyncMock(return_value="released"),
        ) as livraison, patch(
            "sentimail_v3.execution.review_guard.has_material_danger",
            new=AsyncMock(return_value=material),
        ):
            result = await fail_open_held_message(
                pool,  # type: ignore[arg-type]
                SimpleNamespace(),  # type: ignore[arg-type]
                "message-id",
                reason="review_notice_queue_failed_fail_open",
                error=RuntimeError("base"),
            )
        return result, livraison

    def _assert_retenu(
        self, pool: _GuardPool, result: str, livraison: AsyncMock
    ) -> None:
        self.assertEqual(result, "held_fail_closed")
        livraison.assert_not_awaited()
        transitions = pool.writes("UPDATE messages")
        self.assertEqual(len(transitions), 1)
        self.assertEqual(transitions[0][1][1], "held")
        dossiers = pool.writes("UPDATE delivery_cases")
        self.assertEqual(len(dossiers), 1)
        requete, args = dossiers[0]
        self.assertIn("original_delivery_allowed=false", requete)
        self.assertIn(
            "WHEN state='observation_only' THEN 'review_notice_pending'", requete
        )
        self.assertIn("review_guard_attempts", requete)
        details = json.loads(str(args[1]))
        self.assertEqual(details["review_guard"], "fail_closed")
        self.assertEqual(
            details["review_guard_reason"], "review_notice_queue_failed_fail_open"
        )
        self.assertEqual(details["review_guard_error"], "RuntimeError")
        self.assertEqual(len(pool.audits("review.fail_closed")), 1)
        self.assertEqual(pool.audits("review.fail_open_requested"), [])
        self.assertEqual(pool.writes("UPDATE smtp_actions"), [])

    async def test_un_dangereux_n_est_jamais_livre_en_secours(self) -> None:
        pool = _GuardPool(classification="dangerous")
        result, livraison = await self._secours(pool)
        self._assert_retenu(pool, result, livraison)
        audit = pool.audits("review.fail_closed")[0]
        self.assertEqual(audit["classification"], "dangerous")
        self.assertIs(audit["material_danger"], False)

    async def test_une_preuve_materielle_retient_quel_que_soit_le_classement(
        self,
    ) -> None:
        pool = _GuardPool(classification="undetermined")
        result, livraison = await self._secours(pool, material=True)
        self._assert_retenu(pool, result, livraison)

    async def test_sans_jugement_la_preuve_materielle_retient(self) -> None:
        # Chemin d'erreur du verdict : trois échecs, aucun jugement écrit.
        pool = _GuardPool(classification=None)
        result, livraison = await self._secours(pool, material=True)
        self._assert_retenu(pool, result, livraison)

    async def test_un_indesirable_part_par_le_circuit_indesirables(self) -> None:
        pool = _GuardPool(classification="spam")
        result, livraison = await self._secours(pool)

        self.assertEqual(result, "released")
        livraison.assert_awaited_once()
        self.assertEqual(livraison.await_args.kwargs["classify_as"], "spam")
        self.assertTrue(livraison.await_args.kwargs["classify_reasons"])
        persistes = [
            json.loads(str(args[1]))
            for _, args in pool.writes("fail_open_classify_as")
        ]
        self.assertEqual(len(persistes), 1)
        self.assertEqual(persistes[0]["fail_open_classify_as"], "spam")
        self.assertTrue(persistes[0]["junk_reasons"])
        demande = pool.audits("review.fail_open_requested")[0]
        self.assertEqual(demande["route"], "junk")
        self.assertEqual(demande["classification"], "spam")
        self.assertTrue(pool.writes('"review_guard":"fail_open_junk"'))
        self.assertEqual(
            pool.audits("review.fail_open_completed")[0]["route"], "junk"
        )

    async def test_des_motifs_illisibles_n_empechent_pas_le_circuit_indesirables(
        self,
    ) -> None:
        pool = _GuardPool(classification="spam")

        async def fetch(query: str, *args: object) -> list[dict[str, object]]:
            raise RuntimeError("indices illisibles")

        pool.fetch = fetch  # type: ignore[method-assign]
        result, livraison = await self._secours(pool)

        self.assertEqual(result, "released")
        self.assertEqual(livraison.await_args.kwargs["classify_as"], "spam")
        self.assertEqual(livraison.await_args.kwargs["classify_reasons"], [])

    async def test_un_douteux_garde_le_secours_en_boite_de_reception(self) -> None:
        pool = _GuardPool(classification="suspect")
        result, livraison = await self._secours(pool)

        self.assertEqual(result, "released")
        livraison.assert_awaited_once()
        self.assertIsNone(livraison.await_args.kwargs.get("classify_as"))
        self.assertEqual(
            pool.audits("review.fail_open_requested")[0]["route"], "inbox"
        )
        self.assertTrue(pool.writes('"review_guard":"fail_open"'))
        self.assertEqual(pool.writes("fail_open_classify_as"), [])

    async def test_un_message_deja_livre_n_est_pas_retenu_apres_coup(self) -> None:
        pool = _GuardPool(classification="dangerous", status="delivered")
        result, livraison = await self._secours(pool)

        self.assertEqual(result, "already_resolved")
        livraison.assert_not_awaited()
        self.assertEqual(pool.writes(""), [])


class ReconciliateurTests(unittest.IsolatedAsyncioTestCase):
    async def _reconcilier(self, pool: _GuardPool) -> bool:
        return await reconcile_one_review_hold(
            pool,  # type: ignore[arg-type]
            SimpleNamespace(),  # type: ignore[arg-type]
            SimpleNamespace(queue_invitation=AsyncMock()),  # type: ignore[arg-type]
        )

    async def test_une_retenue_fermee_n_est_pas_reclamee_a_chaque_passage(
        self,
    ) -> None:
        pool = _GuardPool(missing=None)

        self.assertFalse(await self._reconcilier(pool))

        candidate = [
            query
            for query, _ in pool.calls
            if "JOIN assistant_outbox ao" in query and "ao.status!='sent'" in query
        ]
        self.assertEqual(len(candidate), 1)
        self.assertIn(
            "coalesce(dc.details->>'review_guard','') <> 'fail_closed'", candidate[0]
        )

    async def test_les_retentatives_de_la_retenue_fermee_sont_bornees(self) -> None:
        pool = _GuardPool(missing=None)

        await self._reconcilier(pool)

        requete, args = pool.calls[0]
        self.assertIn("review_guard_attempts", requete)
        self.assertEqual(
            args,
            (
                MISSING_NOTICE_GRACE_SECONDS,
                FAIL_CLOSED_RETRIES,
                FAIL_CLOSED_RETRY_SECONDS,
            ),
        )
        self.assertEqual((FAIL_CLOSED_RETRIES, FAIL_CLOSED_RETRY_SECONDS), (3, 600))
        # Chaque paramètre a sa valeur : un décalage ferait échouer la
        # réconciliation à chaque passage, sans autre trace qu'un journal.
        self.assertEqual(
            max(int(n) for n in re.findall(r"\$(\d+)", requete)), len(args)
        )

    async def test_l_abandon_ne_pretend_plus_livrer(self) -> None:
        pool = _GuardPool(missing=None)

        async def fetchrow(query: str, *args: object) -> object:
            pool.calls.append((query, args))
            return {
                "id": 7,
                "status": "error",
                "attempts": 5,
                "message_id": "message-id",
            }

        pool.fetchrow = fetchrow  # type: ignore[method-assign]
        await self._reconcilier(pool)

        claim = [query for query, _ in pool.calls if "UPDATE assistant_outbox" in query]
        self.assertEqual(len(claim), 1)
        self.assertIn("abandoned by review guard", claim[0])
        self.assertNotIn("delivered fail-open", claim[0])


if __name__ == "__main__":
    unittest.main()
