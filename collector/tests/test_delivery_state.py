from __future__ import annotations

import unittest

from sentimail_v3.execution.delivery_state import (
    ANALYZING,
    CONSUMED,
    DEFERRED,
    DELIVERED,
    HELD,
    ORIGINS,
    RELEASE_PENDING,
    SUPPRESSED,
    TERMINAL,
    UNDELIVERABLE,
    move,
)


class _Executor:
    """Enregistre la requête et simule le nombre de lignes touchées."""

    def __init__(self, moved: bool = True) -> None:
        self.moved = moved
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    async def execute(self, query: str, *args: object) -> str:
        self.calls.append((query, args))
        return f"UPDATE {1 if self.moved else 0}"


class DeliveryStateTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_transition_says_whether_it_happened(self) -> None:
        executor = _Executor(moved=True)
        self.assertTrue(await move(executor, "id", HELD))
        refused = _Executor(moved=False)
        self.assertFalse(await move(refused, "id", HELD))

    async def test_the_allowed_origins_travel_with_the_update(self) -> None:
        executor = _Executor()
        await move(executor, "id", HELD)
        _, args = executor.calls[0]
        self.assertEqual(args[1], HELD)
        self.assertEqual(set(args[2]), set(ORIGINS[HELD]))

    async def test_an_unknown_state_is_refused_before_any_write(self) -> None:
        executor = _Executor()
        with self.assertRaises(ValueError):
            await move(executor, "id", "inventé")
        self.assertEqual(executor.calls, [])

    def test_a_delivered_message_is_never_reopened(self) -> None:
        for target, origins in ORIGINS.items():
            for terminal in TERMINAL:
                self.assertNotIn(
                    terminal,
                    origins,
                    f"{terminal} ne doit jamais mener à {target}",
                )

    def test_analysis_never_resumes_after_a_decision(self) -> None:
        self.assertNotIn(HELD, ORIGINS[ANALYZING])
        self.assertNotIn(RELEASE_PENDING, ORIGINS[ANALYZING])

    def test_a_user_reply_is_consumed_only_from_intake(self) -> None:
        self.assertEqual(set(ORIGINS[CONSUMED]), {"captured", ANALYZING})

    def test_un_destinataire_inexistant_conclut_le_dossier(self) -> None:
        """Sans boîte où livrer, le dossier se ferme au lieu d'attendre sans fin."""
        self.assertIn(UNDELIVERABLE, TERMINAL)
        for origin in (HELD, DEFERRED, RELEASE_PENDING):
            self.assertIn(origin, ORIGINS[UNDELIVERABLE])

    def test_a_release_can_still_conclude_in_delivery(self) -> None:
        self.assertIn(RELEASE_PENDING, ORIGINS[DELIVERED])
        self.assertIn(HELD, ORIGINS[DELIVERED])

    def test_une_livraison_en_preparation_peut_revenir_a_la_retenue(self) -> None:
        """Un courrier qui n'a pas pu être composé revient à la retenue.

        Seul ce chemin-là : un envoi différé repasse par release_pending avant
        d'être composé, et un état terminal ne se rouvre jamais.
        """
        self.assertIn(RELEASE_PENDING, ORIGINS[HELD])
        self.assertNotIn(DEFERRED, ORIGINS[HELD])
        for terminal in TERMINAL:
            self.assertNotIn(terminal, ORIGINS[HELD])

    def test_authenticated_block_is_a_terminal_non_smtp_outcome(self) -> None:
        self.assertIn(SUPPRESSED, TERMINAL)
        self.assertIn(ANALYZING, ORIGINS[SUPPRESSED])
        self.assertNotIn(SUPPRESSED, ORIGINS[DELIVERED])


if __name__ == "__main__":
    unittest.main()
