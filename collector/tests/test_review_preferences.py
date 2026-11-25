"""Ce qu'un destinataire a choisi de recevoir de MAIA, lu sans modèle."""

from __future__ import annotations

import unittest

from sentimail_v3.conversation.review_preferences import (
    ASK_ONLY_ON_REAL_DOUBT,
    asks_only_on_real_doubt,
)


class _Pool:
    def __init__(self, value: object) -> None:
        self.value = value
        self.calls: list[tuple[object, ...]] = []

    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append(args)
        return self.value


class RealDoubtPreferenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_par_defaut_tout_doute_reste_une_question(self) -> None:
        self.assertFalse(await asks_only_on_real_doubt(_Pool(None), ["a@exemple.test"]))

    async def test_le_choix_pose_est_lu_pour_l_adresse_exacte(self) -> None:
        pool = _Pool(True)
        self.assertTrue(await asks_only_on_real_doubt(pool, ["A@Exemple.test"]))
        self.assertEqual(pool.calls, [("A@Exemple.test", ASK_ONLY_ON_REAL_DOUBT)])

    async def test_un_destinataire_absent_ne_lit_rien(self) -> None:
        pool = _Pool(True)
        self.assertFalse(await asks_only_on_real_doubt(pool, []))
        self.assertFalse(await asks_only_on_real_doubt(pool, [""]))
        self.assertEqual(pool.calls, [])

    async def test_un_message_a_plusieurs_destinataires_garde_ses_questions(self) -> None:
        # Revue de sécurité du 15 octobre 2026 : le choix d'un destinataire ne
        # doit pas gouverner le verdict d'un autre. Le MX sépare aujourd'hui
        # chaque destinataire (6 614 messages, tous à un seul), cette garde
        # tient si cela change.
        pool = _Pool(True)
        self.assertFalse(
            await asks_only_on_real_doubt(pool, ["choix@exemple.test", "autre@exemple.test"])
        )
        self.assertEqual(pool.calls, [])
