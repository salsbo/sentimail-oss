from __future__ import annotations

import unittest

from sentimail_v3.code.doctrine_learning import Profile, store_note


class _Pool:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        return 42

    async def execute(self, query: str, *args: object) -> str:
        self.calls.append((query, args))
        return "OK"

    def wrote(self, fragment: str) -> list[tuple[str, tuple[object, ...]]]:
        return [call for call in self.calls if fragment in call[0]]


def _profil() -> Profile:
    return Profile(
        label="spam",
        signals=("IDENTITY_BRAND_MISMATCH", "AUTH_DMARC_FAIL"),
        message_count=3,
        sender_count=3,
        first_seen="2026-08-14",
        last_seen="2026-08-16",
        message_ids=("1", "2", "3"),
    )


class StoreNoteTests(unittest.IsolatedAsyncioTestCase):
    async def test_la_fiche_entre_au_corpus_sous_sa_propre_nature(self) -> None:
        """« learned » la distingue des normes et de la doctrine écrite à la main."""
        pool = _Pool()

        await store_note(pool, _profil())  # type: ignore[arg-type]

        documents = pool.wrote("INSERT INTO knowledge_documents")
        self.assertEqual(len(documents), 1)
        requete, arguments = documents[0]
        self.assertIn("learned", requete + str(arguments))

    async def test_la_fiche_est_decoupee_en_passages_interrogeables(self) -> None:
        pool = _Pool()

        await store_note(pool, _profil())  # type: ignore[arg-type]

        self.assertTrue(pool.wrote("INSERT INTO knowledge_chunks"))

    async def test_reecrire_une_fiche_remplace_ses_passages(self) -> None:
        # Sinon les versions successives s'accumulent et le corpus se contredit.
        pool = _Pool()

        await store_note(pool, _profil())  # type: ignore[arg-type]

        self.assertTrue(pool.wrote("DELETE FROM knowledge_chunks"))
