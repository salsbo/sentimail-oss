from __future__ import annotations

import unittest

from sentimail_v3.code.knowledge import reference_for_clues


class _Pool:
    """Sert des passages différents selon la nature demandée."""

    def __init__(self) -> None:
        self.natures: list[object] = []

    async def fetch(self, query: str, *args: object) -> list[dict[str, object]]:
        nature = next((a for a in args if a in ("normative", "adversarial")), None)
        self.natures.append(nature)
        if nature is None:
            return []
        titre = "RFC 7489" if nature == "normative" else "Techniques d'usurpation"
        return [
            {
                "source_id": f"{nature}-1",
                "title": titre,
                "url": "https://example.org",
                "section": "1. Section",
                "body": "corps du passage " * 10,
                "embedding": None,
                "rank": 1.0,
            }
        ]


class ReferenceForCluesTests(unittest.IsolatedAsyncioTestCase):
    async def test_les_deux_corpus_sont_interroges(self) -> None:
        """Les normes disent ce qui doit être, la doctrine adverse ce qui se trame."""
        pool = _Pool()

        passages = await reference_for_clues(
            pool,  # type: ignore[arg-type]
            ["IDENTITY_BRAND_MISMATCH", "AUTH_DMARC_FAIL"],
        )

        natures = {str(p.get("nature")) for p in passages}
        self.assertIn("normative", natures)
        self.assertIn("adversarial", natures)

    async def test_chaque_passage_dit_de_quel_corpus_il_vient(self) -> None:
        pool = _Pool()

        passages = await reference_for_clues(
            pool,  # type: ignore[arg-type]
            ["IDENTITY_BRAND_MISMATCH"],
        )

        for passage in passages:
            self.assertIn(passage["nature"], ("normative", "adversarial"))
            self.assertTrue(passage["document"])

    async def test_sans_indice_aucune_question_n_est_posee(self) -> None:
        pool = _Pool()

        self.assertEqual(await reference_for_clues(pool, []), [])  # type: ignore[arg-type]
        self.assertEqual(pool.natures, [])


if __name__ == "__main__":
    unittest.main()


class QuestionLanguageTests(unittest.IsolatedAsyncioTestCase):
    """Chaque corpus s'interroge dans sa langue, sans jamais lire le message."""

    async def test_la_doctrine_francaise_est_interrogee_en_francais(self) -> None:
        from sentimail_v3.code import knowledge

        demandes: dict[str, str] = {}

        async def espion(pool, question, *, nature=None, **kwargs):
            demandes[str(nature)] = question
            return []

        original = knowledge.search
        knowledge.search = espion
        try:
            await knowledge.reference_for_clues(None, ["IDENTITY_BRAND_MISMATCH"])
        finally:
            knowledge.search = original

        # Les normes sont en anglais et nomment les codes ; la doctrine est en
        # français et ne les connaît pas.
        self.assertIn("IDENTITY BRAND MISMATCH", demandes["normative"])
        self.assertIn("marque", demandes["adversarial"].casefold())

    async def test_la_question_adverse_ne_vient_toujours_que_des_indices(self) -> None:
        from sentimail_v3.code import knowledge

        demandes: dict[str, str] = {}

        async def espion(pool, question, *, nature=None, **kwargs):
            demandes[str(nature)] = question
            return []

        original = knowledge.search
        knowledge.search = espion
        try:
            await knowledge.reference_for_clues(None, ["CONTENT_URGENCY"])
        finally:
            knowledge.search = original

        self.assertIn("vite", demandes["adversarial"].casefold())
