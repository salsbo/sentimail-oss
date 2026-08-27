from __future__ import annotations

import json
import os
import unittest
from typing import Any

import asyncpg
from sentimail_v3.code import knowledge
from sentimail_v3.code.knowledge import reference_for_clues
from sentimail_v3.judgment.verdict_engine import _fit_dossier, _parse_verdict

RULES = {
    "verdict_is_final": True,
    "confidence_required": 0.90,
    "deep_execution_complete": True,
    "static_investigation_complete": True,
    "material_danger_evidence": [],
    "authenticated_sender_policy": "none",
}


def _verdict(rationale: str) -> str:
    return json.dumps(
        {
            "unfavorable": {"clue_codes": [], "arguments": []},
            "favorable": {"clue_codes": [], "arguments": []},
            "final_verdict": {
                "classification": "suspect",
                "confidence": 0.7,
                "delivery_decision": "ask_user",
                "rationale": rationale,
                "doubt": True,
                "doubt_reasons": [],
            },
        }
    )


class SelectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_the_message_never_chooses_what_is_quoted(self) -> None:
        """Le corps du mail ne doit pas piloter la recherche documentaire."""
        demandes: list[str] = []

        async def espion(pool: Any, question: str, **kwargs: Any) -> list[Any]:
            demandes.append(question)
            return []

        original = knowledge.search
        knowledge.search = espion
        try:
            await reference_for_clues(
                None,
                ["AUTH_DMARC_FAIL", "URL_CLOAKING"],
            )
        finally:
            knowledge.search = original
        # Un corpus interrogé par question : les normes avec les codes eux-mêmes,
        # la doctrine française avec leur traduction. Ce qui compte n'est pas
        # leur forme, mais que chacune dérive des seuls indices observés - le
        # corps du message n'entre dans aucune des deux.
        from sentimail_v3.code.plain_words import plain_clue

        self.assertEqual(len(demandes), 2)
        attendues = {
            "AUTH DMARC FAIL URL CLOAKING",
            " ".join(
                filter(None, (plain_clue(c, "") for c in ("AUTH_DMARC_FAIL", "URL_CLOAKING")))
            ).strip(),
        }
        self.assertEqual(set(demandes), attendues)

    async def test_without_a_single_clue_nothing_is_quoted(self) -> None:
        original = knowledge.search

        async def jamais(pool: Any, question: str, **kwargs: Any) -> list[Any]:
            raise AssertionError("aucune recherche ne doit partir")

        knowledge.search = jamais
        try:
            self.assertEqual(await reference_for_clues(None, []), [])
        finally:
            knowledge.search = original


class DossierTests(unittest.TestCase):
    def test_knowledge_is_bounded_not_dropped_when_space_runs_out(self) -> None:
        # La doctrine partait la première quand elle n'était qu'un confort
        # d'explication. Depuis qu'elle nomme aussi les montages d'attaque,
        # la supprimer revenait à juger sans savoir de quoi il s'agit : elle
        # est désormais raccourcie, jamais jetée.
        dossier: dict[str, Any] = {
            "reference_knowledge": {"passages": [{"text": "x" * 4000}]},
            "clues": [{"clue_code": "AUTH_DMARC_PASS", "statement": "y" * 200}],
            "message": {"body_text": "z" * 200_000},
        }
        fitted = _fit_dossier(dossier)
        self.assertIn("reference_knowledge", fitted)
        self.assertLessEqual(
            len(fitted["reference_knowledge"]["passages"][0]["text"]), 500
        )
        # Les indices, eux, restent : ce sont eux qui fondent la décision.
        self.assertTrue(fitted["clues"])


class ValidationTests(unittest.TestCase):
    def _dossier(self, texte: str) -> dict[str, Any]:
        return {
            "clues": [
                {"id": 1, "clue_code": "AUTH_DMARC_FAIL", "direction": "adverse"}
            ],
            "judgment_rules": RULES,
            "reference_knowledge": {
                "probative_value": "none",
                "passages": [{"document": "RFC 7489", "section": "3.1", "text": texte}],
            },
        }

    def test_a_reference_quoted_from_a_norm_does_not_look_invented(self) -> None:
        # Les RFC citent leurs propres identifiants ; recopiés dans une
        # motivation, ils ressemblent à des codes de preuve.
        dossier = self._dossier("L'alignement compare AUTH-RESULTS et RFC5322.From.")
        parsed = _parse_verdict(
            _verdict("Selon la norme, AUTH-RESULTS décrit l'authentification."),
            dossier,
        )
        self.assertEqual(parsed["classification"], "suspect")

    def test_an_article_of_the_code_can_be_named_even_without_a_clue(self) -> None:
        # Le dossier porte tout le Code applicable : le modèle peut dire qu'un
        # article ne s'applique pas, sans qu'un indice l'ait déclenché.
        dossier = self._dossier("Un texte de norme.")
        dossier["code_articles"] = [
            {"article_code": "NATURE-002", "title": "Envoi de masse"}
        ]
        parsed = _parse_verdict(
            _verdict("NATURE-002 ne s'applique pas : aucun envoi de masse établi."),
            dossier,
        )
        self.assertEqual(parsed["classification"], "suspect")

    def test_an_invented_reference_is_still_refused(self) -> None:
        dossier = self._dossier("Un texte de norme sans identifiant particulier.")
        with self.assertRaisesRegex(ValueError, "AUTH_SPF_MISSING"):
            _parse_verdict(
                _verdict("AUTH_SPF_MISSING prouve la fraude."),
                dossier,
            )


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class CorpusTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])

    async def asyncTearDown(self) -> None:
        await self.pool.close()

    async def test_an_empty_corpus_is_not_a_failure(self) -> None:
        # Aucun document chargé : le verdict se rend sans connaissance.
        passages = await reference_for_clues(self.pool, ["AUTH_DMARC_PASS"])
        self.assertEqual(passages, [])


if __name__ == "__main__":
    unittest.main()
