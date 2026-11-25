from __future__ import annotations

import unittest

from sentimail_v3.supervision.benchmark import evaluate_sample, summarize
from sentimail_v3.supervision.training import SCHEMA

DOSSIER = {
    "schema": SCHEMA,
    "clues": [
        {
            "clue_code": "AUTH_DMARC_PASS",
            "article_code": "AUTH-002",
            "direction": "favorable",
            "strength": 30,
            "confidence": 1.0,
            "statement": "DMARC authentifie le domaine visible.",
            "occurrence_count": 1,
        }
    ],
    "evidence_families": ["identite"],
    "converging_families": [],
    "counts": {"favorable": 1, "adverse": 0, "neutral": 0},
    "investigation_status": "complete",
    "attachments": 0,
    "judgment_rules": {
        "confidence_required": 0.9,
        "deep_execution_complete": True,
        "static_investigation_complete": True,
        "authenticated_sender_policy": "none",
        "material_danger_evidence": [],
    },
    "deep_analysis": {"complete": True, "url_coverage": {}, "signals": []},
    "history": {},
    "learned_signals": [],
}


class BenchmarkTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_valid_candidate_is_measured_with_the_production_parser(
        self,
    ) -> None:
        async def call(messages: list[dict[str, str]]):
            self.assertIn("DOSSIER À EXAMINER", messages[-1]["content"])
            return (
                """{
                  "unfavorable":{"clue_codes":[],"arguments":[]},
                  "favorable":{"clue_codes":["AUTH_DMARC_PASS"],"arguments":["Authentifié."]},
                  "attack":{"techniques":[],"impersonated_brand":null,"targeted":false},
                  "final_verdict":{"classification":"legitimate","confidence":0.99,
                    "delivery_decision":"deliver","rationale":"Identité authentifiée.",
                    "doubt":false,"doubt_reasons":[]}
                }""",
                {
                    "model": "local-test",
                    "usage": {"prompt_eval_count": 10, "eval_count": 4},
                },
            )

        result = await evaluate_sample(
            {"sample_id": 1, "human_label": "legitimate", "dossier": DOSSIER},
            call,
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["outcome"], "deliver")
        self.assertEqual(result["prompt_tokens"], 10)

    async def test_an_invalid_candidate_abstains_and_fails_the_gate(self) -> None:
        async def call(messages: list[dict[str, str]]):
            return "pas du json", {}

        result = await evaluate_sample(
            {"sample_id": 2, "human_label": "spam", "dossier": DOSSIER},
            call,
        )
        summary = summarize(
            [result],
            dataset_manifest={"dataset_id": "abc", "schema_version": SCHEMA},
            model="bad-model",
            provider="ollama",
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["outcome"], "ask_user")
        self.assertFalse(summary["operational_gate"]["passed"])
        self.assertFalse(summary["security_gate"]["eligible"])
        self.assertEqual(summary["unsafe_deliveries"], 0)


if __name__ == "__main__":
    unittest.main()
