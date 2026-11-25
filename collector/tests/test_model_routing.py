from __future__ import annotations

import unittest

from sentimail_v3.judgment.model_routing import (
    escalation_reasons,
    initial_route,
    same_outcome,
    unsafe_delivery_divergence,
)
from sentimail_v3.supervision.model_routing import enforcement_blocker


def dossier(
    *directions: str,
    deep_complete: bool = True,
    static_complete: bool = True,
    material: bool = False,
    sender_policy: str = "none",
) -> dict[str, object]:
    return {
        "clues": [
            {"clue_code": f"C{index}", "direction": direction}
            for index, direction in enumerate(directions)
        ],
        "judgment_rules": {
            "confidence_required": 0.90,
            "deep_execution_complete": deep_complete,
            "static_investigation_complete": static_complete,
            "incomplete_analysis_is_decisive": True,
            "material_danger_evidence": [{"kind": "x"}] if material else [],
            "authenticated_sender_policy": sender_policy,
        },
    }


def verdict(
    decision: str = "deliver",
    classification: str = "legitimate",
    confidence: float = 0.98,
    doubt: bool = False,
) -> dict[str, object]:
    return {
        "delivery_decision": decision,
        "classification": classification,
        "confidence": confidence,
        "verdict_doubt": doubt,
    }


class InitialRouteTests(unittest.TestCase):
    def test_une_charge_seule_va_directement_au_premium(self) -> None:
        self.assertEqual(initial_route(dossier("adverse")),
                         ("premium", "adverse_only_evidence"))

    def test_a_complete_univocal_case_starts_on_economy(self) -> None:
        self.assertEqual(
            initial_route(dossier("favorable")),
            ("economy", "simple_univocal_dossier"),
        )

    def test_mixed_evidence_goes_directly_to_premium(self) -> None:
        self.assertEqual(
            initial_route(dossier("favorable", "adverse")),
            ("premium", "mixed_evidence"),
        )

    def test_material_or_incomplete_cases_are_premium(self) -> None:
        self.assertEqual(initial_route(dossier("adverse", material=True))[0], "premium")
        self.assertEqual(
            initial_route(dossier("favorable", deep_complete=False))[0], "premium"
        )
        self.assertEqual(
            initial_route(dossier("favorable", static_complete=False))[0], "premium"
        )
        self.assertEqual(
            initial_route(dossier("favorable", sender_policy="hold"))[0], "premium"
        )


class EscalationTests(unittest.TestCase):
    def test_only_a_clear_high_confidence_delivery_can_stay_economy(self) -> None:
        self.assertEqual(
            escalation_reasons(verdict(), dossier("favorable"), 0.05), []
        )
        self.assertEqual(
            escalation_reasons(
                verdict(confidence=0.95), dossier("favorable"), 0.05
            ),
            [],
        )

    def test_doubt_low_margin_and_non_delivery_escalate(self) -> None:
        reasons = escalation_reasons(
            verdict("ask_user", "suspect", 0.92, True),
            dossier("adverse"),
            0.05,
        )
        self.assertIn("non_delivery_decision", reasons)
        self.assertIn("verdict_doubt", reasons)
        self.assertIn("confidence_margin", reasons)

    def test_delivery_despite_adverse_evidence_escalates(self) -> None:
        self.assertIn(
            "adverse_evidence_on_delivery",
            escalation_reasons(verdict(), dossier("adverse"), 0.05),
        )

    def test_unsafe_divergence_is_flash_deliver_vs_pro_hold(self) -> None:
        flash = verdict()
        pro = verdict("ask_user", "suspect", 0.95, True)
        self.assertFalse(same_outcome(flash, pro))
        self.assertTrue(unsafe_delivery_divergence(flash, pro))
        self.assertFalse(unsafe_delivery_divergence(pro, flash))


class EnforcementGuardTests(unittest.TestCase):
    def test_fifty_samples_without_unsafe_divergence_are_required(self) -> None:
        self.assertIn("insuffisant", enforcement_blocker(49, 49, 0) or "")
        self.assertIn("dangereuse", enforcement_blocker(50, 50, 1) or "")
        self.assertIn("accord", enforcement_blocker(50, 47, 0) or "")
        self.assertIsNone(enforcement_blocker(50, 48, 0))


if __name__ == "__main__":
    unittest.main()
