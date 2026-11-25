from __future__ import annotations

import json
import unittest

from sentimail_v3.supervision.training import (
    SCHEMA,
    canonical_dossier,
    compact_dossier,
    fingerprint,
    safe_teacher_target,
    split_group_hash,
)

DOSSIER = {
    "schema": "sentinel-verdict-dossier-v3-trial-roles",
    "message": {
        "subject": "Facture urgente à régler",
        "body_text": "Bonjour Alex, merci de virer 4200 euros sur IBAN FR76...",
        "from_header": "Compta <compta@fournisseur.example>",
        "favorable_points": 12,
        "adverse_points": 95,
        "investigation_status": "complete",
        "attachment_count": 1,
    },
    "selected_headers": [{"name": "subject", "value": "Facture urgente à régler"}],
    "entities": [{"value_normalized": "https://paiement.example/collecte?token=abc"}],
    "clues": [
        {
            "clue_code": "AUTH_DMARC_FAIL",
            "article_code": "AUTH-001",
            "direction": "adverse",
            "strength": 70,
            "confidence": 1.0,
            "statement": (
                "compta@fournisseur.example renvoie vers "
                "https://paiement.example/collecte?token=abc."
            ),
            "facts": {"raw": "compta@fournisseur.example"},
        },
        {
            "clue_code": "URL_SANDBOX_FORM",
            "article_code": "DEEP-002",
            "direction": "adverse",
            "strength": 60,
            "confidence": 0.9,
            "statement": "Un formulaire réclame des identifiants.",
            "facts": {"final_apexes": ["paiement.example"]},
        },
    ],
    "judgment_rules": {
        "confidence_required": 0.9,
        "deep_execution_complete": True,
        "trusted_sender": False,
        "material_danger_evidence": [],
    },
    "deep_analysis": {
        "complete": True,
        "url_coverage": {"actionable_total": 12},
        "signals": [{"article_code": "DEEP-002", "kind": "credential_form"}],
        "history": {
            "previous_message_count": 3,
            "ground_truth_labels": {"spam": 2},
            "persistent_allow": False,
            "sender_domain_age_days": 12,
        },
    },
    "learned_signals": [{"clue_code": "AUTH_DMARC_FAIL", "confirmed_adverse": 4}],
}


class CompactDossierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.view = compact_dossier(DOSSIER)
        self.text = json.dumps(self.view, ensure_ascii=False)

    def test_no_personal_content_survives(self) -> None:
        for leak in (
            "Facture urgente",
            "Bonjour Alex",
            "IBAN",
            "compta@fournisseur.example",
            "paiement.example/collecte",
            "token=abc",
        ):
            self.assertNotIn(leak, self.text, f"{leak} ne doit pas être conservé")

    def test_the_reasoning_survives_entirely(self) -> None:
        codes = {clue["clue_code"] for clue in self.view["clues"]}
        self.assertEqual(codes, {"AUTH_DMARC_FAIL", "URL_SANDBOX_FORM"})
        self.assertEqual(self.view["counts"]["adverse"], 2)
        self.assertEqual(self.view["counts"]["adverse_points"], 95)
        self.assertEqual(self.view["judgment_rules"]["confidence_required"], 0.9)
        self.assertTrue(self.view["deep_analysis"]["complete"])
        self.assertEqual(self.view["history"]["ground_truth_labels"], {"spam": 2})
        self.assertEqual(self.view["schema"], SCHEMA)
        self.assertTrue(all("statement" not in clue for clue in self.view["clues"]))

    def test_evidence_families_group_the_clues(self) -> None:
        # Les familles sont celles du jugement, tirées de l'article et non du
        # préfixe du code : l'apprentissage doit ranger les preuves comme le
        # jugement les a rangées.
        self.assertEqual(self.view["evidence_families"], ["identite", "liens"])

    def test_the_view_is_far_smaller_than_the_dossier(self) -> None:
        realistic = {
            **DOSSIER,
            "message": {**DOSSIER["message"], "body_text": "Contenu privé. " * 800},
        }
        complete = len(json.dumps(realistic, ensure_ascii=False))
        self.assertLess(len(self.text), complete)

    def test_the_fingerprint_is_stable_and_content_addressed(self) -> None:
        self.assertEqual(fingerprint(self.view), fingerprint(compact_dossier(DOSSIER)))
        other = compact_dossier({**DOSSIER, "clues": DOSSIER["clues"][:1]})
        self.assertNotEqual(fingerprint(self.view), fingerprint(other))

    def test_an_empty_dossier_never_raises(self) -> None:
        view = compact_dossier({})
        self.assertEqual(view["clues"], [])
        self.assertEqual(view["evidence_families"], [])

    def test_the_legacy_product_name_is_a_schema_alias(self) -> None:
        legacy = {**self.view, "schema": "sentinel-v3-training-view-1"}
        self.assertEqual(canonical_dossier(legacy)["schema"], SCHEMA)

    def test_a_legacy_free_text_statement_is_removed(self) -> None:
        legacy = {**self.view, "clues": [dict(self.view["clues"][0])]}
        legacy["clues"][0]["statement"] = (
            "Client Dupont sur https://secret.example et client@example.org"
        )
        encoded = json.dumps(canonical_dossier(legacy), ensure_ascii=False)
        self.assertNotIn("Client Dupont", encoded)
        self.assertNotIn("secret.example", encoded)
        self.assertNotIn("client@example.org", encoded)

    def test_an_unknown_schema_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            canonical_dossier({"schema": "unrelated-training-view"})

    def test_the_split_group_ignores_clue_order(self) -> None:
        reversed_view = {**self.view, "clues": list(reversed(self.view["clues"]))}
        self.assertEqual(split_group_hash(self.view), split_group_hash(reversed_view))

    def test_la_vue_garde_les_seuils_et_la_piece_jointe(self) -> None:
        # Sans ces champs, la mesure à 60 jours des règles de seuil serait
        # impossible depuis verdict_runs.input_snapshot, comme elle l'était
        # jusqu'ici pour learned_reduction.
        dossier = {
            **DOSSIER,
            "llm_budget": {"truncated_for_llm": True},
            "judgment_rules": {
                **DOSSIER["judgment_rules"],
                "attachment_analysis_complete": False,
                "learned_reduction": 0.08,
                "authenticated_allow_reduction": 0.08,
                "threshold_reduction_applied": 0.0,
                "reduction_suspended_by": ["CORRELATION_FINANCIAL_FRAUD", "X" * 300],
                "allow_identity_authenticated": True,
            },
        }
        view = compact_dossier(dossier)
        rules = view["judgment_rules"]
        self.assertIs(rules["attachment_analysis_complete"], False)
        self.assertEqual(rules["learned_reduction"], 0.08)
        self.assertEqual(rules["authenticated_allow_reduction"], 0.08)
        self.assertEqual(rules["threshold_reduction_applied"], 0.0)
        self.assertEqual(
            rules["reduction_suspended_by"], ["CORRELATION_FINANCIAL_FRAUD", "X" * 100]
        )
        self.assertIs(rules["allow_identity_authenticated"], True)
        self.assertIs(view["llm_truncated"], True)
        self.assertEqual(canonical_dossier(view), view)

        # Une vue conservée avant ce chantier se relit sans lever.
        ancienne = {**self.view, "judgment_rules": {"version": "v3"}}
        ancienne.pop("llm_truncated", None)
        relue = canonical_dossier(ancienne)
        self.assertIsNone(relue["judgment_rules"]["attachment_analysis_complete"])
        self.assertEqual(relue["judgment_rules"]["threshold_reduction_applied"], 0.0)
        self.assertEqual(relue["judgment_rules"]["reduction_suspended_by"], [])
        self.assertIs(relue["llm_truncated"], False)

    def test_la_vue_dit_pourquoi_un_message_douteux_a_ete_livre(self) -> None:
        # 15 octobre 2026 : chez qui ne veut que les vrais doutes, un verdict
        # suspect peut être livré. Sans le choix dans la vue, le corpus
        # apprendrait « suspect, donc livrer » sans sa raison.
        dossier = {
            **DOSSIER,
            "judgment_rules": {
                **DOSSIER["judgment_rules"],
                "ask_only_on_real_doubt": True,
                "real_doubt": False,
            },
        }
        rules = compact_dossier(dossier)["judgment_rules"]
        self.assertIs(rules["ask_only_on_real_doubt"], True)
        self.assertIs(rules["real_doubt"], False)
        relue = canonical_dossier({**self.view, "judgment_rules": {"version": "v3"}})
        self.assertIs(relue["judgment_rules"]["ask_only_on_real_doubt"], False)

    def test_the_teacher_target_keeps_codes_but_not_free_text(self) -> None:
        target = safe_teacher_target(
            {
                "classification": "dangerous",
                "confidence": 0.97,
                "delivery_decision": "junk",
                "verdict_doubt": False,
                "rationale": "Nom Client et compte bancaire FR76",
                "supporting_clue_codes": ["AUTH_DMARC_FAIL"],
                "contradicting_clue_codes": [],
                "attack": {"techniques": ["T1566"], "impersonated_brand": "Banque"},
            }
        )
        encoded = json.dumps(target, ensure_ascii=False)
        self.assertIn("AUTH_DMARC_FAIL", encoded)
        self.assertIn("T1566", encoded)
        self.assertNotIn("Nom Client", encoded)
        self.assertNotIn("Banque", encoded)


if __name__ == "__main__":
    unittest.main()
