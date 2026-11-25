"""Ce qui ouvre la livraison, et ce qui la referme, avant le verdict.

Trois règles du jugement, toutes calculées avant l'appel au modèle :

- une pièce jointe restée sans inspection rend l'analyse incomplète décisive,
  même pour un expéditeur authentifié ou autorisé ;
- une convergence défavorable suspend la confiance accordée à l'expéditeur
  (réduction de seuil et posture d'expéditeur de confiance) ;
- les règles se calculent sur les indices complets, avant l'ajustement du
  dossier à la taille du contexte du modèle.
"""

from __future__ import annotations

import inspect
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from sentimail_v3.judgment import workflow as verdict_engine
from sentimail_v3.judgment.model_routing import initial_route
from sentimail_v3.judgment.verdict_engine import (
    JudgmentContradiction,
    _judgment_rules,
    _material_danger_evidence,
    _parse_verdict,
    _prompt,
    _validate_final_judgment,
)
from sentimail_v3.observation.deep_analysis import analyze_message

SETTINGS = SimpleNamespace(auto_delivery_confidence=0.90)
DMARC = {
    "clue_code": "AUTH_DMARC_PASS",
    "article_code": "AUTH-001",
    "direction": "favorable",
    "strength": 60,
}


def _regles(
    clues: list[dict[str, object]], deep: dict[str, object]
) -> dict[str, object]:
    dossier: dict[str, object] = {
        "message": {"investigation_status": "complete", "adverse_points": 0},
        "code_articles": [],
        "clues": clues,
    }
    dossier["judgment_rules"] = _judgment_rules(dossier, deep, SETTINGS)  # type: ignore[arg-type]
    return dossier


def _verdict(
    classification: str = "legitimate",
    decision: str = "deliver",
    confidence: float = 1.0,
) -> dict[str, object]:
    return {
        "classification": classification,
        "confidence": confidence,
        "delivery_decision": decision,
        "verdict_doubt": classification != "legitimate",
    }


def _autorise(**history: object) -> dict[str, object]:
    return {"ground_truth_labels": {}, "persistent_allow": True, **history}


class PieceJointeNonInspecteeTests(unittest.TestCase):
    def test_piece_jointe_non_inspectee_decisive_meme_authentifiee(self) -> None:
        dossier = _regles(
            [DMARC],
            {"complete": False, "attachments_complete": False, "urls_complete": True},
        )
        rules = dossier["judgment_rules"]
        self.assertFalse(rules["attachment_analysis_complete"])  # type: ignore[index]
        self.assertTrue(rules["incomplete_analysis_is_decisive"])  # type: ignore[index]
        with self.assertRaises(JudgmentContradiction) as leve:
            _validate_final_judgment(_verdict(), dossier)
        self.assertIn("deep_execution_incomplete", leve.exception.contradictions)
        self.assertTrue(leve.exception.structural)

    def test_l_expediteur_autorise_ne_contourne_pas_la_piece_jointe(self) -> None:
        dossier = _regles(
            [DMARC],
            {
                "complete": False,
                "attachments_complete": False,
                "urls_complete": True,
                "history": _autorise(),
            },
        )
        self.assertTrue(dossier["judgment_rules"]["trusted_sender"])  # type: ignore[index]
        with self.assertRaises(JudgmentContradiction) as leve:
            _validate_final_judgment(_verdict(), dossier)
        self.assertIn("deep_execution_incomplete", leve.exception.contradictions)
        self.assertTrue(leve.exception.structural)

    def test_l_indice_att019_suffit_sans_drapeau(self) -> None:
        # Le drapeau dit « complet », l'indice dit le contraire : l'indice
        # gagne, puisqu'il constate une inspection qui n'a pas abouti.
        dossier = _regles(
            [
                DMARC,
                {
                    "clue_code": "ATTACHMENT_ANALYSIS_BLOCKED",
                    "article_code": "ATT-019",
                    "direction": "neutral",
                    "strength": 0,
                },
            ],
            {"complete": True},
        )
        rules = dossier["judgment_rules"]
        self.assertFalse(rules["attachment_analysis_complete"])  # type: ignore[index]
        self.assertFalse(rules["deep_execution_complete"])  # type: ignore[index]
        self.assertTrue(rules["incomplete_analysis_is_decisive"])  # type: ignore[index]

    def test_repli_sur_les_analyses_de_pieces_jointes(self) -> None:
        # Un dossier d'avant ce chantier n'a pas le drapeau : on relit les
        # analyses de pièces jointes elles-mêmes.
        dossier = _regles(
            [DMARC],
            {"complete": False, "attachment_analyses": [{"analysis_incomplete": True}]},
        )
        self.assertFalse(
            dossier["judgment_rules"]["attachment_analysis_complete"]  # type: ignore[index]
        )

    def test_sans_piece_jointe_un_lien_inacheve_ne_derange_toujours_pas(self) -> None:
        dossier = _regles(
            [DMARC],
            {"complete": False, "attachments_complete": True, "urls_complete": False},
        )
        rules = dossier["judgment_rules"]
        self.assertTrue(rules["attachment_analysis_complete"])  # type: ignore[index]
        self.assertFalse(rules["incomplete_analysis_is_decisive"])  # type: ignore[index]
        _validate_final_judgment(_verdict(), dossier)

    def test_classer_un_indesirable_reste_permis_piece_jointe_non_inspectee(
        self,
    ) -> None:
        dossier = _regles(
            [DMARC],
            {"complete": False, "attachments_complete": False, "urls_complete": True},
        )
        _validate_final_judgment(_verdict("spam", "junk", 0.95), dossier)
        with self.assertRaises(JudgmentContradiction) as leve:
            _validate_final_judgment(_verdict("dangerous", "junk", 0.95), dossier)
        self.assertIn("deep_execution_incomplete", leve.exception.contradictions)

    def test_classer_un_danger_permis_si_seul_un_lien_est_inacheve(self) -> None:
        dossier = _regles(
            [DMARC],
            {"complete": False, "attachments_complete": True, "urls_complete": False},
        )
        rules = dossier["judgment_rules"]
        self.assertTrue(rules["attachment_analysis_complete"])  # type: ignore[index]
        self.assertFalse(rules["deep_execution_complete"])  # type: ignore[index]
        _validate_final_judgment(_verdict("dangerous", "junk", 0.90), dossier)

    def test_conflit_destination_bloque_deliver_mais_autorise_junk_sans_preuve_materielle(
        self,
    ) -> None:
        dossier = _regles(
            [
                DMARC,
                {
                    "clue_code": "CORRELATION_UNVERIFIED_IDENTITY_DESTINATION",
                    "article_code": "CORR-019",
                    "direction": "adverse",
                    "strength": 90,
                },
            ],
            {"complete": True, "attachments_complete": True, "urls_complete": True},
        )
        rules = dossier["judgment_rules"]
        self.assertTrue(rules["identity_destination_conflict"])  # type: ignore[index]
        self.assertEqual(rules["material_danger_evidence"], [])  # type: ignore[index]
        with self.assertRaises(JudgmentContradiction) as leve:
            _validate_final_judgment(_verdict("legitimate", "deliver", 0.99), dossier)
        self.assertIn(
            "identity_destination_conflict_unresolved", leve.exception.contradictions
        )
        for classification in ("spam", "dangerous"):
            _validate_final_judgment(_verdict(classification, "junk", 0.90), dossier)

    def test_le_routage_envoie_le_dossier_au_juge_premium(self) -> None:
        dossier = _regles(
            [DMARC],
            {"complete": False, "attachments_complete": False, "urls_complete": True},
        )
        self.assertEqual(initial_route(dossier), ("premium", "deep_analysis_incomplete"))

    def test_analyze_message_expose_la_completude_par_famille(self) -> None:
        source = inspect.getsource(analyze_message)
        self.assertIn('"attachments_complete": attachments_complete', source)
        self.assertIn('"urls_complete": urls_complete', source)

    def test_le_prompt_dit_qu_un_fichier_non_inspecte_n_est_jamais_livre(self) -> None:
        self.assertIn(
            "judgment_rules.attachment_analysis_complete=false",
            _prompt({})[0]["content"],
        )


class ConvergenceDefavorableTests(unittest.TestCase):
    def test_une_convergence_defavorable_suspend_la_reduction_de_l_autorisation(
        self,
    ) -> None:
        dossier = _regles(
            [
                DMARC,
                {
                    "clue_code": "CORRELATION_FINANCIAL_FRAUD",
                    "article_code": "CORR-008",
                    "direction": "adverse",
                    "strength": 85,
                },
            ],
            {"complete": True, "attachments_complete": True, "history": _autorise()},
        )
        rules = dossier["judgment_rules"]
        self.assertEqual(rules["confidence_required"], 0.9)  # type: ignore[index]
        self.assertEqual(rules["authenticated_allow_reduction"], 0.08)  # type: ignore[index]
        self.assertEqual(rules["threshold_reduction_applied"], 0.0)  # type: ignore[index]
        self.assertEqual(
            rules["reduction_suspended_by"], ["CORRELATION_FINANCIAL_FRAUD"]  # type: ignore[index]
        )
        self.assertFalse(rules["trusted_sender"])  # type: ignore[index]
        self.assertFalse(rules["trusted_sender_noise_is_not_a_reason_to_ask"])  # type: ignore[index]
        self.assertEqual(rules["authenticated_sender_policy"], "allow")  # type: ignore[index]
        with self.assertRaises(JudgmentContradiction) as leve:
            _validate_final_judgment(_verdict(confidence=0.85), dossier)
        self.assertEqual(
            leve.exception.contradictions, ["confidence_below_judicial_threshold"]
        )
        self.assertFalse(leve.exception.structural)

    def test_une_convergence_defavorable_suspend_la_reduction_apprise(self) -> None:
        dossier = _regles(
            [
                DMARC,
                {
                    "clue_code": "CORRELATION_COMPROMISED_SENDER",
                    "article_code": "CORR-009",
                    "direction": "adverse",
                    "strength": 75,
                },
            ],
            {
                "complete": True,
                "history": {"ground_truth_labels": {"legitimate": 20}},
            },
        )
        rules = dossier["judgment_rules"]
        self.assertEqual(rules["learned_reduction"], 0.08)  # type: ignore[index]
        self.assertEqual(rules["confidence_required"], 0.9)  # type: ignore[index]
        self.assertEqual(
            rules["reduction_suspended_by"], ["CORRELATION_COMPROMISED_SENDER"]  # type: ignore[index]
        )

    def test_une_correlation_favorable_ne_suspend_rien(self) -> None:
        dossier = _regles(
            [
                DMARC,
                {
                    "clue_code": "CORRELATION_TRANSACTIONAL_COHERENCE",
                    "article_code": "CORR-012",
                    "direction": "favorable",
                    "strength": 40,
                },
            ],
            {"complete": True, "history": _autorise()},
        )
        rules = dossier["judgment_rules"]
        self.assertEqual(rules["confidence_required"], 0.82)  # type: ignore[index]
        self.assertEqual(rules["threshold_reduction_applied"], 0.08)  # type: ignore[index]
        self.assertEqual(rules["reduction_suspended_by"], [])  # type: ignore[index]
        self.assertTrue(rules["trusted_sender"])  # type: ignore[index]

    def test_le_gabarit_de_campagne_connu_ne_suspend_pas(self) -> None:
        # CORR-011 est une mémoire de ressemblance, pas une convergence de
        # faits observés sur ce message : son préfixe TPLT_ ne suspend rien.
        dossier = _regles(
            [
                DMARC,
                {
                    "clue_code": "TPLT_KNOWN_CAMPAIGN",
                    "article_code": "CORR-011",
                    "direction": "adverse",
                    "strength": 60,
                },
            ],
            {"complete": True, "history": _autorise()},
        )
        rules = dossier["judgment_rules"]
        self.assertEqual(rules["confidence_required"], 0.82)  # type: ignore[index]
        self.assertTrue(rules["trusted_sender"])  # type: ignore[index]

    def test_la_reduction_apprise_exige_une_identite_authentifiee(self) -> None:
        deep = {"complete": True, "history": {"ground_truth_labels": {"legitimate": 20}}}
        usurpable = _regles([], deep)["judgment_rules"]
        self.assertEqual(usurpable["learned_reduction"], 0.08)  # type: ignore[index]
        self.assertEqual(usurpable["threshold_reduction_applied"], 0.0)  # type: ignore[index]
        self.assertEqual(usurpable["confidence_required"], 0.9)  # type: ignore[index]
        authentifiee = _regles([DMARC], deep)["judgment_rules"]
        self.assertEqual(authentifiee["confidence_required"], 0.82)  # type: ignore[index]

    def test_le_prompt_dit_que_la_confiance_ne_survit_pas_a_une_convergence(
        self,
    ) -> None:
        self.assertIn(
            "judgment_rules.reduction_suspended_by", _prompt({})[0]["content"]
        )


def _indice(code: str, article: str, strength: int) -> dict[str, object]:
    return {
        "clue_code": code,
        "article_code": article,
        "direction": "adverse",
        "strength": strength,
        "confidence": 0.9,
        "statement": "Constat de test suffisamment long pour peser dans le dossier.",
    }


def _gros_dossier(
    clues: list[dict[str, object]], articles: list[dict[str, object]] | None = None
) -> dict[str, object]:
    return {
        "message": {"investigation_status": "complete", "adverse_points": 0},
        "code_articles": articles or [],
        "clues": clues,
    }


class ReglesSurIndicesCompletsTests(unittest.TestCase):
    def test_la_barriere_materielle_survit_a_la_troncature(self) -> None:
        clues = [_indice(f"URL_BRUIT_{index}", "URL-001", 50) for index in range(70)]
        clues.append(_indice("ATTACHMENT_ACTIVE_CODE", "ATT-010", 5))
        # asyncpg rend la colonne jsonb en texte : la barrière doit la relire.
        articles = [
            {
                "article_code": "ATT-010",
                "parameters": json.dumps(
                    {
                        "delivery_barrier": "material_danger",
                        "material_kind": "active_code_execution",
                    }
                ),
            }
        ]
        with patch("sentimail_v3.judgment.dossier_view.MAX_LLM_DOSSIER_CHARS", 500):
            dossier = verdict_engine._prepare_for_judgment(
                _gros_dossier(clues, articles), {"complete": True}, SETTINGS  # type: ignore[arg-type]
            )
        self.assertTrue(dossier["llm_budget"]["truncated_for_llm"])  # type: ignore[index]
        vue = dossier["clues"]
        self.assertLessEqual(len(vue), 40)  # type: ignore[arg-type]
        self.assertNotIn(
            "ATTACHMENT_ACTIVE_CODE", {clue["clue_code"] for clue in vue}  # type: ignore[union-attr, index]
        )
        rules = dossier["judgment_rules"]
        self.assertTrue(rules["material_danger_evidence"])  # type: ignore[index]
        with self.assertRaises(JudgmentContradiction) as leve:
            _validate_final_judgment(_verdict(), dossier)
        self.assertIn("material_danger_unresolved", leve.exception.contradictions)

    def test_la_convergence_voit_les_familles_coupees(self) -> None:
        clues = [_indice(f"HEADER_BRUIT_{index}", "HEADER-001", 95) for index in range(70)]
        clues.append(_indice("ATTACHMENT_MACRO", "ATT-012", 90))
        with patch("sentimail_v3.judgment.dossier_view.MAX_LLM_DOSSIER_CHARS", 500):
            dossier = verdict_engine._prepare_for_judgment(
                _gros_dossier(clues), {"complete": True}, SETTINGS  # type: ignore[arg-type]
            )
        self.assertNotIn(
            "ATTACHMENT_MACRO", {c["clue_code"] for c in dossier["clues"]}  # type: ignore[union-attr, index]
        )
        self.assertIn(
            "pieces_jointes", dossier["judgment_rules"]["converging_families"]  # type: ignore[index]
        )

    def test_un_code_de_la_couverture_n_est_pas_une_preuve_inventee(self) -> None:
        clues = [_indice("URL_GARDE", "URL-001", 95)]
        clues += [_indice(f"HEADER_BRUIT_{index}", "HEADER-001", 90) for index in range(70)]
        clues.append(_indice("URL_COUPE", "URL-002", 30))
        with patch("sentimail_v3.judgment.dossier_view.MAX_LLM_DOSSIER_CHARS", 500):
            dossier = verdict_engine._prepare_for_judgment(
                _gros_dossier(clues), {"complete": True}, SETTINGS  # type: ignore[arg-type]
            )
        vue = {c["clue_code"] for c in dossier["clues"]}  # type: ignore[union-attr, index]
        self.assertIn("URL_GARDE", vue)
        self.assertNotIn("URL_COUPE", vue)

        def reponse(motif: str) -> str:
            return json.dumps(
                {
                    "unfavorable": {"clue_codes": ["URL_GARDE"], "arguments": []},
                    "favorable": {"clue_codes": [], "arguments": []},
                    "final_verdict": {
                        "classification": "suspect",
                        "confidence": 0.6,
                        "delivery_decision": "ask_user",
                        "rationale": motif,
                        "doubt": True,
                        "doubt_reasons": [],
                    },
                }
            )

        resultat = _parse_verdict(
            reponse("URL_GARDE et URL_COUPE décrivent le même lien."), dossier
        )
        self.assertEqual(resultat["delivery_decision"], "ask_user")
        with self.assertRaises(ValueError) as leve:
            _parse_verdict(reponse("URL_INVENTE_999 le prouve."), dossier)
        self.assertIn("URL_INVENTE_999", str(leve.exception))

    def test_des_parametres_illisibles_sont_journalises(self) -> None:
        dossier = _gros_dossier(
            [_indice("ATTACHMENT_ACTIVE_CODE", "ATT-010", 90)],
            [{"article_code": "ATT-010", "parameters": "{"}],
        )
        with self.assertLogs("sentimail-v3-verdict", level="INFO") as journal:
            self.assertEqual(_material_danger_evidence(dossier), [])
        self.assertTrue(
            any("verdict.material_parameters_unreadable" in ligne for ligne in journal.output)
        )
        self.assertTrue(any("ATT-010" in ligne for ligne in journal.output))


class DossierCompletTests(unittest.IsolatedAsyncioTestCase):
    async def test_build_dossier_ne_tronque_plus(self) -> None:
        from tests.test_dossier_texte_visible import HTML, _Pool

        dossier = await verdict_engine._build_dossier(
            _Pool(None, HTML), "inv", {"complete": True}  # type: ignore[arg-type]
        )
        self.assertNotIn("llm_budget", dossier)


if __name__ == "__main__":
    unittest.main()
