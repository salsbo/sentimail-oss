from __future__ import annotations

import asyncio
import hashlib
import json
import unittest
from email import policy
from email.message import EmailMessage
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
from sentimail_v3.judgment.verdict_engine import (
    JudgmentContradiction,
    _judgment_execution,
    _judgment_rules,
    _parse_final_response,
    _parse_verdict,
    _prompt,
    _validate_final_judgment,
)
from sentimail_v3.observation.deep_analysis import (
    _SIGNAL_RULES,
    BASE_URLS,
    MAX_URLS,
    _analyze_attachments,
    _analyze_urls,
    _contextualize_equivalent_url_limits,
    _explained_authenticated_redirect_limit,
    _explained_authenticated_same_apex_fetch_error,
    _is_definitive_target_failure,
    _json,
    _json_object,
    _message_url_candidates,
    _select_url_candidates,
    _signals,
    fetch_url_analysis_with_retry,
)
from sentimail_v3.observation.preview import render_source


class DecisionPolicyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.settings = SimpleNamespace(
            auto_delivery_confidence=0.90,
        )

    def _rules(
        self, dossier: dict[str, object], deep: dict[str, object]
    ) -> dict[str, object]:
        rules = _judgment_rules(dossier, deep, self.settings)  # type: ignore[arg-type]
        dossier["judgment_rules"] = rules
        return rules

    @staticmethod
    def _judgment(
        classification: str = "legitimate",
        confidence: float = 0.92,
        decision: str = "deliver",
        doubt: bool = False,
    ) -> dict[str, object]:
        return {
            "classification": classification,
            "confidence": confidence,
            "delivery_decision": decision,
            "verdict_doubt": doubt or classification != "legitimate",
        }

    # 15 octobre 2026 : une destinataire recevait seize avis par mois, dont
    # neuf sans danger ni faisceau (analyses inabouties, promotions, activité
    # mal lue). Elle a choisi de n'être interrogée que sur un vrai doute ; un
    # message laissé passer « n'est pas grave » (décision du mainteneur).
    def _vrai_doute_seulement(self, clues: list[dict[str, object]] | None = None,
                              deep_complete: bool = False,
                              articles: list[dict[str, object]] | None = None) -> dict[str, object]:
        dossier: dict[str, object] = {
            "message": {"investigation_status": "complete", "adverse_points": 0},
            "clues": clues or [],
            "code_articles": articles or [],
        }
        deep = {
            "complete": deep_complete,
            "history": {"ground_truth_labels": {}, "ask_only_on_real_doubt": True},
        }
        self._rules(dossier, deep)
        return dossier

    def test_sans_vrai_doute_le_message_est_livre_meme_analyse_inaboutie(self) -> None:
        dossier = self._vrai_doute_seulement()
        rules = dossier["judgment_rules"]
        self.assertTrue(rules["ask_only_on_real_doubt"])
        self.assertFalse(rules["real_doubt"])
        _validate_final_judgment(self._judgment("undetermined", 0.6, "deliver"), dossier)
        _validate_final_judgment(self._judgment("suspect", 0.55, "deliver"), dossier)

    def test_sans_vrai_doute_demander_est_refuse(self) -> None:
        dossier = self._vrai_doute_seulement()
        with self.assertRaises(JudgmentContradiction) as raised:
            _validate_final_judgment(self._judgment("suspect", 0.55, "ask_user"), dossier)
        self.assertEqual(raised.exception.contradictions, ["ask_without_real_doubt"])
        self.assertTrue(raised.exception.structural)

    def test_la_demande_refusee_devient_une_livraison(self) -> None:
        dossier = self._vrai_doute_seulement()
        for decision, classification, confidence in (
            ("ask_user", "suspect", 0.55),
            ("junk", "spam", 0.5),
        ):
            with self.subTest(decision=decision):
                content = json.dumps({"final_verdict": {
                    "classification": classification, "confidence": confidence,
                    "delivery_decision": decision, "rationale": "Promotion.",
                    "doubt": True, "doubt_reasons": [],
                }})
                result, contradictions = _parse_final_response(content, dossier)
                self.assertEqual(result["delivery_decision"], "deliver")
                self.assertEqual(result["classification"], classification)
                self.assertTrue(contradictions)
                _validate_final_judgment(result, dossier)
                self.assertTrue(_judgment_execution(result)["original_delivery_allowed"])

    def test_un_faisceau_defavorable_reste_un_vrai_doute(self) -> None:
        dossier = self._vrai_doute_seulement([{
            "clue_code": "CORRELATION_COMPROMISED_SENDER", "direction": "adverse", "strength": 70,
        }], deep_complete=True)
        self.assertTrue(dossier["judgment_rules"]["real_doubt"])
        _validate_final_judgment(self._judgment("suspect", 0.6, "ask_user"), dossier)
        with self.assertRaises(JudgmentContradiction):
            _validate_final_judgment(self._judgment("suspect", 0.6, "deliver"), dossier)

    def test_une_preuve_materielle_reste_un_vrai_doute(self) -> None:
        dossier = self._vrai_doute_seulement([{
            "clue_code": "CONTENT_EXTORTION", "direction": "adverse", "strength": 80,
            "article_code": "CONTENT-099",
        }], deep_complete=True, articles=[{
            "article_code": "CONTENT-099",
            "parameters": {"delivery_barrier": "material_danger", "material_kind": "extortion"},
        }])
        self.assertTrue(dossier["judgment_rules"]["material_danger_evidence"])
        self.assertTrue(dossier["judgment_rules"]["real_doubt"])
        _validate_final_judgment(self._judgment("suspect", 0.6, "ask_user"), dossier)

    def test_un_verdict_dangereux_garde_sa_question(self) -> None:
        dossier = self._vrai_doute_seulement()
        _validate_final_judgment(self._judgment("dangerous", 0.7, "ask_user"), dossier)

    def test_sans_ce_choix_rien_ne_change(self) -> None:
        dossier = {"message": {"investigation_status": "complete", "adverse_points": 0}}
        rules = self._rules(dossier, {"complete": False, "history": {"ground_truth_labels": {}}})
        self.assertFalse(rules["ask_only_on_real_doubt"])
        _validate_final_judgment(self._judgment("suspect", 0.55, "ask_user"), dossier)
        with self.assertRaises(JudgmentContradiction):
            _validate_final_judgment(self._judgment("undetermined", 0.6, "deliver"), dossier)

    def test_legitimate_new_sender_at_ninety_two_percent_is_delivered(self) -> None:
        dossier = {
            "message": {"investigation_status": "complete", "adverse_points": 0}
        }
        deep = {"complete": True, "history": {"ground_truth_labels": {}}}
        self._rules(dossier, deep)
        result = self._judgment()
        _validate_final_judgment(result, dossier)
        self.assertTrue(_judgment_execution(result)["original_delivery_allowed"])

    def test_prompt_and_parser_make_the_final_delivery_decision_binding(self) -> None:
        dossier: dict[str, object] = {
            "message": {"investigation_status": "complete", "adverse_points": 0},
            "clues": [],
        }
        deep = {
            "complete": True,
            "history": {"ground_truth_labels": {}},
            "url_coverage": {
                "coverage_limited": True,
                "actionable_apexes_total": 9,
                "actionable_apexes_analyzed": 9,
            },
        }
        self._rules(dossier, deep)
        self.assertIn("3. VERDICT FINAL", _prompt(dossier)[0]["content"])
        result = _parse_verdict(
            json.dumps(
                {
                    "unfavorable": {"clue_codes": [], "arguments": []},
                    "favorable": {"clue_codes": [], "arguments": []},
                    "final_verdict": {
                        "classification": "legitimate",
                        "confidence": 0.92,
                        "delivery_decision": "deliver",
                        "rationale": "Le faisceau à décharge l'emporte.",
                        "doubt": False,
                        "doubt_reasons": [],
                    },
                }
            ),
            dossier,
        )
        self.assertEqual(result["delivery_decision"], "deliver")

    def test_consistent_feedback_reduces_doubt_but_not_below_floor(self) -> None:
        # Les confirmations portent sur l'adresse exacte : sans DMARC sur ce
        # message, l'adresse peut être usurpée et la réduction ne s'applique
        # pas (voir test_seuils_du_juge). Ne pas retirer cet indice pour
        # « réparer » le test : ce serait rouvrir le trou.
        dossier = {
            "message": {"investigation_status": "complete", "adverse_points": 10},
            "clues": [{"clue_code": "AUTH_DMARC_PASS"}],
        }
        deep = {
            "complete": True,
            "history": {"ground_truth_labels": {"legitimate": 20}},
        }
        rules = self._rules(dossier, deep)
        result = self._judgment(confidence=0.91)
        _validate_final_judgment(result, dossier)
        self.assertEqual(rules["confidence_required"], 0.82)

    def test_authenticated_allow_list_lowers_doubt_without_bypassing_safety(self) -> None:
        dossier = {
            "message": {"investigation_status": "complete", "adverse_points": 10},
            "clues": [{"clue_code": "AUTH_DMARC_PASS"}],
        }
        deep = {
            "complete": True,
            "history": {
                "ground_truth_labels": {},
                "persistent_allow": True,
            },
        }
        allowed = self._rules(dossier, deep)
        result = self._judgment(confidence=0.84)
        _validate_final_judgment(result, dossier)
        self.assertEqual(allowed["confidence_required"], 0.82)

        # Une vérification inachevée ne dérange plus quand rien ne motive la
        # méfiance : identité authentifiée, aucun indice défavorable.
        incomplete_dossier = dict(dossier)
        incomplete = self._rules(incomplete_dossier, {**deep, "complete": False})
        _validate_final_judgment(self._judgment(confidence=1.0), incomplete_dossier)
        self.assertFalse(incomplete["deep_execution_complete"])
        self.assertFalse(incomplete["incomplete_analysis_is_decisive"])

        # Elle redevient bloquante dès qu'un indice défavorable réel existe :
        # on ne livre pas ce qu'on n'a pas pu vérifier quand il y a un doute.
        doubtful_dossier = {
            "message": {"investigation_status": "complete", "adverse_points": 30},
            "clues": [
                {"clue_code": "AUTH_DMARC_PASS"},
                {"clue_code": "URL_CLOAKING", "direction": "adverse", "strength": 40},
            ],
        }
        doubtful = self._rules(doubtful_dossier, {**deep, "complete": False})
        self.assertTrue(doubtful["incomplete_analysis_is_decisive"])
        with self.assertRaisesRegex(ValueError, "deep_execution_incomplete"):
            _validate_final_judgment(
                self._judgment(confidence=1.0), doubtful_dossier
            )

        spoofed_dossier = {
            "message": {
                "investigation_status": "complete",
                "adverse_points": 70,
            },
            "clues": [{"clue_code": "AUTH_DMARC_FAIL"}],
        }
        spoofed = self._rules(spoofed_dossier, deep)
        with self.assertRaisesRegex(ValueError, "confidence_below_judicial_threshold"):
            _validate_final_judgment(
                self._judgment(confidence=0.84), spoofed_dossier
            )
        self.assertEqual(spoofed["authenticated_allow_reduction"], 0.0)
        signals = _signals(
            [],
            [],
            {
                "ground_truth_labels": {},
                "previous_message_count": 1,
                "persistent_allow": True,
                "sender_domain_enriched": True,
            },
            True,
        )
        self.assertIn("POLICY-002", {item["article_code"] for item in signals})
        self.assertEqual(_SIGNAL_RULES["POLICY-002"][1:3], ("favorable", 25))

    def test_incomplete_analysis_must_be_decided_as_undetermined(self) -> None:
        dossier = {
            "message": {"investigation_status": "complete", "adverse_points": 0}
        }
        deep = {"complete": False, "history": {"ground_truth_labels": {}}}
        self._rules(dossier, deep)
        with self.assertRaisesRegex(ValueError, "deep_execution_incomplete"):
            _validate_final_judgment(self._judgment(confidence=1.0), dossier)
        result = self._judgment(
            classification="undetermined",
            confidence=0.95,
            decision="ask_user",
            doubt=True,
        )
        _validate_final_judgment(result, dossier)
        self.assertFalse(_judgment_execution(result)["original_delivery_allowed"])

    def test_authenticated_hold_is_law_presented_before_judgment(self) -> None:
        dossier = {
            "message": {"investigation_status": "complete", "adverse_points": 0}
        }
        deep = {
            "complete": True,
            "history": {
                "ground_truth_labels": {},
                "persistent_hold": True,
            },
        }
        rules = self._rules(dossier, deep)
        self.assertEqual(rules["authenticated_sender_policy"], "hold")
        with self.assertRaisesRegex(ValueError, "authenticated_hold_ignored"):
            _validate_final_judgment(self._judgment(confidence=0.99), dossier)
        _validate_final_judgment(
            self._judgment(
                classification="suspect",
                confidence=0.99,
                decision="ask_user",
                doubt=True,
            ),
            dossier,
        )

    def test_anthropic_pattern_is_delivered_despite_heuristic_score(self) -> None:
        dossier = {
            "message": {
                "investigation_status": "complete",
                "adverse_points": 164,
            },
            "code_articles": [
                {
                    "article_code": "CONTENT-003",
                    "parameters": {},
                },
                {
                    "article_code": "DEEP-002",
                    "parameters": {},
                },
            ],
            "clues": [
                {
                    "article_code": "CONTENT-003",
                    "clue_code": "CONTENT_SOCIAL_ENGINEERING_COMBINATION",
                    "direction": "adverse",
                    "strength": 70,
                },
                {
                    "article_code": "DEEP-002",
                    "clue_code": "URL_SANDBOX_FORM",
                    "direction": "adverse",
                    "strength": 65,
                },
            ],
        }
        deep = {"complete": True, "history": {"ground_truth_labels": {}}}
        rules = self._rules(dossier, deep)
        result = self._judgment()
        _validate_final_judgment(result, dossier)
        self.assertEqual(rules["adverse_points_observed"], 164)
        self.assertEqual(rules["material_danger_evidence"], [])

    def test_material_danger_must_be_resolved_inside_the_final_judgment(self) -> None:
        dossier = {
            "message": {
                "investigation_status": "complete",
                "adverse_points": 100,
            },
            "code_articles": [
                {
                    "article_code": "RSPAMD-002",
                    "parameters": {
                        "delivery_barrier": "material_danger",
                        "material_kind": "malware_or_virus",
                    },
                }
            ],
            "clues": [
                {
                    "article_code": "RSPAMD-002",
                    "clue_code": "RSPAMD_MATERIAL_SYMBOL",
                    "direction": "adverse",
                    "strength": 100,
                }
            ],
        }
        deep = {"complete": True, "history": {"ground_truth_labels": {}}}
        rules = self._rules(dossier, deep)
        with self.assertRaisesRegex(ValueError, "material_danger_unresolved"):
            _validate_final_judgment(self._judgment(confidence=0.99), dossier)
        self.assertEqual(
            rules["material_danger_evidence"][0]["clue_code"],
            "RSPAMD_MATERIAL_SYMBOL",
        )
        _validate_final_judgment(
            self._judgment(
                classification="dangerous",
                confidence=0.99,
                decision="ask_user",
                doubt=True,
            ),
            dossier,
        )

    def test_critical_severity_alone_is_not_an_implicit_delivery_barrier(self) -> None:
        dossier = {
            "message": {
                "investigation_status": "complete",
                "adverse_points": 100,
            },
            "code_articles": [
                {
                    "article_code": "FUTURE-001",
                    "severity": "critical",
                    "parameters": {},
                }
            ],
            "clues": [
                {
                    "article_code": "FUTURE-001",
                    "clue_code": "FUTURE_HEURISTIC",
                    "direction": "adverse",
                    "strength": 100,
                }
            ],
        }
        deep = {"complete": True, "history": {"ground_truth_labels": {}}}
        self._rules(dossier, deep)
        _validate_final_judgment(self._judgment(confidence=0.99), dossier)

    def test_history_signals_country_size_and_recent_domain(self) -> None:
        history = {
            "ground_truth_labels": {},
            "previous_message_count": 20,
            "previous_active_days": 20,
            "size_zscore": 3.5,
            "hour_previously_seen": True,
            "unfamiliar_transport_countries": ["RU"],
            "sender_domain_age_days": 12,
        }
        codes = {
            value["article_code"] for value in _signals([], [], history, True)
        }
        self.assertIn("HIST-003", codes)
        self.assertIn("DOMAIN-001", codes)

    def test_unseen_hour_is_mute_for_a_sender_with_spread_hours(self) -> None:
        # Un expéditeur déclenché par l'utilisateur (confirmation de commande)
        # écrit à toute heure : une heure jamais vue ne dit rien de lui.
        history = {
            "ground_truth_labels": {},
            "previous_message_count": 20,
            "previous_active_days": 20,
            "hour_previously_seen": False,
            "usual_hours_utc": [0, 2, 4, 6, 8, 10, 12, 13, 14, 16, 18, 19, 21, 23],
            "unfamiliar_transport_countries": [],
        }
        codes = {value["article_code"] for value in _signals([], [], history, True)}
        self.assertNotIn("HIST-003", codes)

    def test_unseen_hour_still_fires_for_a_sender_with_a_regular_schedule(self) -> None:
        # Un expéditeur aux horaires réguliers (peu d'heures distinctes vues)
        # sortir de son créneau habituel reste un écart de comportement.
        history = {
            "ground_truth_labels": {},
            "previous_message_count": 20,
            "previous_active_days": 20,
            "hour_previously_seen": False,
            "usual_hours_utc": [8, 9, 10],
            "unfamiliar_transport_countries": [],
        }
        codes = {value["article_code"] for value in _signals([], [], history, True)}
        self.assertIn("HIST-003", codes)

    def test_heure_jamais_vue_sur_quelques_jours_seulement_reste_muette(self) -> None:
        # M-e36c20, 15 octobre 2026 : douze messages en quatre jours, dont
        # cinq notifications envoyées dans la même minute. Quatre heures vues,
        # et 11 h 33 (Paris) passait pour un écart. Ce n'est pas une habitude.
        history = {
            "ground_truth_labels": {},
            "previous_message_count": 12,
            "previous_active_days": 4,
            "hour_previously_seen": False,
            "usual_hours_utc": [8, 12, 13, 14],
            "unfamiliar_transport_countries": [],
        }
        codes = {value["article_code"] for value in _signals([], [], history, True)}
        self.assertNotIn("HIST-003", codes)

    def test_heure_jamais_vue_sur_douze_jours_tire(self) -> None:
        history = {
            "ground_truth_labels": {},
            "previous_message_count": 12,
            "previous_active_days": 12,
            "hour_previously_seen": False,
            "usual_hours_utc": [8, 12, 13, 14],
            "unfamiliar_transport_countries": [],
        }
        codes = {value["article_code"] for value in _signals([], [], history, True)}
        self.assertIn("HIST-003", codes)

    def test_taille_hors_fourchette_sur_historique_fourni_tire(self) -> None:
        # z-score élevé ET taille hors de la fourchette moitié/double : anomalie.
        history = {
            "ground_truth_labels": {},
            "previous_message_count": 20,
            "previous_active_days": 20,
            "size_zscore": 4.0,
            "mean_size_bytes": 100000,
            "current_size_bytes": 350000,
            "hour_previously_seen": True,
            "usual_hours_utc": list(range(14)),
            "unfamiliar_transport_countries": [],
        }
        codes = {value["article_code"] for value in _signals([], [], history, True)}
        self.assertIn("HIST-003", codes)

    def test_newsletter_a_peine_plus_lourde_reste_muette(self) -> None:
        # Cas M-a5b072 (FlightAware) : z-score 8,8 mais 1,26x la moyenne, dans
        # la fourchette. Le z-score s'emballe sur des tailles régulières ; sans
        # écart franc en valeur, ce n'est pas une anomalie.
        history = {
            "ground_truth_labels": {},
            "previous_message_count": 6,
            "size_zscore": 8.8,
            "mean_size_bytes": 677206,
            "current_size_bytes": 854440,
            "hour_previously_seen": True,
            "usual_hours_utc": [12, 13],
            "unfamiliar_transport_countries": [],
        }
        codes = {value["article_code"] for value in _signals([], [], history, True)}
        self.assertNotIn("HIST-003", codes)

    def test_taille_hors_fourchette_mais_historique_maigre_reste_muette(self) -> None:
        # Écart franc mais moins de 10 messages : trop peu pour parler d'habitude.
        history = {
            "ground_truth_labels": {},
            "previous_message_count": 5,
            "size_zscore": 6.0,
            "mean_size_bytes": 100000,
            "current_size_bytes": 900000,
            "hour_previously_seen": True,
            "usual_hours_utc": [12, 13],
            "unfamiliar_transport_countries": [],
        }
        codes = {value["article_code"] for value in _signals([], [], history, True)}
        self.assertNotIn("HIST-003", codes)

    def test_established_domain_is_explicit_weak_defence(self) -> None:
        signals = _signals(
            [],
            [],
            {
                "ground_truth_labels": {},
                "previous_message_count": 0,
                "sender_domain_enriched": True,
                "sender_domain_age_days": 10709,
                "sender_domain_creation_date": "1997-04-17T04:00:00Z",
            },
            True,
        )
        established = next(
            value for value in signals if value["article_code"] == "DOMAIN-002"
        )
        self.assertEqual(established["age_days"], 10709)
        self.assertEqual(_SIGNAL_RULES["DOMAIN-002"][1:3], ("favorable", 15))

    def test_missing_domain_age_is_neutral_and_supervisable(self) -> None:
        signals = _signals(
            [],
            [],
            {
                "ground_truth_labels": {},
                "previous_message_count": 1,
                "sender_domain": "example.org",
                "sender_domain_enriched": False,
            },
            True,
        )
        self.assertIn("DOMAIN-003", {value["article_code"] for value in signals})
        self.assertEqual(_SIGNAL_RULES["DOMAIN-003"][1:3], ("neutral", 0))

    def test_tracking_and_generic_forms_are_deduplicated_and_balanced(self) -> None:
        urls = [
            {
                "initial_apex": "mailer.example",
                "final_apex": "brand.example",
                "cross_apex_redirect": True,
                "forms": [],
            }
            for _ in range(8)
        ]
        urls.extend(
            [
                {
                    "initial_apex": "brand.example",
                    "final_apex": "brand.example",
                    "cross_apex_redirect": False,
                    "forms": [{"method": "GET", "inputs": ["query"]}],
                },
                {
                    "initial_apex": "brand.example",
                    "final_apex": "brand.example",
                    "cross_apex_redirect": False,
                    "forms": [{"method": "GET", "inputs": ["query"]}],
                },
            ]
        )
        signals = _signals(
            urls,
            [],
            {"ground_truth_labels": {}, "previous_message_count": 1},
            True,
            authenticated=True,
        )
        codes = [value["article_code"] for value in signals]
        self.assertEqual(codes.count("DEEP-006"), 1)
        self.assertEqual(codes.count("DEEP-007"), 1)
        self.assertNotIn("DEEP-001", codes)
        self.assertNotIn("DEEP-002", codes)

    def test_sensitive_forms_create_one_charge_per_family(self) -> None:
        urls = [
            {
                "initial_apex": "tracker.example",
                "final_apex": "unknown.example",
                "cross_apex_redirect": True,
                "forms": [{"method": "POST", "inputs": ["email", "password"]}],
            }
            for _ in range(4)
        ]
        signals = _signals(
            urls,
            [],
            {"ground_truth_labels": {}, "previous_message_count": 1},
            True,
        )
        codes = [value["article_code"] for value in signals]
        self.assertEqual(codes.count("DEEP-008"), 1)
        self.assertEqual(codes.count("DEEP-002"), 1)

    def test_authenticated_ambient_login_form_is_neutral_and_named(self) -> None:
        signals = _signals(
            [
                {
                    "initial_apex": "mailer.example",
                    "final_apex": "linkedin.com",
                    "cross_apex_redirect": True,
                    "forms": [
                        {
                            "method": "POST",
                            "inputs": ["session_key", "session_password"],
                        }
                    ],
                }
            ],
            [],
            {"ground_truth_labels": {}, "previous_message_count": 1},
            True,
            authenticated=True,
        )
        by_code = {value["article_code"]: value for value in signals}
        self.assertNotIn("DEEP-002", by_code)
        self.assertEqual(by_code["DEEP-014"]["sensitive_categories"], ["password"])

    async def test_single_use_url_is_never_sent_to_http_sandbox(self) -> None:
        raw = (
            b"From: sender@example.org\r\n"
            b"To: user@example.org\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b'<a href="https://accounts.example/reset?token=abcdefghijk">Login</a>'
        )
        pool = SimpleNamespace(
            fetchval=AsyncMock(return_value=False),
            execute=AsyncMock(),
        )
        client = SimpleNamespace(post=AsyncMock(side_effect=AssertionError("HTTP used")))
        urls, complete, _ = await _analyze_urls(
            pool,  # type: ignore[arg-type]
            client,  # type: ignore[arg-type]
            SimpleNamespace(url_sandbox_url="http://sandbox"),  # type: ignore[arg-type]
            "00000000-0000-0000-0000-000000000001",
            raw,
        )
        client.post.assert_not_awaited()
        self.assertTrue(complete)
        self.assertTrue(urls[0]["analysis_skipped"])
        self.assertEqual(
            urls[0]["skip_reason"], "protected_single_use_or_side_effect_url"
        )

    def test_html_context_replaces_plain_text_duplicate(self) -> None:
        raw = b"""From: sender@example.org\r
To: user@example.org\r
MIME-Version: 1.0\r
Content-Type: multipart/alternative; boundary=x\r
\r
--x\r
Content-Type: text/plain; charset=utf-8\r
\r
https://tracker.example/social\r
--x\r
Content-Type: text/html; charset=utf-8\r
\r
<a href="https://tracker.example/social"><img alt="LinkedIn"></a>\r
--x--\r
"""
        candidates, _ = _message_url_candidates(raw)
        link = next(item for item in candidates if item["url"].endswith("/social"))
        self.assertEqual(link["role"], "html_link")
        self.assertEqual(link["visible_text"], "LinkedIn")
        self.assertEqual(link["link_context"], "secondary_navigation")

    def test_plain_link_keeps_the_nearby_visible_label(self) -> None:
        raw = (
            b"From: sender@example.org\r\n"
            b"To: user@example.org\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Download invoice (https://pay.example.org/invoice/opaque)\r\n"
        )
        candidates, _ = _message_url_candidates(raw)
        self.assertEqual(candidates[0]["visible_text"], "Download invoice")

    def test_equivalent_mime_link_explains_same_apex_protocol_limit(self) -> None:
        results = [
            {
                "role": "plain_text",
                "visible_text": "Download invoice",
                "initial_url": "https://pay.stripe.example/invoice/opaque",
                "initial_apex": "stripe.example",
                "final_apex": "",
                "error": "fetch_error:HttpProtocolError",
            },
            {
                "role": "html_link",
                "visible_text": "Download invoice",
                "initial_url": "https://email.stripe.example/track/opaque",
                "initial_apex": "stripe.example",
                "final_apex": "stripe.example",
                "error": "fetch_error:HttpProtocolError",
                "navigation_limit_explained": True,
            },
        ]
        _contextualize_equivalent_url_limits(results, authenticated=True)
        self.assertTrue(results[0]["navigation_limit_explained"])
        self.assertEqual(
            results[0]["navigation_limit_reason"],
            "authenticated_equivalent_mime_link_same_apex",
        )

    def test_equivalent_label_never_excuses_a_different_apex(self) -> None:
        results = [
            {
                "visible_text": "Download invoice",
                "initial_url": "https://unknown.example/invoice",
                "initial_apex": "unknown.example",
                "error": "fetch_error:HttpProtocolError",
            },
            {
                "visible_text": "Download invoice",
                "initial_url": "https://billing.example.org/invoice",
                "initial_apex": "example.org",
                "final_apex": "example.org",
            },
        ]
        _contextualize_equivalent_url_limits(results, authenticated=True)
        self.assertNotIn("navigation_limit_explained", results[0])

    def test_sandbox_hop_timeout_is_a_navigation_limit(self) -> None:
        for error in ("hop_timeout", "sandbox_total_timeout", "timeout:read"):
            data = {
                "error": error,
                "initial_url": "https://tracker.example.net/ls/click",
                "initial_apex": "example.net",
                "final_apex": "example.net",
            }
            self.assertTrue(
                _explained_authenticated_same_apex_fetch_error(data, True), error
            )
            self.assertFalse(
                _explained_authenticated_same_apex_fetch_error(data, False), error
            )

    def test_a_sandbox_outage_is_never_an_explained_limit(self) -> None:
        data = {
            "error": "sandbox_request:ConnectError",
            "initial_url": "https://tracker.example.net/ls/click",
            "initial_apex": "example.net",
            "final_apex": "",
        }
        self.assertFalse(_explained_authenticated_same_apex_fetch_error(data, True))

    def test_a_hop_timeout_towards_another_apex_stays_a_gap(self) -> None:
        data = {
            "error": "hop_timeout",
            "initial_url": "https://tracker.example.net/ls/click",
            "initial_apex": "example.net",
            "final_apex": "elsewhere.example",
        }
        self.assertFalse(_explained_authenticated_same_apex_fetch_error(data, True))

    def test_a_network_delay_is_replayed_once_before_becoming_a_gap(self) -> None:
        responses = [
            {"initial_url": "https://tracker.example.net/x", "error": "hop_timeout"},
            {"initial_url": "https://tracker.example.net/x", "final_apex": "example.org"},
        ]

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=responses.pop(0))

        async def run() -> tuple[dict[str, object], str, Exception | None]:
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler)
            ) as client:
                return await fetch_url_analysis_with_retry(
                    client,
                    SimpleNamespace(url_sandbox_url="http://url-sandbox:8090"),
                    "https://tracker.example.net/x",
                    "key",
                )

        data, status, error = asyncio.run(run())
        self.assertEqual(status, "ok")
        self.assertIsNone(error)
        self.assertNotIn("error", data)
        self.assertEqual(responses, [])

    def test_a_persistent_delay_is_kept_as_a_gap_without_looping(self) -> None:
        calls = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(
                200,
                json={"initial_url": "https://tracker.example.net/x", "error": "hop_timeout"},
            )

        async def run() -> tuple[dict[str, object], str, Exception | None]:
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler)
            ) as client:
                return await fetch_url_analysis_with_retry(
                    client,
                    SimpleNamespace(url_sandbox_url="http://url-sandbox:8090"),
                    "https://tracker.example.net/x",
                    "key",
                )

        data, _, _ = asyncio.run(run())
        self.assertEqual(calls, 2)
        self.assertEqual(data["error"], "hop_timeout")
        self.assertTrue(data["retry_attempted"])

    def test_a_result_without_delay_is_never_replayed(self) -> None:
        calls = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(
                200,
                json={
                    "initial_url": "https://tracker.example.net/x",
                    "error": "credential_form",
                },
            )

        async def run() -> tuple[dict[str, object], str, Exception | None]:
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler)
            ) as client:
                return await fetch_url_analysis_with_retry(
                    client,
                    SimpleNamespace(url_sandbox_url="http://url-sandbox:8090"),
                    "https://tracker.example.net/x",
                    "key",
                )

        asyncio.run(run())
        self.assertEqual(calls, 1)

    def test_postgres_json_sanitizes_pdf_nul_recursively(self) -> None:
        encoded = _json({"text": "alpha\x00omega", "nested": ["x\x00y"]})
        self.assertNotIn("\\u0000", encoded)
        self.assertEqual(json.loads(encoded)["text"], "alpha\ufffdomega")

    async def test_pdf_nul_does_not_become_an_incomplete_analysis(self) -> None:
        message = EmailMessage()
        message["From"] = "sender@example.org"
        message["To"] = "user@example.org"
        message.set_content("Invoice attached")
        payload = b"%PDF-1.4 minimal test"
        message.add_attachment(
            payload,
            maintype="application",
            subtype="pdf",
            filename="invoice.pdf",
        )
        digest = hashlib.sha256(payload).hexdigest()
        pool = SimpleNamespace(
            fetch=AsyncMock(
                return_value=[
                    {
                        "path": "0.1",
                        "filename": "invoice.pdf",
                        "content_type": "application/pdf",
                        "decoded_size_bytes": len(payload),
                        "decoded_sha256": digest,
                    }
                ]
            ),
            fetchrow=AsyncMock(return_value=None),
            execute=AsyncMock(),
        )
        response = SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {
                "filename": "invoice.pdf",
                "score": 0.0,
                "findings": [],
                "extracted_text": "Invoice\x00paid",
                "analysis_incomplete": False,
            },
        )
        client = SimpleNamespace(post=AsyncMock(return_value=response))
        analyses, complete = await _analyze_attachments(
            pool,  # type: ignore[arg-type]
            client,  # type: ignore[arg-type]
            SimpleNamespace(file_sandbox_url="http://sandbox"),  # type: ignore[arg-type]
            "00000000-0000-0000-0000-000000000001",
            message.as_bytes(policy=policy.SMTP),
        )
        self.assertTrue(complete)
        self.assertFalse(analyses[0]["analysis_incomplete"])
        persisted_json = pool.execute.await_args.args[6]
        self.assertNotIn("\\u0000", persisted_json)
        self.assertEqual(json.loads(persisted_json)["extracted_text"], "Invoice\ufffdpaid")

    def test_incomplete_sandbox_results_are_neutral_procedural_limits(self) -> None:
        self.assertEqual(_SIGNAL_RULES["DEEP-003"][1:3], ("neutral", 0))
        self.assertEqual(_SIGNAL_RULES["DEEP-005"][1:3], ("neutral", 0))

    async def test_secondary_navigation_is_not_fetched_or_marked_incomplete(self) -> None:
        raw = (
            b"From: sender@example.org\r\n"
            b"To: user@example.org\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b'<a href="https://tracker.example/social"><img alt="LinkedIn"></a>'
        )
        pool = SimpleNamespace(
            fetchval=AsyncMock(return_value=False),
            execute=AsyncMock(),
        )
        client = SimpleNamespace(post=AsyncMock(side_effect=AssertionError("HTTP used")))
        urls, complete, _ = await _analyze_urls(
            pool,  # type: ignore[arg-type]
            client,  # type: ignore[arg-type]
            SimpleNamespace(url_sandbox_url="http://sandbox"),  # type: ignore[arg-type]
            "00000000-0000-0000-0000-000000000001",
            raw,
        )
        client.post.assert_not_awaited()
        self.assertTrue(complete)
        self.assertEqual(urls[0]["skip_reason"], "non_primary_navigation")

    async def test_unsubscribe_label_protects_an_opaque_tracking_url(self) -> None:
        raw = (
            b"From: sender@example.org\r\n"
            b"To: user@example.org\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b'<a href="https://tracker.example/opaque/123456">me desabonner</a>'
        )
        pool = SimpleNamespace(
            fetchval=AsyncMock(return_value=False),
            execute=AsyncMock(),
        )
        client = SimpleNamespace(post=AsyncMock(side_effect=AssertionError("HTTP used")))
        urls, complete, _ = await _analyze_urls(
            pool,  # type: ignore[arg-type]
            client,  # type: ignore[arg-type]
            SimpleNamespace(url_sandbox_url="http://sandbox"),  # type: ignore[arg-type]
            "00000000-0000-0000-0000-000000000001",
            raw,
        )
        client.post.assert_not_awaited()
        self.assertTrue(complete)
        self.assertEqual(
            urls[0]["skip_reason"], "protected_single_use_or_side_effect_url"
        )

    def test_render_resources_do_not_exhaust_actionable_url_budget(self) -> None:
        images = "".join(
            f'<img src="https://cdn.example.org/image-{index}.png">'
            for index in range(40)
        )
        raw = (
            "From: sender@example.org\r\n"
            "To: user@example.org\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" '
            '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'
            f'{images}<a href="https://brand.example.org/account">Compte</a>'
        ).encode()
        candidates, resource_total = _message_url_candidates(raw)
        actionable = [item for item in candidates if item["role"] != "render_resource"]
        self.assertEqual(len(actionable), 1)
        self.assertEqual(resource_total, 40)
        self.assertFalse(any("w3.org" in item["url"] for item in candidates))

    def test_url_selection_groups_equivalent_variants_without_merging_articles(self) -> None:
        candidates = [
            {
                "url": "https://news.example/track/a",
                "role": "plain_text",
                "visible_text": "A major security story",
                "link_context": "primary",
            },
            {
                "url": "https://news.example/track/b",
                "role": "html_link",
                "visible_text": "A major security story",
                "link_context": "primary",
            },
            {
                "url": "https://news.example/article/one",
                "role": "html_link",
                "visible_text": "Read more",
                "link_context": "primary",
            },
            {
                "url": "https://news.example/article/two",
                "role": "html_link",
                "visible_text": "Read more",
                "link_context": "primary",
            },
        ]
        selected, coverage = _select_url_candidates(candidates)
        self.assertEqual(len(selected), 3)
        self.assertEqual(coverage["actionable_representatives_total"], 3)
        self.assertEqual(coverage["exact_or_equivalent_urls_collapsed"], 1)

    def test_url_budget_grows_with_destination_diversity_but_stays_bounded(self) -> None:
        candidates = [
            {
                "url": f"https://site-{index}.com/path",
                "role": "html_link",
                "visible_text": f"Destination {index}",
                "link_context": "primary",
            }
            for index in range(MAX_URLS + 10)
        ]
        selected, coverage = _select_url_candidates(candidates)
        self.assertEqual(len(selected), MAX_URLS)
        self.assertEqual(coverage["adaptive_budget"], MAX_URLS)
        self.assertTrue(coverage["coverage_limited"])

    async def test_representative_budget_limit_is_context_not_analysis_failure(self) -> None:
        links = "".join(
            f'<a href="https://news.example/article-{index}">Story {index}</a>'
            for index in range(BASE_URLS + 5)
        )
        raw = (
            "From: sender@example.org\r\n"
            "To: user@example.org\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            + links
        ).encode()
        pool = SimpleNamespace(
            fetchval=AsyncMock(return_value=False),
            fetchrow=AsyncMock(return_value=None),
            execute=AsyncMock(),
        )
        response = SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {
                "initial_url": "https://news.example/article",
                "initial_host": "news.example",
                "initial_apex": "news.example",
                "final_host": "news.example",
                "final_apex": "news.example",
                "forms": [],
            },
        )
        client = SimpleNamespace(post=AsyncMock(return_value=response))
        urls, complete, coverage = await _analyze_urls(
            pool,  # type: ignore[arg-type]
            client,  # type: ignore[arg-type]
            SimpleNamespace(url_sandbox_url="http://sandbox"),  # type: ignore[arg-type]
            "00000000-0000-0000-0000-000000000001",
            raw,
        )
        self.assertEqual(len(urls), BASE_URLS)
        self.assertTrue(complete)
        self.assertTrue(coverage["coverage_limited"])
        self.assertEqual(coverage["uninspected_representatives"], 5)

    def test_cached_jsonb_accepts_asyncpg_string_representation(self) -> None:
        self.assertEqual(_json_object('{"status":"ok","score":1}')["status"], "ok")
        self.assertEqual(_json_object({"status": "ok"})["status"], "ok")

    def test_final_display_convergence_is_defence_evidence(self) -> None:
        signals = _signals(
            [
                {
                    "initial_apex": "tracker.example",
                    "final_apex": "brand.example",
                    "displayed_apex": "brand.example",
                    "cross_apex_redirect": True,
                    "forms": [],
                }
            ],
            [],
            {"ground_truth_labels": {}, "previous_message_count": 1},
            True,
            authenticated=True,
        )
        self.assertIn("DEEP-009", {item["article_code"] for item in signals})

    def test_authenticated_stable_redirect_limit_is_explained(self) -> None:
        data = {
            "error": "too_many_redirects",
            "initial_url": "https://tracker.example.net/campaign",
            "final_apex": "edf.fr",
            "chain": [
                {"url": "https://particulier.edf.fr/compte"},
                {"url": "https://espace-client.edf.fr/oauth2"},
                {"url": "https://attente.edf.fr/queue"},
                {"url": "https://espace-client.edf.fr/oauth2"},
            ],
        }
        self.assertTrue(_explained_authenticated_redirect_limit(data, True))
        self.assertFalse(_explained_authenticated_redirect_limit(data, False))

    def test_redirect_limit_with_unstable_apex_is_not_explained(self) -> None:
        data = {
            "error": "too_many_redirects",
            "initial_url": "https://tracker.example.net/campaign",
            "final_apex": "edf.fr",
            "chain": [
                {"url": "https://particulier.edf.fr/compte"},
                {"url": "https://unknown.example.org/bounce"},
                {"url": "https://espace-client.edf.fr/oauth2"},
            ],
        }
        self.assertFalse(_explained_authenticated_redirect_limit(data, True))

    def test_redirect_limit_without_observed_cycle_is_not_explained(self) -> None:
        data = {
            "error": "too_many_redirects",
            "initial_url": "https://tracker.example.net/campaign",
            "final_apex": "edf.fr",
            "chain": [
                {"url": "https://particulier.edf.fr/first"},
                {"url": "https://espace-client.edf.fr/second"},
                {"url": "https://attente.edf.fr/third"},
            ],
        }
        self.assertFalse(_explained_authenticated_redirect_limit(data, True))

    def test_authenticated_same_apex_protocol_error_is_contextualized(self) -> None:
        data = {
            "error": "fetch_error:HttpProtocolError",
            "initial_url": "https://service.example.org/help",
            "initial_apex": "example.org",
            "final_apex": "example.org",
        }
        self.assertTrue(_explained_authenticated_same_apex_fetch_error(data, True))
        self.assertFalse(_explained_authenticated_same_apex_fetch_error(data, False))

    def test_explained_redirect_limit_is_neutral_not_incomplete(self) -> None:
        signals = _signals(
            [
                {
                    "role": "html_link",
                    "error": "too_many_redirects",
                    "navigation_limit_explained": True,
                    "final_apex": "edf.fr",
                }
            ],
            [],
            {"ground_truth_labels": {}, "previous_message_count": 1},
            True,
            authenticated=True,
        )
        codes = {item["article_code"] for item in signals}
        self.assertIn("DEEP-012", codes)
        self.assertNotIn("DEEP-003", codes)

    def test_broken_remote_target_is_a_result_not_a_sandbox_outage(self) -> None:
        for error in (
            "blocked_url:dns_resolution_failed",
            "blocked_url:invalid_hostname",
            "blocked_url:missing_hostname",
            "redirect_without_location",
        ):
            with self.subTest(error=error):
                self.assertTrue(_is_definitive_target_failure(error))
                signals = _signals(
                    [{"role": "html_link", "error": error}],
                    [],
                    {"ground_truth_labels": {}, "previous_message_count": 1},
                    True,
                    authenticated=False,
                )
                self.assertNotIn(
                    "DEEP-003", {item["article_code"] for item in signals}
                )

    def test_security_block_remains_an_incomplete_inspection(self) -> None:
        self.assertFalse(
            _is_definitive_target_failure("blocked_url:non_global_address")
        )

    def test_plain_preview_is_html_escaped(self) -> None:
        raw = (
            b"From: attacker@example.org\r\n"
            b"To: user@example.org\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"<script>alert(1)</script>\r\n"
        )
        source = render_source(raw)
        self.assertIsNotNone(source)
        self.assertNotIn("<script>", source or "")
        self.assertIn("&lt;script&gt;", source or "")


class FreshCrossApexDestinationTests(unittest.TestCase):
    """B : une destination inter-apex récente reste suspecte sous auth."""

    HISTORY = {"ground_truth_labels": {}, "previous_message_count": 1}

    def _codes(self, urls, *, sender_apex, domain_ages, authenticated=True):
        signals = _signals(
            urls,
            [],
            self.HISTORY,
            True,
            authenticated=authenticated,
            sender_apex=sender_apex,
            domain_ages=domain_ages,
        )
        return {item["article_code"] for item in signals}

    def test_authenticated_sender_to_fresh_apex_is_adverse(self) -> None:
        # Le motif du phishing par abus d'ESP : émetteur aligné DMARC, CTA vers
        # un domaine de deux jours. L'auth ne doit pas l'absoudre.
        urls = [{"role": "actionable", "final_apex": "prim-clients.com"}]
        codes = self._codes(
            urls,
            sender_apex="aclscertification.org",
            domain_ages={"prim-clients.com": 2, "aclscertification.org": 5959},
        )
        self.assertIn("DOMAIN-004", codes)
        self.assertEqual(_SIGNAL_RULES["DOMAIN-004"][1], "adverse")

    def test_authenticated_sender_to_established_apex_stays_silent(self) -> None:
        # Le faux positif à éviter : newsletter authentifiée (Fulli, Synology)
        # renvoyant vers un apex établi. L'âge est le discriminant.
        urls = [{"role": "actionable", "final_apex": "verisure.fr"}]
        codes = self._codes(
            urls,
            sender_apex="fulli.fr",
            domain_ages={"verisure.fr": 4000, "fulli.fr": 3000},
        )
        self.assertNotIn("DOMAIN-004", codes)

    def test_same_apex_destination_is_not_cross_apex(self) -> None:
        urls = [{"role": "actionable", "final_apex": "aclscertification.org"}]
        codes = self._codes(
            urls,
            sender_apex="aclscertification.org",
            domain_ages={"aclscertification.org": 2},
        )
        self.assertNotIn("DOMAIN-004", codes)

    def test_a_render_resource_is_not_an_actionable_destination(self) -> None:
        # Un pixel de suivi jeune ne doit pas condamner : seul un lien
        # activable compte.
        urls = [{"role": "render_resource", "final_apex": "cdn-fresh.example"}]
        codes = self._codes(
            urls,
            sender_apex="sender.example",
            domain_ages={"cdn-fresh.example": 1},
        )
        self.assertNotIn("DOMAIN-004", codes)

    def test_unknown_destination_age_does_not_fire(self) -> None:
        # Sans âge RDAP établi, pas de charge : l'absence n'est pas une preuve.
        urls = [{"role": "actionable", "final_apex": "prim-clients.com"}]
        codes = self._codes(
            urls, sender_apex="aclscertification.org", domain_ages={}
        )
        self.assertNotIn("DOMAIN-004", codes)


if __name__ == "__main__":
    unittest.main()
