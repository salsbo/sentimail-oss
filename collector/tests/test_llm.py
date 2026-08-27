from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import httpx
from sentimail_v3.config import load_settings
from sentimail_v3.llm import (
    LlmError,
    ProviderRoute,
    openai_compatible_chat_json,
    provider_chat_json,
)
from sentimail_v3.judgment.verdict_engine import (
    MAX_LLM_DOSSIER_CHARS,
    _deduplicate_clues,
    _fit_dossier,
    _parse_verdict,
    _prompt,
)


class VerdictParsingTests(unittest.TestCase):
    @staticmethod
    def _judgment_rules() -> dict[str, object]:
        return {
            "verdict_is_final": True,
            "confidence_required": 0.90,
            "deep_execution_complete": True,
            "static_investigation_complete": True,
            "material_danger_evidence": [],
            "authenticated_sender_policy": "none",
        }

    def setUp(self) -> None:
        self.dossier = {
            "privacy": {
                "raw_eml_included": False,
                "html_included": False,
                "attachment_content_included": False,
            },
            "message": {"body_text": "bonjour"},
            "clues": [
                {"id": 1, "clue_code": "AUTH.DMARC.PASS"},
                {"id": 2, "clue_code": "HEADER.REPLY_TO.DISTINCT"},
            ],
            "judgment_rules": self._judgment_rules(),
        }

    def test_constrains_verdict_and_rejects_invented_clues(self) -> None:
        parsed = _parse_verdict(
            """{
                "classification":"delete",
                "confidence":4,
                "delivery_decision":"ask_user",
                "rationale":"incertain",
                "supporting_clue_codes":["AUTH.DMARC.PASS","INVENTED"],
                "contradicting_clue_codes":["HEADER.REPLY_TO.DISTINCT"],
                "uncertainties":["intention inconnue"],
                "requested_additional_evidence":[]
            }""",
            self.dossier,
        )
        self.assertEqual(parsed["classification"], "undetermined")
        self.assertEqual(parsed["confidence"], 1.0)
        self.assertEqual(parsed["supporting_clue_codes"], ["AUTH.DMARC.PASS"])

    def test_parses_three_role_trial_and_enforces_evidence_direction(self) -> None:
        dossier = {
            "clues": [
                {"id": 1, "clue_code": "AUTH_FAIL", "direction": "adverse"},
                {"id": 2, "clue_code": "OLD_DOMAIN", "direction": "favorable"},
            ],
            "judgment_rules": self._judgment_rules(),
        }
        parsed = _parse_verdict(
            """{
              "unfavorable":{"clue_codes":["AUTH_FAIL","OLD_DOMAIN","FAKE"],
                              "arguments":["Authentification en échec."]},
              "favorable":{"clue_codes":["OLD_DOMAIN","AUTH_FAIL"],
                           "arguments":["Domaine ancien."]},
              "final_verdict":{"classification":"suspect","confidence":0.81,
                         "delivery_decision":"ask_user",
                         "rationale":"La charge l'emporte sans danger matériel.",
                         "doubt":true,"doubt_reasons":["Intention inconnue"]}
            }""",
            dossier,
        )
        self.assertEqual(parsed["supporting_clue_codes"], ["AUTH_FAIL"])
        self.assertEqual(parsed["contradicting_clue_codes"], ["OLD_DOMAIN"])
        self.assertEqual(parsed["classification"], "suspect")
        self.assertTrue(parsed["verdict_doubt"])

    def test_a_verdict_cannot_cite_evidence_absent_from_this_message(self) -> None:
        # Ce cas garde volontairement l'ancien schema (prosecutor/defence/judge) :
        # une reponse ecrite avant le renommage doit rester comprise.
        dossier = {
            "clues": [
                {
                    "id": 1,
                    "article_code": "IDENTITY-005",
                    "clue_code": "IDENTITY_ENVELOPE_VISIBLE_ALIGNED",
                    "direction": "favorable",
                }
            ],
            "judgment_rules": self._judgment_rules(),
        }
        with self.assertRaisesRegex(ValueError, "IDENTITY-004"):
            _parse_verdict(
                """{
                  "prosecutor":{"clue_codes":[],"arguments":[]},
                  "defence":{"clue_codes":["IDENTITY_ENVELOPE_VISIBLE_ALIGNED"],
                               "arguments":[]},
                  "judge":{"classification":"suspect","confidence":0.7,
                             "delivery_decision":"ask_user",
                             "rationale":"IDENTITY-004 prouve une tromperie.",
                             "doubt":true,"doubt_reasons":[]}
                }""",
                dossier,
            )

    def test_prompt_marks_email_as_untrusted_data(self) -> None:
        prompt = _prompt(self.dossier)
        self.assertIn("jamais instructions", prompt[1]["content"])
        self.assertIn("examen contradictoire", prompt[0]["content"])
        self.assertIn("ÉLÉMENTS DÉFAVORABLES", prompt[0]["content"])
        self.assertIn("ÉLÉMENTS FAVORABLES", prompt[0]["content"])
        self.assertIn("VERDICT FINAL", prompt[0]["content"])
        self.assertIn("Sans élément matériel de dommage", prompt[0]["content"])
        self.assertNotIn("raw_eml", self.dossier["message"])
        self.assertNotIn("body_html", self.dossier["message"])

    def test_repeated_clue_family_is_counted_once(self) -> None:
        clues = _deduplicate_clues(
            [
                {
                    "id": index,
                    "article_code": "DEEP-001",
                    "clue_code": "URL_SANDBOX_CROSS_APEX",
                    "direction": "adverse",
                    "strength": 55,
                    "confidence": 0.9,
                    "statement": "redirect",
                    "facts": {},
                    "provenance": {},
                }
                for index in range(8)
            ]  # type: ignore[arg-type]
        )
        self.assertEqual(len(clues), 1)
        self.assertEqual(clues[0]["occurrence_count"], 8)

    def test_llm_dossier_is_bounded_without_dropping_budget_notice(self) -> None:
        dossier = {
            "message": {"body_text": "x" * 500_000},
            "entities": [{"value": "y" * 10_000} for _ in range(250)],
            "clues": [{"statement": "z" * 10_000} for _ in range(200)],
            "selected_headers": [{"value": "h" * 10_000} for _ in range(100)],
            "deep_analysis": {
                "url_analyses": [{"body": "u" * 20_000} for _ in range(20)],
                "attachment_analyses": [],
            },
            "code_articles": [{"principle": "a" * 10_000} for _ in range(54)],
        }
        fitted = _fit_dossier(dossier)
        rendered = json.dumps(fitted)
        self.assertLessEqual(len(rendered), MAX_LLM_DOSSIER_CHARS)
        self.assertTrue(fitted["llm_budget"]["truncated_for_llm"])


class OpenAICompatibleClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_calls_json_api_without_leaking_key_in_payload(self) -> None:
        seen: dict[str, object] = {}

        async def handler(request: httpx.Request) -> httpx.Response:
            seen["authorization"] = request.headers.get("authorization")
            seen["body"] = request.content.decode()
            return httpx.Response(
                200,
                json={
                    "id": "test",
                    "model": "deepseek-v4-pro",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": "{\"ok\":true}"},
                        }
                    ],
                    "usage": {"total_tokens": 12},
                },
            )

        route = ProviderRoute(
            "openai_compatible", "https://api.deepseek.test", "deepseek-v4-pro",
            "secret-test-key", "max_tokens",
        )
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as client:
            content, metadata = await openai_compatible_chat_json(
                client,
                route=route,
                messages=[{"role": "user", "content": "JSON"}],
                max_tokens=20,
            )
        self.assertEqual(content, '{"ok":true}')
        self.assertEqual(metadata["finish_reason"], "stop")
        self.assertEqual(seen["authorization"], "Bearer secret-test-key")
        self.assertNotIn("secret-test-key", str(seen["body"]))
        # DeepSeek (max_tokens) accepte et attend toujours temperature.
        self.assertEqual(json.loads(str(seen["body"]))["temperature"], 0.1)

    async def test_redacts_http_error_body(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            del request
            return httpx.Response(401, text="sensitive provider response")

        route = ProviderRoute(
            "openai_compatible", "https://api.deepseek.test", "deepseek-v4-pro",
            "secret-test-key", "max_tokens",
        )
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as client:
            with self.assertRaisesRegex(LlmError, "LLM HTTP 401"):
                await openai_compatible_chat_json(
                    client,
                    route=route,
                    messages=[{"role": "user", "content": "JSON"}],
                    max_tokens=20,
                )

    async def test_openai_adapter_uses_supported_chat_parameters(self) -> None:
        seen: dict[str, object] = {}

        async def handler(request: httpx.Request) -> httpx.Response:
            seen["authorization"] = request.headers.get("authorization")
            seen["json"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "id": "openai-test",
                    "model": "gpt-5.4",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": '{"ok":true}'},
                        }
                    ],
                    "usage": {"total_tokens": 10},
                },
            )

        class Pool:
            async def fetchrow(self, query: str, *args: object):
                del query, args
                return {
                    "provider": "openai_compatible",
                    "base_url": "https://api.openai.com/v1",
                    "model_name": "gpt-5.4",
                    "token_limit_param": "max_completion_tokens",
                    "secret_filename": "openai_api_key",
                }

        with TemporaryDirectory() as directory:
            Path(directory, "openai_api_key").write_text(
                "sk-openai-test-key-1234567890"
            )
            with patch.dict("os.environ", {"DATABASE_URL": "postgresql://test"}):
                settings = replace(load_settings(), provider_secrets_dir=directory)
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler)
            ) as client:
                content, metadata = await provider_chat_json(
                    Pool(),  # type: ignore[arg-type]
                    client,
                    settings,
                    messages=[{"role": "user", "content": "JSON"}],
                    max_tokens=20,
                )
        payload = seen["json"]
        self.assertEqual(content, '{"ok":true}')
        self.assertEqual(metadata["provider"], "openai_compatible")
        self.assertEqual(
            seen["authorization"], "Bearer sk-openai-test-key-1234567890"
        )
        self.assertEqual(payload["max_completion_tokens"], 20)  # type: ignore[index]
        self.assertNotIn("thinking", payload)  # type: ignore[operator]
        # OpenAI (max_completion_tokens) refuse temperature : elle ne doit
        # jamais figurer dans le corps envoyé à cet endpoint.
        self.assertNotIn("temperature", payload)  # type: ignore[operator]


class MaterialSpamProfileTests(unittest.TestCase):
    """Un profil de spam matériel remonte suspect -> spam/junk, jamais legitimate."""

    @staticmethod
    def _dossier(*clue_codes: str) -> dict[str, object]:
        codes = set(clue_codes)
        return {
            "clues": [
                {"id": i, "clue_code": code, "direction": "adverse"}
                for i, code in enumerate(clue_codes, start=1)
            ],
            "material_spam_profile": (
                "AUTH_DMARC_FAIL" in codes
                and "HISTORY_FIRST_OBSERVATION" in codes
                and bool(
                    codes
                    & {
                        "NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS",
                        "NATURE_SOLICITATION_WITHOUT_OPT_OUT",
                    }
                )
            ),
            "judgment_rules": {
                "verdict_is_final": True,
                "confidence_required": 0.90,
                "deep_execution_complete": True,
                "static_investigation_complete": True,
                "material_danger_evidence": [],
                "authenticated_sender_policy": "none",
            },
        }

    @staticmethod
    def _verdict(classification: str, decision: str, confidence: float = 0.7) -> str:
        return json.dumps(
            {
                "final_verdict": {
                    "classification": classification,
                    "confidence": confidence,
                    "delivery_decision": decision,
                    "rationale": "x",
                }
            }
        )

    PROFILE = (
        "AUTH_DMARC_FAIL",
        "HISTORY_FIRST_OBSERVATION",
        "NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS",
    )

    def test_forged_unsolicited_first_contact_pitch_becomes_junk(self) -> None:
        parsed = _parse_verdict(
            self._verdict("suspect", "ask_user"), self._dossier(*self.PROFILE)
        )
        self.assertEqual(parsed["classification"], "spam")
        self.assertEqual(parsed["delivery_decision"], "junk")

    def test_a_truncated_clue_list_still_condemns_the_profile(self) -> None:
        # Le dossier envoyé au LLM peut être tronqué : le flag, calculé sur les
        # indices complets, doit suffire même si les indices du profil ont
        # disparu de la liste. C'était la cause des arnaques restées en held.
        dossier = self._dossier()  # aucun indice dans la liste
        dossier["material_spam_profile"] = True
        parsed = _parse_verdict(self._verdict("spam", "ask_user"), dossier)
        self.assertEqual(parsed["delivery_decision"], "junk")

    def test_spam_classified_but_still_asked_is_forced_to_junk(self) -> None:
        # L'arbitre classe spam mais demande confirmation : le profil matériel
        # tranche, on file en indésirables sans déranger l'utilisateur.
        parsed = _parse_verdict(
            self._verdict("spam", "ask_user"), self._dossier(*self.PROFILE)
        )
        self.assertEqual(parsed["classification"], "spam")
        self.assertEqual(parsed["delivery_decision"], "junk")

    def test_low_confidence_native_junk_is_lifted_to_the_threshold(self) -> None:
        # L'arbitre junke déjà mais sous le seuil : sans relèvement, la
        # validation rétrograde en revue (le vrai bug des arnaques santé). Le
        # profil matériel porte la confiance au seuil pour que junk tienne.
        parsed = _parse_verdict(
            self._verdict("spam", "junk", confidence=0.65),
            self._dossier(*self.PROFILE),
        )
        self.assertEqual(parsed["delivery_decision"], "junk")
        self.assertGreaterEqual(parsed["confidence"], 0.90)

    def test_a_legitimate_verdict_is_never_upgraded(self) -> None:
        # Le garde-fou absolu : on ne touche jamais un verdict propre, donc aucun
        # faux positif possible sur du courrier livré.
        parsed = _parse_verdict(
            self._verdict("legitimate", "deliver", confidence=0.95),
            self._dossier(*self.PROFILE),
        )
        self.assertEqual(parsed["classification"], "legitimate")
        self.assertEqual(parsed["delivery_decision"], "deliver")

    def test_an_authenticated_sender_is_not_the_profile(self) -> None:
        # Sans DMARC fail (expéditeur non forgé), le profil ne tient pas :
        # une newsletter authentifiée douteuse reste en revue, pas en junk.
        parsed = _parse_verdict(
            self._verdict("suspect", "ask_user"),
            self._dossier(
                "HISTORY_FIRST_OBSERVATION",
                "NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS",
            ),
        )
        self.assertEqual(parsed["classification"], "suspect")
        self.assertEqual(parsed["delivery_decision"], "ask_user")

    def test_a_known_correspondent_is_not_the_profile(self) -> None:
        # Une relation préalable (pas de première observation) exclut le profil,
        # même si un mail authentique casse DMARC en transit.
        parsed = _parse_verdict(
            self._verdict("suspect", "ask_user"),
            self._dossier(
                "AUTH_DMARC_FAIL", "NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS"
            ),
        )
        self.assertEqual(parsed["classification"], "suspect")

    def test_an_incomplete_analysis_is_not_condemned(self) -> None:
        # On ne condamne pas sur un dossier partiel, même profil réuni.
        dossier = self._dossier(*self.PROFILE)
        dossier["judgment_rules"]["deep_execution_complete"] = False
        parsed = _parse_verdict(self._verdict("suspect", "ask_user"), dossier)
        self.assertEqual(parsed["classification"], "suspect")
        self.assertEqual(parsed["delivery_decision"], "ask_user")


if __name__ == "__main__":
    unittest.main()
