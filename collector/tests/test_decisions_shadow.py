from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx

from sentimail_v3.config import Settings
from sentimail_v3.judgment.decisions_shadow import (
    MAX_INPUT_CHARS,
    NEUTRAL_USER_AGENT,
    build_decisions_payload,
    build_report,
    build_shadow_input,
    compute_unsafe_divergence,
    evaluate_shadow,
    parse_decisions_response,
    resolve_gemini_api_key,
)


def _make_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "database_url": "postgresql://test:test@localhost/test",
        "smtp_host": "127.0.0.1",
        "smtp_port": 2525,
        "relay_host": "127.0.0.1",
        "relay_port": 10027,
        "enrichment_interval_seconds": 30,
        "conversation_enabled": False,
        "action_address": "maia@example.test",
        "action_aliases": (),
        "assistant_sender": "MAIA <maia@example.test>",
        "operator_address": "op@example.test",
        "operator_addresses": ("op@example.test",),
        "assistant_token_secret": "secret",
        "assistant_interval_seconds": 5,
        "deepseek_api_key": "",
        "search_api_key": "",
        "search_base_url": "https://api.tavily.com",
        "deepseek_base_url": "https://api.deepseek.com",
        "deepseek_verdict_model": "deepseek-v4-pro",
        "deepseek_assistant_model": "deepseek-v4-pro",
        "deepseek_timeout_seconds": 180,
        "remote_llm_deadline_seconds": 120,
        "economy_llm_deadline_seconds": 30,
        "verdict_interval_seconds": 5,
        "verdict_not_before": None,
        "decision_mode": True,
        "auto_delivery_confidence": 0.9,
        "analysis_wait_seconds": 30,
        "url_sandbox_url": "http://url-sandbox:8090",
        "file_sandbox_url": "http://file-sandbox:8091",
        "render_sandbox_url": "http://render-sandbox:8092",
        "provider_secrets_dir": "/nonexistent-secrets-dir",
        "anthropic_model": "claude-sonnet-5-5",
        "openai_model": "gpt-5.4",
        "assistant_llm_hourly_limit": 20,
        "assistant_llm_daily_limit": 100,
        "assistant_llm_conversation_limit": 10,
        "verdict_llm_hourly_limit": 100,
        "verdict_llm_daily_limit": 500,
        "verdict_concurrency": 2,
        "watchdog_ingress_host": "collector",
        "watchdog_ingress_port": 2525,
        "watchdog_smtp_preflight_enabled": True,
        "probe_enabled": False,
        "probe_recipient": "probe@example.test",
        "probe_timeout_seconds": 45,
        "probe_interval_seconds": 300,
        "retention_enabled": False,
        "retention_redact_after_days": 30,
        "retention_delete_after_days": 180,
        "retention_interval_seconds": 3600,
        "retention_batch_size": 500,
        "hold_lifecycle_enabled": False,
        "hold_reminder_after_days": 3,
        "hold_decision_after_days": 7,
        "hold_lifecycle_interval_seconds": 3600,
        "raw_eml_key_file": None,
        "digest_enabled": False,
        "digest_interval_hours": 24,
        "digest_minimum_cases": 2,
        "digest_quiet_hours": 12,
        "local_llm_url": "",
        "caretaker_interval_hours": 6,
        "console_url": "",
        "knowledge_path": "/app/knowledge",
        "knowledge_embedding_url": "",
        "knowledge_embedding_model": "bge-m3",
    }
    base.update(overrides)
    return Settings(**base)


def _sample_dossier() -> dict[str, Any]:
    return {
        "message": {
            "from_header": "Service Client <alerte@faux-domaine.example>",
            "envelope_from": "bounce@autre-domaine.example",
            "reply_to_header": "support@repondre.example",
            "subject": "Action urgente : votre compte est suspendu",
            "body_text": "Cliquez ici pour confirmer vos coordonnées bancaires sous 24h.",
            "body_html": "<html><body>SHOULD_NOT_APPEAR_HTML</body></html>",
            "raw_eml": "SHOULD_NOT_APPEAR_RAW_EML",
        },
        "selected_headers": [
            {
                "name_normalized": "authentication-results",
                "value": "mx.example; dmarc=fail spf=softfail dkim=none",
            }
        ],
        "clues": [
            {
                "clue_code": "AUTH-001",
                "direction": "adverse",
                "strength": 40,
                "statement": "DMARC en échec sur le domaine expéditeur",
            }
        ],
        "entities": [
            {
                "entity_type": "url",
                "role": "body_link",
                "value_normalized": "https://login-verif.example/auth",
            }
        ],
        "attachment_metadata": [
            {
                "filename": "facture.pdf",
                "content_type": "application/pdf",
                "decoded_size_bytes": 12345,
            }
        ],
    }


class _FakePool:
    def __init__(self, *, fail_shadow_insert: bool = False) -> None:
        self.executed: list[tuple[str, tuple[Any, ...]]] = []
        self.fetchvals: list[tuple[str, tuple[Any, ...]]] = []
        self.fail_shadow_insert = fail_shadow_insert
        self.report_row: dict[str, Any] = {}

    async def fetchval(self, query: str, *args: Any) -> Any:
        self.fetchvals.append((query, args))
        return 101

    async def execute(self, query: str, *args: Any) -> str:
        if self.fail_shadow_insert and "decisions_api_shadow" in query:
            raise RuntimeError("db unavailable")
        self.executed.append((query, args))
        return "INSERT 0 1"

    async def fetchrow(self, query: str, *args: Any) -> dict[str, Any]:
        return self.report_row


class _FakeResponse:
    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self._body = body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/decisions")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("http error", request=request, response=response)

    def json(self) -> Any:
        return self._body


class _FakeAsyncClient:
    def __init__(
        self,
        response: _FakeResponse | None = None,
        *,
        exc: BaseException | None = None,
        delay: float = 0.0,
    ) -> None:
        self.response = response
        self.exc = exc
        self.delay = delay
        self.calls: list[dict[str, Any]] = []

    async def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append({"url": url, **kwargs})
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.exc is not None:
            raise self.exc
        assert self.response is not None
        return self.response


class DecisionsShadowTests(unittest.IsolatedAsyncioTestCase):
    async def test_disabled_is_silent_noop(self) -> None:
        pool = _FakePool()
        client = _FakeAsyncClient()
        settings = _make_settings(gemini_decisions_enabled=False)
        with patch.dict(os.environ, {"GEMINI_API_KEY": "secret-key"}, clear=False):
            result = await evaluate_shadow(
                pool,
                client,  # type: ignore[arg-type]
                settings,
                message_id="11111111-1111-1111-1111-111111111111",
                verdict_run_id="22222222-2222-2222-2222-222222222222",
                dossier=_sample_dossier(),
                binding_result={"classification": "spam", "delivery_decision": "junk", "confidence": 0.95},
            )
        self.assertIsNone(result)
        self.assertEqual(client.calls, [])
        self.assertEqual(pool.executed, [])

    async def test_missing_key_is_silent_noop(self) -> None:
        pool = _FakePool()
        client = _FakeAsyncClient()
        settings = _make_settings(gemini_decisions_enabled=True)
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}, clear=False):
            result = await evaluate_shadow(
                pool,
                client,  # type: ignore[arg-type]
                settings,
                message_id="11111111-1111-1111-1111-111111111111",
                verdict_run_id="22222222-2222-2222-2222-222222222222",
                dossier=_sample_dossier(),
                binding_result={"classification": "spam", "delivery_decision": "junk", "confidence": 0.95},
            )
        self.assertIsNone(result)
        self.assertEqual(client.calls, [])
        self.assertEqual(pool.executed, [])

    def test_key_resolution_from_provider_secrets_dir_and_priority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            secrets_dir = Path(tmp) / "secrets"
            secrets_dir.mkdir()
            (secrets_dir / "gemini_api_key").write_text("  dir-secret-key\n", encoding="utf-8")

            settings = _make_settings(provider_secrets_dir=str(secrets_dir))
            with patch.dict(os.environ, {"GEMINI_API_KEY": "env-secret-key"}, clear=False):
                self.assertEqual(resolve_gemini_api_key(settings), "dir-secret-key")

            explicit_file = Path(tmp) / "custom_key"
            explicit_file.write_text("file-secret-key\n", encoding="utf-8")
            settings_explicit = _make_settings(
                provider_secrets_dir=str(secrets_dir),
                gemini_api_key_file=str(explicit_file),
            )
            self.assertEqual(resolve_gemini_api_key(settings_explicit), "file-secret-key")

    def test_build_shadow_input_bounded_and_excludes_html_and_raw(self) -> None:
        dossier = _sample_dossier()
        dossier["message"]["body_text"] = "A" * 50_000
        text = build_shadow_input(dossier)
        self.assertLessEqual(len(text), MAX_INPUT_CHARS)
        self.assertIn("Action urgente", text)
        self.assertIn("AUTH-001", text)
        self.assertIn("https://login-verif.example/auth", text)
        self.assertIn("facture.pdf", text)
        self.assertNotIn("SHOULD_NOT_APPEAR_HTML", text)
        self.assertNotIn("SHOULD_NOT_APPEAR_RAW_EML", text)

    def test_payload_shape_has_six_closed_set_questions(self) -> None:
        payload = build_decisions_payload("gemini-decision-1", "test input")
        self.assertEqual(payload["model"], "gemini-decision-1")
        self.assertEqual(payload["input"], "test input")
        questions = payload["questions"]
        self.assertEqual(
            set(questions.keys()),
            {
                "classification",
                "delivery_decision",
                "is_obvious_scam",
                "is_brand_impersonation",
                "requests_sensitive_action",
                "risk_score",
            },
        )
        self.assertEqual(questions["classification"]["type"], "choice")
        self.assertEqual(
            set(questions["classification"]["criteria"].keys()),
            {"legitimate", "spam", "dangerous"},
        )
        self.assertEqual(questions["delivery_decision"]["type"], "choice")
        self.assertEqual(
            set(questions["delivery_decision"]["criteria"].keys()),
            {"deliver", "junk", "ask_user"},
        )
        for noul_key in (
            "is_obvious_scam",
            "is_brand_impersonation",
            "requests_sensitive_action",
        ):
            self.assertEqual(questions[noul_key]["type"], "noul")
        self.assertEqual(questions["risk_score"]["type"], "score")
        self.assertIsInstance(questions["risk_score"]["criteria"], list)
        self.assertEqual(len(questions["risk_score"]["criteria"]), 5)

    def test_parse_response_choice_and_argmax_probabilities(self) -> None:
        response_payload = {
            "answers": {
                "classification": {
                    "type": "choice",
                    "probabilities": {"legitimate": 0.05, "spam": 0.15, "dangerous": 0.80},
                },
                "delivery_decision": {
                    "type": "choice",
                    "choice": "junk",
                    "probabilities": {"deliver": 0.02, "junk": 0.91, "ask_user": 0.07},
                    "confidence": 0.91,
                },
                "is_obvious_scam": {"type": "noul", "noul": 0.93, "confidence": 0.93},
                "is_brand_impersonation": {"type": "noul", "noul": 0.87, "confidence": 0.87},
                "requests_sensitive_action": {"type": "noul", "noul": 0.95, "confidence": 0.95},
                "risk_score": {"type": "score", "score": 4.7, "confidence": 0.9},
            },
            "usage": {"total_input_tokens": 512, "total_output_tokens": 0},
        }
        parsed = parse_decisions_response(
            response_payload,
            binding_classification="dangerous",
            binding_decision="ask_user",
        )
        self.assertEqual(parsed["input_tokens"], 512)
        self.assertEqual(parsed["predicted_classification"], "dangerous")
        self.assertAlmostEqual(parsed["classification_confidence"], 0.80)
        self.assertEqual(parsed["predicted_decision"], "junk")
        self.assertAlmostEqual(parsed["decision_confidence"], 0.91)
        self.assertAlmostEqual(parsed["scam_probability"], 0.93)
        self.assertAlmostEqual(parsed["impersonation_probability"], 0.87)
        self.assertAlmostEqual(parsed["sensitive_action_probability"], 0.95)
        self.assertAlmostEqual(parsed["risk_score"], 4.7)
        self.assertTrue(parsed["agrees_classification"])
        self.assertFalse(parsed["agrees_decision"])
        self.assertFalse(parsed["unsafe_divergence"])

    def test_unsafe_divergence_logic(self) -> None:
        self.assertTrue(compute_unsafe_divergence("deliver", "spam", "deliver"))
        self.assertTrue(compute_unsafe_divergence("deliver", "dangerous", "junk"))
        self.assertTrue(compute_unsafe_divergence("deliver", "suspect", "ask_user"))
        self.assertTrue(compute_unsafe_divergence("deliver", "undetermined", "junk"))
        self.assertFalse(compute_unsafe_divergence("deliver", "legitimate", "deliver"))
        self.assertFalse(compute_unsafe_divergence("junk", "dangerous", "ask_user"))
        self.assertFalse(compute_unsafe_divergence("ask_user", "spam", "junk"))
        self.assertFalse(compute_unsafe_divergence(None, "dangerous", "junk"))

    async def test_evaluate_shadow_success_inserts_db_and_uses_neutral_headers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "gemini_api_key").write_text("test-gemini-key", encoding="utf-8")
            settings = _make_settings(
                gemini_decisions_enabled=True,
                provider_secrets_dir=tmp,
            )
            api_body = {
                "answers": {
                    "classification": {
                        "type": "choice",
                        "choice": "legitimate",
                        "confidence": 0.77,
                    },
                    "delivery_decision": {
                        "type": "choice",
                        "choice": "deliver",
                        "confidence": 0.72,
                    },
                    "is_obvious_scam": {"type": "noul", "noul": 0.12},
                    "is_brand_impersonation": {"type": "noul", "noul": 0.08},
                    "requests_sensitive_action": {"type": "noul", "noul": 0.25},
                    "risk_score": {"type": "score", "score": 1.4},
                },
                "usage": {"total_input_tokens": 320, "total_output_tokens": 0},
            }
            pool = _FakePool()
            client = _FakeAsyncClient(_FakeResponse(200, api_body))

            res = await evaluate_shadow(
                pool,
                client,  # type: ignore[arg-type]
                settings,
                message_id="11111111-1111-1111-1111-111111111111",
                verdict_run_id="22222222-2222-2222-2222-222222222222",
                dossier=_sample_dossier(),
                binding_result={"classification": "dangerous", "delivery_decision": "ask_user", "confidence": 0.85},
            )

        self.assertIsNotNone(res)
        assert res is not None
        self.assertEqual(res["status"], "ok")
        self.assertTrue(res["unsafe_divergence"])

        self.assertEqual(len(client.calls), 1)
        call = client.calls[0]
        self.assertEqual(call["url"], settings.gemini_decisions_url)
        headers = call["headers"]
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["x-goog-api-key"], "test-gemini-key")
        self.assertEqual(headers["User-Agent"], NEUTRAL_USER_AGENT)
        for forbidden in ("sentimail",):
            self.assertNotIn(forbidden, json.dumps(headers).lower())

        # Vérifie l'insertion dans decisions_api_shadow et le journal llm_attempt_events
        self.assertTrue(any("llm_attempt_events" in q for q, _ in pool.fetchvals))
        shadow_inserts = [
            (q, args) for q, args in pool.executed if "INSERT INTO decisions_api_shadow" in q
        ]
        self.assertEqual(len(shadow_inserts), 1)
        _, args = shadow_inserts[0]
        self.assertEqual(args[0], "11111111-1111-1111-1111-111111111111")
        self.assertEqual(args[1], "22222222-2222-2222-2222-222222222222")
        self.assertEqual(args[2], "gemini-decision-1")
        self.assertEqual(args[3], "ok")
        self.assertIsNone(args[4])
        self.assertEqual(args[6], 320)
        self.assertEqual(args[7], "dangerous")
        self.assertEqual(args[8], "ask_user")
        self.assertEqual(args[10], "legitimate")
        self.assertEqual(args[11], "deliver")
        self.assertIs(args[19], False)  # agrees_classification
        self.assertIs(args[20], False)  # agrees_decision
        self.assertIs(args[21], True)  # unsafe_divergence

    async def test_fail_soft_on_http_error(self) -> None:
        settings = _make_settings(gemini_decisions_enabled=True)
        pool = _FakePool()
        client = _FakeAsyncClient(_FakeResponse(503, {"error": "unavailable"}))

        with patch.dict(os.environ, {"GEMINI_API_KEY": "env-key"}, clear=False):
            res = await evaluate_shadow(
                pool,
                client,  # type: ignore[arg-type]
                settings,
                message_id="11111111-1111-1111-1111-111111111111",
                verdict_run_id="22222222-2222-2222-2222-222222222222",
                dossier=_sample_dossier(),
                binding_result={"classification": "spam", "delivery_decision": "junk", "confidence": 0.92},
            )
        self.assertIsNone(res)
        shadow_inserts = [
            args for q, args in pool.executed if "INSERT INTO decisions_api_shadow" in q
        ]
        self.assertEqual(len(shadow_inserts), 1)
        self.assertEqual(shadow_inserts[0][3], "error")
        self.assertEqual(shadow_inserts[0][4], "HTTPStatusError")

    async def test_fail_soft_on_timeout_and_db_failure(self) -> None:
        settings = _make_settings(
            gemini_decisions_enabled=True,
            gemini_decisions_timeout_seconds=0.05,
        )
        pool = _FakePool(fail_shadow_insert=True)
        client = _FakeAsyncClient(_FakeResponse(200, {}), delay=0.5)

        with patch.dict(os.environ, {"GEMINI_API_KEY": "env-key"}, clear=False):
            res = await evaluate_shadow(
                pool,
                client,  # type: ignore[arg-type]
                settings,
                message_id="11111111-1111-1111-1111-111111111111",
                verdict_run_id=None,
                dossier=_sample_dossier(),
                binding_result={"classification": "legitimate", "delivery_decision": "deliver", "confidence": 0.99},
            )
        self.assertIsNone(res)

    async def test_build_report_formats_metrics(self) -> None:
        pool = _FakePool()
        pool.report_row = {
            "total": 10,
            "ok": 9,
            "errors": 1,
            "p50_latency_ms": 182.346,
            "p95_latency_ms": 412.678,
            "avg_input_tokens": 480.44,
            "classification_agreement_rate": 0.88888,
            "decision_agreement_rate": 0.77777,
            "ask_user_to_junk_on_scams": 2,
            "unsafe_divergences": 0,
            "ground_truth_matches": 3,
            "ground_truth_total": 4,
        }
        report = await build_report(pool, days=7)
        self.assertEqual(report["days"], 7)
        self.assertEqual(report["total"], 10)
        self.assertEqual(report["ok"], 9)
        self.assertEqual(report["errors"], 1)
        self.assertEqual(report["p50_latency_ms"], 182.35)
        self.assertEqual(report["p95_latency_ms"], 412.68)
        self.assertEqual(report["avg_input_tokens"], 480.4)
        self.assertEqual(report["classification_agreement_rate"], 0.8889)
        self.assertEqual(report["decision_agreement_rate"], 0.7778)
        self.assertEqual(report["ask_user_to_junk_on_scams"], 2)
        self.assertEqual(report["unsafe_divergences"], 0)
        self.assertEqual(report["ground_truth_matches"], 3)
        self.assertEqual(report["ground_truth_total"], 4)


if __name__ == "__main__":
    unittest.main()
