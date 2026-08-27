from __future__ import annotations

import json
import os
import unittest
import unittest.mock
from typing import Any

import asyncpg
import httpx
from sentimail_v3 import llm
from sentimail_v3.config import Settings, load_settings
from sentimail_v3.llm import LlmError, ProviderRoute, local_chat_json, local_route
from sentimail_v3.supervision.local_llm import probe


def _settings() -> Settings:
    from dataclasses import replace

    return replace(load_settings(), local_llm_url="http://ollama.test")


def _ollama(content: str, status: int = 200) -> httpx.AsyncClient:
    async def handler(request: httpx.Request) -> httpx.Response:
        if status != 200:
            return httpx.Response(status, json={"error": "boom"})
        return httpx.Response(
            200,
            json={
                "model": json.loads(request.content)["model"],
                "message": {"role": "assistant", "content": content},
                "done_reason": "stop",
                "eval_count": 42,
            },
        )

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class LocalChatTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_local_answer_is_returned_with_its_provenance(self) -> None:
        async with _ollama('{"answer": "bonjour"}') as client:
            content, metadata = await local_chat_json(
                client,
                base_url="http://ollama.test",
                model="qwen3:14b",
                messages=[{"role": "user", "content": "salut"}],
                max_tokens=100,
            )
        self.assertIn("bonjour", content)
        self.assertEqual(metadata["provider"], "ollama")
        self.assertTrue(metadata["local"])

    async def test_an_empty_local_answer_is_an_error(self) -> None:
        async with _ollama("   ") as client:
            with self.assertRaises(LlmError):
                await local_chat_json(
                    client,
                    base_url="http://ollama.test",
                    model="qwen3:14b",
                    messages=[{"role": "user", "content": "salut"}],
                    max_tokens=100,
                )

    async def test_without_an_address_nothing_is_attempted(self) -> None:
        async with _ollama('{"a":1}') as client:
            with self.assertRaisesRegex(LlmError, "adresse"):
                await local_chat_json(
                    client,
                    base_url="",
                    model="qwen3:14b",
                    messages=[{"role": "user", "content": "salut"}],
                    max_tokens=100,
                )

    async def test_probing_reports_a_model_that_ignores_the_schema(self) -> None:
        async with _ollama('{"bavardage": "je preferais repondre en prose"}'):
            pass
        # Le modèle répond du JSON, mais pas celui que le code sait lire.
        import sentimail_v3.supervision.local_llm as module

        async def fake_chat(client: Any, **kwargs: Any) -> tuple[str, dict[str, Any]]:
            return '{"bavardage": "non"}', {"usage": {"eval_count": 3}}

        original = module.local_chat_json
        module.local_chat_json = fake_chat
        try:
            report = await probe("qwen3:14b", "http://ollama.test")
        finally:
            module.local_chat_json = original
        self.assertFalse(report["roles"]["conversation"]["ok"])
        self.assertIn("tool", report["roles"]["conversation"]["missing_keys"])
        self.assertFalse(report["roles"]["verdict"]["ok"])


class FallbackRoleTests(unittest.IsolatedAsyncioTestCase):
    """Le repli local -> distant ne doit pas perdre le rôle en route.

    `provider_chat_json` ne se rappelait pas lui-même sans `role=...` lors du
    repli, ce qui faisait retomber `_provider_role(None)` sur "verdict" - une
    conversation recevait alors une réponse taillée pour un jugement. Ici on
    fige un rôle "conversation" et on vérifie qu'il ressort tel quel côté
    `active_provider`, sans passer par une vraie base de données.
    """

    async def test_a_local_failure_falls_back_to_the_remote_provider(self) -> None:
        captured_roles: list[str | None] = []

        async def local_route_stub(pool: Any, role: str | None) -> tuple[str, bool]:
            return ("qwen3:14b", True)

        async def broken_local(client: Any, **kwargs: Any) -> tuple[str, dict[str, Any]]:
            raise LlmError("modèle local HTTP 500")

        async def active_provider_stub(
            pool: Any, settings: Settings, role: str | None = None
        ) -> ProviderRoute:
            captured_roles.append(role)
            return ProviderRoute(
                "openai_compatible",
                "https://api.deepseek.com",
                "deepseek-v4-pro",
                "clef-de-test",
                "max_tokens",
            )

        async def remote_chat(
            client: Any, *, route: ProviderRoute, messages: Any, max_tokens: int
        ) -> tuple[str, dict[str, Any]]:
            return '{"ok":1}', {"model": route.model}

        originals = (
            llm.local_route,
            llm.local_chat_json,
            llm.active_provider,
            llm.openai_compatible_chat_json,
        )
        llm.local_route = local_route_stub
        llm.local_chat_json = broken_local
        llm.active_provider = active_provider_stub
        llm.openai_compatible_chat_json = remote_chat
        try:
            with unittest.mock.patch.dict(
                os.environ, {"DATABASE_URL": "postgresql://test"}
            ):
                settings = _settings()
            content, metadata = await llm.provider_chat_json(
                None,
                None,
                settings,
                messages=[{"role": "user", "content": "x"}],
                max_tokens=10,
                role="conversation",
            )
        finally:
            (
                llm.local_route,
                llm.local_chat_json,
                llm.active_provider,
                llm.openai_compatible_chat_json,
            ) = originals
        self.assertIn("ok", content)
        self.assertEqual(metadata["provider"], "openai_compatible")
        # La panne locale est dite, pas avalée : sinon le repli deviendrait
        # permanent sans que personne ne le sache.
        self.assertEqual(metadata["local_fallback_from"], "qwen3:14b")
        self.assertIn("HTTP 500", metadata["local_failure"])
        # Verrou : le rôle d'origine ("conversation") doit atteindre
        # active_provider lors du repli, jamais None.
        self.assertEqual(captured_roles, ["conversation"])


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class RoutingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])

    async def asyncTearDown(self) -> None:
        await self.pool.execute("DELETE FROM llm_local_routing")
        await self.pool.close()

    async def test_no_route_means_the_remote_provider_keeps_the_role(self) -> None:
        self.assertIsNone(await local_route(self.pool, "conversation"))
        self.assertIsNone(await local_route(self.pool, None))

    async def test_a_disabled_route_is_not_a_route(self) -> None:
        await self.pool.execute(
            "INSERT INTO llm_local_routing (role, model_name, enabled) "
            "VALUES ('conversation','qwen3:14b',false)"
        )
        self.assertIsNone(await local_route(self.pool, "conversation"))

    async def test_roles_are_switched_one_by_one(self) -> None:
        await self.pool.execute(
            "INSERT INTO llm_local_routing (role, model_name, enabled) "
            "VALUES ('conversation','qwen3:14b',true)"
        )
        self.assertEqual(await local_route(self.pool, "conversation"), ("qwen3:14b", True))
        # Le verdict, lui, reste chez le fournisseur distant.
        self.assertIsNone(await local_route(self.pool, "verdict"))

    async def test_without_fallback_a_local_failure_is_final(self) -> None:
        await self.pool.execute(
            "INSERT INTO llm_local_routing "
            "(role, model_name, enabled, fallback_enabled) "
            "VALUES ('conversation','qwen3:14b',true,false)"
        )
        original = llm.local_chat_json

        async def broken(client: Any, **kwargs: Any) -> tuple[str, dict[str, Any]]:
            raise LlmError("modèle local HTTP 500")

        llm.local_chat_json = broken
        try:
            with self.assertRaisesRegex(LlmError, "HTTP 500"):
                await llm.provider_chat_json(
                    self.pool,
                    None,
                    _settings(),
                    messages=[{"role": "user", "content": "x"}],
                    max_tokens=10,
                    role="conversation",
                )
        finally:
            llm.local_chat_json = original


if __name__ == "__main__":
    unittest.main()
