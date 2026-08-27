# collector/tests/test_llm_routes.py
from __future__ import annotations

import unittest
from unittest.mock import AsyncMock

from sentimail_v3.llm import (
    LlmError,
    ProviderRoute,
    active_provider,
    _provider_role,
)


class RoleMappingTests(unittest.TestCase):
    def test_la_conversation_va_a_la_carte_conversation(self) -> None:
        self.assertEqual(_provider_role("conversation"), "conversation")

    def test_tout_le_reste_va_a_la_carte_verdict(self) -> None:
        for role in ("verdict", "requested_action", "identity_claim",
                     "activity_coherence", None):
            self.assertEqual(_provider_role(role), "verdict")


class _FakePool:
    def __init__(self, row):
        self._row = row
        self.queries = []

    async def fetchrow(self, sql, *args):
        self.queries.append((sql, args))
        return self._row


class _EnvSettings:
    deepseek_api_key = "cle-env"
    deepseek_base_url = "https://api.deepseek.com"
    deepseek_verdict_model = "deepseek-v4-pro"
    deepseek_assistant_model = "deepseek-v4-pro"
    provider_secrets_dir = "/nonexistent"


class ActiveProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_table_vide_replie_sur_l_environnement(self) -> None:
        route = await active_provider(_FakePool(None), _EnvSettings(), role="verdict")
        self.assertEqual(route.provider, "openai_compatible")
        self.assertEqual(route.base_url, "https://api.deepseek.com")
        self.assertEqual(route.model, "deepseek-v4-pro")
        self.assertEqual(route.api_key, "cle-env")
        self.assertEqual(route.token_limit_param, "max_tokens")

    async def test_le_repli_environnement_coupe_le_raisonnement_deepseek(self) -> None:
        # Régression du 22/08 : le repli env EST le chemin historique
        # DeepSeek ; son API raisonne par défaut et un dossier long épuiserait
        # max_tokens en raisonnement, contenu vide à l'arrivée.
        route = await active_provider(_FakePool(None), _EnvSettings(), role="verdict")
        self.assertEqual(route.body_extras, {"thinking": {"type": "disabled"}})

    async def test_la_ligne_du_role_est_lue(self) -> None:
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "openai_api_key").write_text("cle-fichier\n")
            settings = _EnvSettings()
            settings.provider_secrets_dir = d
            row = {"provider": "openai_compatible",
                   "base_url": "https://api.openai.com/v1",
                   "model_name": "gpt-5",
                   "token_limit_param": "max_completion_tokens",
                   "secret_filename": "openai_api_key",
                   "body_extras": {}}
            route = await active_provider(_FakePool(row), settings, role="verdict")
            self.assertEqual(route.api_key, "cle-fichier")
            self.assertEqual(route.token_limit_param, "max_completion_tokens")
            self.assertEqual(route.body_extras, {})

    async def test_body_extras_lu_en_dict_depuis_la_ligne(self) -> None:
        row = {"provider": "openai_compatible", "base_url": "https://api.deepseek.com",
               "model_name": "deepseek-v4-pro", "token_limit_param": "max_tokens",
               "secret_filename": "deepseek_api_key",
               "body_extras": {"thinking": {"type": "disabled"}}}
        route = await active_provider(_FakePool(row), _EnvSettings(), role="verdict")
        self.assertEqual(route.body_extras, {"thinking": {"type": "disabled"}})

    async def test_body_extras_lu_en_str_jsonb_depuis_la_ligne(self) -> None:
        # asyncpg renvoie une chaîne pour jsonb sans codec dédié : les deux
        # formes doivent être acceptées.
        row = {"provider": "openai_compatible", "base_url": "https://api.deepseek.com",
               "model_name": "deepseek-v4-pro", "token_limit_param": "max_tokens",
               "secret_filename": "deepseek_api_key",
               "body_extras": '{"thinking": {"type": "disabled"}}'}
        route = await active_provider(_FakePool(row), _EnvSettings(), role="verdict")
        self.assertEqual(route.body_extras, {"thinking": {"type": "disabled"}})

    async def test_nom_de_fichier_hors_norme_refuse(self) -> None:
        row = {"provider": "openai_compatible", "base_url": "https://x",
               "model_name": "m", "token_limit_param": "max_tokens",
               "secret_filename": "../etc/passwd", "body_extras": {}}
        with self.assertRaises(LlmError):
            await active_provider(_FakePool(row), _EnvSettings(), role="verdict")


class _FakeResponse:
    status_code = 200
    def raise_for_status(self): pass
    def json(self):
        return {"id": "r1", "model": "m",
                "choices": [{"message": {"content": "{\"ok\":true}"},
                             "finish_reason": "stop"}],
                "usage": {}}


class OpenAiCompatibleTests(unittest.IsolatedAsyncioTestCase):
    async def test_le_parametre_de_limite_suit_la_route(self) -> None:
        from sentimail_v3.llm import openai_compatible_chat_json
        client = AsyncMock()
        client.post.return_value = _FakeResponse()
        route = ProviderRoute("openai_compatible", "https://api.openai.com/v1",
                              "gpt-5", "cle", "max_completion_tokens")
        await openai_compatible_chat_json(
            client, route=route,
            messages=[{"role": "user", "content": "x"}], max_tokens=900)
        body = client.post.call_args.kwargs["json"]
        self.assertEqual(body["max_completion_tokens"], 900)
        self.assertNotIn("max_tokens", body)
        self.assertNotIn("thinking", body)

    async def test_sans_cle_aucun_en_tete_authorization(self) -> None:
        from sentimail_v3.llm import openai_compatible_chat_json
        client = AsyncMock()
        client.post.return_value = _FakeResponse()
        route = ProviderRoute("openai_compatible", "http://ollama:11434/v1",
                              "qwen3", "", "max_tokens")
        await openai_compatible_chat_json(
            client, route=route,
            messages=[{"role": "user", "content": "x"}], max_tokens=900)
        headers = client.post.call_args.kwargs.get("headers") or {}
        self.assertNotIn("Authorization", headers)

    async def test_route_avec_body_extras_les_envoie(self) -> None:
        from sentimail_v3.llm import openai_compatible_chat_json
        client = AsyncMock()
        client.post.return_value = _FakeResponse()
        route = ProviderRoute("openai_compatible", "https://api.deepseek.com",
                              "deepseek-v4-pro", "cle", "max_tokens",
                              {"thinking": {"type": "disabled"}})
        await openai_compatible_chat_json(
            client, route=route,
            messages=[{"role": "user", "content": "x"}], max_tokens=900)
        body = client.post.call_args.kwargs["json"]
        self.assertEqual(body["thinking"], {"type": "disabled"})

    async def test_route_sans_body_extras_n_envoie_aucun_champ_thinking(self) -> None:
        from sentimail_v3.llm import openai_compatible_chat_json
        client = AsyncMock()
        client.post.return_value = _FakeResponse()
        route = ProviderRoute("openai_compatible", "https://api.deepseek.com",
                              "deepseek-v4-pro", "cle", "max_tokens", {})
        await openai_compatible_chat_json(
            client, route=route,
            messages=[{"role": "user", "content": "x"}], max_tokens=900)
        body = client.post.call_args.kwargs["json"]
        self.assertNotIn("thinking", body)
