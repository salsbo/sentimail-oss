# collector/tests/test_standalone.py
"""Gèle le fonctionnement de l'instance sans supervision externe.

Avec seulement le minimum requis dans l'environnement - la base, le secret
de jeton assistant, la clé DeepSeek - et sans aucune ligne dans
`llm_role_providers` ni `instance_identity`, l'instance doit rester
opérationnelle : `load_settings` réussit, `active_provider` retombe sur
l'environnement pour chaque rôle, `instance_identity` retombe sur
l'environnement. Aucun watchdog externe, aucune configuration en base n'est
requise pour démarrer.
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from sentimail_v3.config import load_settings
from sentimail_v3.identity import Identity, instance_identity, reset_cache
from sentimail_v3.llm import ProviderRoute, active_provider

_MINIMAL_ENV = {
    "DATABASE_URL": "postgresql://user:pass@db:5432/sentimail_v3",
    "ASSISTANT_TOKEN_SECRET": "a" * 32,
    "DEEPSEEK_API_KEY": "cle-deepseek",
    "PROBE_ENABLED": "false",
}


class _FakePoolNoRow:
    """Simule des tables `llm_role_providers`/`instance_identity` vides."""

    def __init__(self) -> None:
        self.calls = 0

    async def fetchrow(self, sql, *args):
        self.calls += 1
        return None


class StandaloneInstanceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        reset_cache()

    async def test_load_settings_reussit_avec_le_minimum_et_la_sonde_off(
        self,
    ) -> None:
        with patch.dict(os.environ, _MINIMAL_ENV, clear=True):
            settings = load_settings()
        self.assertFalse(settings.probe_enabled)
        self.assertEqual(settings.deepseek_api_key, "cle-deepseek")

    async def test_active_provider_verdict_replie_sur_l_environnement(
        self,
    ) -> None:
        with patch.dict(os.environ, _MINIMAL_ENV, clear=True):
            settings = load_settings()
        pool = _FakePoolNoRow()
        route = await active_provider(pool, settings, role="verdict")
        self.assertEqual(
            route,
            ProviderRoute(
                "openai_compatible",
                settings.deepseek_base_url,
                settings.deepseek_verdict_model,
                "cle-deepseek",
                "max_tokens",
                {"thinking": {"type": "disabled"}},
            ),
        )

    async def test_active_provider_conversation_replie_sur_l_environnement(
        self,
    ) -> None:
        with patch.dict(os.environ, _MINIMAL_ENV, clear=True):
            settings = load_settings()
        pool = _FakePoolNoRow()
        route = await active_provider(pool, settings, role="conversation")
        self.assertEqual(
            route,
            ProviderRoute(
                "openai_compatible",
                settings.deepseek_base_url,
                settings.deepseek_assistant_model,
                "cle-deepseek",
                "max_tokens",
                {"thinking": {"type": "disabled"}},
            ),
        )

    async def test_instance_identity_replie_sur_l_environnement(self) -> None:
        with patch.dict(os.environ, _MINIMAL_ENV, clear=True):
            settings = load_settings()
        pool = _FakePoolNoRow()
        identity = await instance_identity(pool, settings)
        self.assertEqual(
            identity,
            Identity(
                action_address=settings.action_address,
                action_aliases=tuple(settings.action_aliases),
                assistant_sender=settings.assistant_sender,
                probe_recipient=settings.probe_recipient,
            ),
        )


if __name__ == "__main__":
    unittest.main()
