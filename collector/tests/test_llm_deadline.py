"""Un appel au fournisseur distant a une durée totale, pas seulement un délai
par lecture.

Le 14 septembre, un appel Flash a reçu ses en-têtes HTTP 200 en moins d'une
seconde puis un corps qui ne finissait jamais : des octets arrivaient au moins
toutes les 180 s, le délai de lecture ne sautait pas, et le juge est resté
suspendu 901 s. Le dépassement doit devenir une `LlmError` : c'est la seule
erreur que le repli Flash vers Pro rattrape.
"""

from __future__ import annotations

import asyncio
import os
import time
import unittest
from unittest.mock import patch

import httpx

from sentimail_v3 import llm
from sentimail_v3.config import load_settings
from sentimail_v3.llm import (
    INVESTIGATOR_ROLES,
    LlmError,
    ProviderRoute,
    openai_compatible_chat_json,
    provider_chat_json,
)


ROUTE = ProviderRoute(
    "openai_compatible", "https://api.deepseek.test", "deepseek-v4-flash",
    "secret-test-key", "max_tokens",
)


async def _reponse_qui_ne_finit_jamais(request: httpx.Request) -> httpx.Response:
    del request
    await asyncio.sleep(5)
    return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})


class _FakePool:
    async def fetchrow(self, sql: str, *args: object) -> None:
        return None


class _Settings:
    deepseek_api_key = "cle-env"
    deepseek_base_url = "https://api.deepseek.test"
    deepseek_verdict_model = "deepseek-v4-pro"
    deepseek_assistant_model = "deepseek-v4-pro"
    provider_secrets_dir = "/nonexistent"
    remote_llm_deadline_seconds = 0.05


class _SettingsLarges(_Settings):
    remote_llm_deadline_seconds = 5.0


class BudgetTotalTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_budget_explicite_l_emporte_sur_le_reglage(self) -> None:
        # Flash répond en 7 s au 95e centile : un Flash suspendu ne doit pas
        # coûter le budget de Pro avant le repli.
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_reponse_qui_ne_finit_jamais)
        ) as client:
            debut = time.perf_counter()
            with self.assertRaises(LlmError):
                await provider_chat_json(
                    _FakePool(),  # type: ignore[arg-type]
                    client,
                    _SettingsLarges(),  # type: ignore[arg-type]
                    messages=[{"role": "user", "content": "JSON"}],
                    max_tokens=20,
                    role="verdict",
                    allow_local=False,
                    deadline_seconds=0.05,
                )
        self.assertLess(time.perf_counter() - debut, 2.0)

    async def test_un_corps_qui_ne_finit_jamais_devient_une_llm_error(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_reponse_qui_ne_finit_jamais)
        ) as client:
            debut = time.perf_counter()
            with self.assertRaises(LlmError) as capture:
                await openai_compatible_chat_json(
                    client,
                    route=ROUTE,
                    messages=[{"role": "user", "content": "JSON"}],
                    max_tokens=20,
                    deadline_seconds=0.05,
                )
        self.assertLess(time.perf_counter() - debut, 2.0)
        self.assertIn("délai", str(capture.exception))

    async def test_le_budget_vient_des_reglages_pour_tout_appel_distant(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_reponse_qui_ne_finit_jamais)
        ) as client:
            debut = time.perf_counter()
            with self.assertRaises(LlmError):
                await provider_chat_json(
                    _FakePool(),  # type: ignore[arg-type]
                    client,
                    _Settings(),  # type: ignore[arg-type]
                    messages=[{"role": "user", "content": "JSON"}],
                    max_tokens=20,
                    role="verdict",
                    allow_local=False,
                )
        self.assertLess(time.perf_counter() - debut, 2.0)


class _SettingsEnqueteur(_SettingsLarges):
    investigator_llm_attempt_seconds = 0.05


class _Fournisseur:
    """Compte les appels ; les `fige` premiers restent sans réponse."""

    def __init__(self, fige: int = 0, statut: int = 200) -> None:
        self.appels = 0
        self.fige = fige
        self.statut = statut

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        del request
        self.appels += 1
        if self.appels <= self.fige:
            await asyncio.sleep(5)
        if self.statut != 200:
            return httpx.Response(self.statut, json={"error": "panne"})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"ok": true}'}}]})


class TentativeEnqueteurTests(unittest.IsolatedAsyncioTestCase):
    """Le 12 novembre 2026, un appel DeepSeek resté sans réponse a consommé les
    45 s de `sender_relation` : passage sans constat, superviseur dégradé une
    heure. L'appel suivant, 23 ms plus tard, répondait en 1,5 s."""

    async def _appel(self, fournisseur: _Fournisseur, role: str, **options: object):
        async with httpx.AsyncClient(transport=httpx.MockTransport(fournisseur)) as client:
            return await provider_chat_json(
                _FakePool(),  # type: ignore[arg-type]
                client,
                _SettingsEnqueteur(),  # type: ignore[arg-type]
                messages=[{"role": "user", "content": "JSON"}],
                max_tokens=20,
                role=role,
                allow_local=False,
                **options,  # type: ignore[arg-type]
            )

    async def test_un_appel_fige_est_abandonne_puis_refait_une_fois(self) -> None:
        for role in sorted(INVESTIGATOR_ROLES):
            with self.subTest(role=role):
                fournisseur = _Fournisseur(fige=1)
                debut = time.perf_counter()
                content, metadata = await self._appel(fournisseur, role)
                self.assertLess(time.perf_counter() - debut, 2.0)
                self.assertEqual(content, '{"ok": true}')
                self.assertEqual(fournisseur.appels, 2)
                self.assertEqual(metadata["attempt_count"], 2)
                self.assertTrue(metadata["retried_after_deadline"])

    async def test_une_reponse_dans_le_delai_ne_coute_qu_un_appel(self) -> None:
        fournisseur = _Fournisseur()
        _, metadata = await self._appel(fournisseur, "sender_relation")
        self.assertEqual(fournisseur.appels, 1)
        self.assertEqual(metadata["attempt_count"], 1)
        self.assertNotIn("retried_after_deadline", metadata)

    async def test_deux_appels_figes_rendent_l_erreur_sans_troisieme_essai(self) -> None:
        fournisseur = _Fournisseur(fige=5)
        debut = time.perf_counter()
        with self.assertRaises(LlmError) as capture:
            await self._appel(fournisseur, "sender_relation")
        self.assertTrue(capture.exception.deadline_exceeded)
        self.assertLess(time.perf_counter() - debut, 2.0)
        self.assertEqual(fournisseur.appels, 2)

    async def test_une_erreur_du_fournisseur_n_est_pas_retentee(self) -> None:
        fournisseur = _Fournisseur(statut=500)
        with self.assertRaises(LlmError) as capture:
            await self._appel(fournisseur, "sender_relation")
        self.assertFalse(capture.exception.deadline_exceeded)
        self.assertEqual(fournisseur.appels, 1)

    async def test_le_juge_et_la_conversation_gardent_leur_budget_sans_reprise(self) -> None:
        for role in ("verdict", "conversation"):
            with self.subTest(role=role):
                fournisseur = _Fournisseur(fige=1)
                debut = time.perf_counter()
                with self.assertRaises(LlmError):
                    await self._appel(fournisseur, role, deadline_seconds=0.05)
                self.assertLess(time.perf_counter() - debut, 2.0)
                self.assertEqual(fournisseur.appels, 1)

    async def test_un_delai_explicite_de_l_appelant_n_est_pas_retente(self) -> None:
        fournisseur = _Fournisseur(fige=1)
        with self.assertRaises(LlmError) as capture:
            await self._appel(fournisseur, "sender_relation", deadline_seconds=0.05)
        self.assertTrue(capture.exception.deadline_exceeded)
        self.assertEqual(fournisseur.appels, 1)

    async def test_le_depassement_garde_son_type_et_son_texte(self) -> None:
        # `error_type` des journaux et `verdict_retry.is_transient` lisent le
        # type et le texte : ils ne changent pas.
        fournisseur = _Fournisseur(fige=1)
        with self.assertRaises(LlmError) as capture:
            await self._appel(fournisseur, "verdict", deadline_seconds=0.05)
        self.assertIs(type(capture.exception), LlmError)
        self.assertIn("délai total de 0.05 s dépassé", str(capture.exception))

    async def test_deux_tentatives_tiennent_dans_le_delai_de_l_enqueteur(self) -> None:
        class _Reglage:
            investigator_llm_attempt_seconds = 30
            deep_hook_deadline_seconds = 45

        self.assertEqual(llm._investigator_attempt_seconds(_Reglage()), 15)  # type: ignore[arg-type]
        _Reglage.investigator_llm_attempt_seconds = 10
        self.assertEqual(llm._investigator_attempt_seconds(_Reglage()), 10)  # type: ignore[arg-type]

    async def test_le_modele_local_n_est_ni_borne_ni_rejoue(self) -> None:
        # Le modèle local charge ses poids à froid : il garde son délai. Après
        # son échec, seul le fournisseur distant est borné et refait une fois.
        locaux: list[object] = []

        async def route_locale(pool: object, role: str | None) -> tuple[str, bool]:
            return "modele-local", True

        async def local_en_panne(client: object, **options: object) -> tuple[str, dict[str, object]]:
            locaux.append(options["deadline_seconds"])
            raise LlmError("modèle local indisponible")

        class _SettingsLocal(_SettingsEnqueteur):
            local_llm_url = "http://ollama.test"

        fournisseur = _Fournisseur(fige=1)
        with patch.object(llm, "local_route", route_locale), patch.object(llm, "local_chat_json", local_en_panne):
            async with httpx.AsyncClient(transport=httpx.MockTransport(fournisseur)) as client:
                content, metadata = await provider_chat_json(
                    _FakePool(),  # type: ignore[arg-type]
                    client,
                    _SettingsLocal(),  # type: ignore[arg-type]
                    messages=[{"role": "user", "content": "JSON"}],
                    max_tokens=20,
                    role="sender_relation",
                )
        self.assertEqual(content, '{"ok": true}')
        self.assertEqual(locaux, [None])
        self.assertEqual(fournisseur.appels, 2)
        self.assertEqual(metadata["attempt_count"], 3)
        self.assertEqual(metadata["local_fallback_from"], "modele-local")


ENV_MINIMAL = {
    "DATABASE_URL": "postgresql://sentimail_v3:x@db:5432/sentimail_v3",
    "ASSISTANT_TOKEN_SECRET": "a" * 32,
}


class ReglageTests(unittest.TestCase):
    def test_le_budget_par_defaut_couvre_le_pire_cas_mesure(self) -> None:
        # Sur 30 jours : Pro p95 15 s, maximum 26 s ; Flash p95 7 s. Le budget
        # laisse une marge large et reste loin du seuil de retard de 10 min,
        # même avec Flash puis Pro en cascade.
        with patch.dict(os.environ, ENV_MINIMAL, clear=True):
            settings = load_settings()
        self.assertEqual(settings.remote_llm_deadline_seconds, 120)

    def test_le_budget_se_regle_par_l_environnement(self) -> None:
        with patch.dict(
            os.environ, {**ENV_MINIMAL, "REMOTE_LLM_DEADLINE_SECONDS": "45"}, clear=True
        ):
            settings = load_settings()
        self.assertEqual(settings.remote_llm_deadline_seconds, 45)

    def test_le_palier_flash_a_son_propre_budget(self) -> None:
        with patch.dict(os.environ, ENV_MINIMAL, clear=True):
            settings = load_settings()
        self.assertEqual(settings.economy_llm_deadline_seconds, 30)
        with patch.dict(
            os.environ, {**ENV_MINIMAL, "ECONOMY_LLM_DEADLINE_SECONDS": "12"}, clear=True
        ):
            settings = load_settings()
        self.assertEqual(settings.economy_llm_deadline_seconds, 12)

    def test_la_tentative_d_enqueteur_laisse_deux_essais_dans_le_delai_du_hook(self) -> None:
        with patch.dict(os.environ, ENV_MINIMAL, clear=True):
            settings = load_settings()
        self.assertEqual(settings.investigator_llm_attempt_seconds, 15)
        self.assertEqual(llm._investigator_attempt_seconds(settings), 15)
        self.assertLess(2 * settings.investigator_llm_attempt_seconds, settings.deep_hook_deadline_seconds)
        with patch.dict(
            os.environ, {**ENV_MINIMAL, "INVESTIGATOR_LLM_ATTEMPT_SECONDS": "20"}, clear=True
        ):
            settings = load_settings()
        self.assertEqual(settings.investigator_llm_attempt_seconds, 20)
