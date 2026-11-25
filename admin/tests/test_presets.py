from __future__ import annotations

import unittest

from sentimail_admin.presets import PRESETS, Preset, secret_filename_for


class PresetsTests(unittest.TestCase):
    """Les préréglages du moteur : un fournisseur nommé n'existe plus, l'URL le dit.

    Deux adaptateurs seulement (``openai_compatible``, ``anthropic``), comme en
    base. ``custom`` est le seul préréglage sans fichier de clé fixe : il se
    déduit du rôle, parce qu'un fournisseur maison peut différer entre le
    verdict et la conversation.
    """

    def test_les_six_presets_existent(self) -> None:
        self.assertEqual(
            sorted(PRESETS),
            ["anthropic", "custom", "deepseek", "mistral", "ollama", "openai"],
        )

    def test_chaque_preset_donne_une_url_http(self) -> None:
        for nom, preset in PRESETS.items():
            if nom != "custom":
                self.assertRegex(preset.base_url, r"^https?://")

    def test_seul_anthropic_utilise_l_adaptateur_anthropic(self) -> None:
        for nom, preset in PRESETS.items():
            if nom == "anthropic":
                self.assertEqual(preset.provider, "anthropic")
            else:
                self.assertEqual(preset.provider, "openai_compatible")

    def test_valeurs_verbatim_deepseek(self) -> None:
        self.assertEqual(
            PRESETS["deepseek"],
            Preset(
                "openai_compatible",
                "https://api.deepseek.com",
                "deepseek-v4-pro",
                "max_tokens",
                "deepseek_api_key",
                {"thinking": {"type": "disabled"}},
            ),
        )

    def test_seul_deepseek_coupe_le_raisonnement(self) -> None:
        # DeepSeek v4 raisonne par défaut : sur un dossier long, le
        # raisonnement épuise max_tokens et le contenu revient vide.
        for nom, preset in PRESETS.items():
            with self.subTest(nom=nom):
                if nom == "deepseek":
                    self.assertEqual(
                        preset.body_extras, {"thinking": {"type": "disabled"}}
                    )
                else:
                    self.assertEqual(preset.body_extras, {})

    def test_valeurs_verbatim_openai(self) -> None:
        self.assertEqual(
            PRESETS["openai"],
            Preset(
                "openai_compatible",
                "https://api.openai.com/v1",
                "gpt-5",
                "max_completion_tokens",
                "openai_api_key",
            ),
        )

    def test_valeurs_verbatim_mistral(self) -> None:
        self.assertEqual(
            PRESETS["mistral"],
            Preset(
                "openai_compatible",
                "https://api.mistral.ai/v1",
                "mistral-large-latest",
                "max_tokens",
                "mistral_api_key",
            ),
        )

    def test_valeurs_verbatim_ollama(self) -> None:
        self.assertEqual(
            PRESETS["ollama"],
            Preset(
                "openai_compatible",
                "http://host.docker.internal:11434/v1",
                "qwen3:8b",
                "max_tokens",
                "ollama_api_key",
            ),
        )

    def test_valeurs_verbatim_anthropic(self) -> None:
        self.assertEqual(
            PRESETS["anthropic"],
            Preset(
                "anthropic",
                "https://api.anthropic.com",
                "claude-sonnet-5-5",
                "max_tokens",
                "anthropic_api_key",
            ),
        )

    def test_custom_n_a_ni_url_ni_fichier_fixe(self) -> None:
        preset = PRESETS["custom"]
        self.assertEqual(preset.provider, "openai_compatible")
        self.assertEqual(preset.base_url, "")
        self.assertEqual(preset.model, "")
        self.assertEqual(preset.token_limit_param, "max_tokens")
        self.assertIsNone(preset.secret_filename)


class SecretFilenameForTests(unittest.TestCase):
    def test_le_fichier_secret_custom_depend_du_role(self) -> None:
        self.assertEqual(secret_filename_for("custom", "verdict"), "custom_verdict_api_key")
        self.assertEqual(
            secret_filename_for("custom", "conversation"), "custom_conversation_api_key"
        )
        self.assertEqual(secret_filename_for("deepseek", "verdict"), "deepseek_api_key")

    def test_les_autres_presets_ignorent_le_role(self) -> None:
        for nom in ("deepseek", "openai", "mistral", "ollama", "anthropic"):
            with self.subTest(nom=nom):
                self.assertEqual(
                    secret_filename_for(nom, "verdict"),
                    secret_filename_for(nom, "conversation"),
                )


if __name__ == "__main__":
    unittest.main()
