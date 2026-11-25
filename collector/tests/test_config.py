from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from sentimail_v3.config import load_settings


class SecretFileConfigurationTests(unittest.TestCase):
    def test_database_and_assistant_secrets_are_read_from_files(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database_password = root / "database-password"
            assistant_secret = root / "assistant-secret"
            database_password.write_text("db p@ss/word", encoding="utf-8")
            assistant_secret.write_text("a" * 32, encoding="utf-8")

            environment = {
                "DATABASE_PASSWORD_FILE": str(database_password),
                "ASSISTANT_TOKEN_SECRET_FILE": str(assistant_secret),
            }
            with patch.dict(os.environ, environment, clear=True):
                settings = load_settings()

        self.assertEqual(
            settings.database_url,
            "postgresql://sentimail_v3:db%20p%40ss%2Fword@db:5432/sentimail_v3",
        )
        self.assertEqual(settings.assistant_token_secret, "a" * 32)


class GroupedLettersTests(unittest.TestCase):
    def test_le_recapitulatif_groupe_est_coupe_par_defaut(self) -> None:
        # Décision du mainteneur du 15 octobre 2026 : plus aucun courrier qui
        # demande une position sur plusieurs messages à la fois. Trois messages
        # en attente font trois courriers, jamais un bulletin à trois cases.
        environment = {"DATABASE_URL": "postgresql://sentimail_v3@db:5432/sentimail_v3"}
        with patch.dict(os.environ, environment, clear=True):
            settings = load_settings()
        self.assertFalse(settings.digest_enabled)
