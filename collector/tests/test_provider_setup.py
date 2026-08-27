from __future__ import annotations

import asyncio
import io
import unittest
from email.message import EmailMessage

import pyzipper
from sentimail_v3.conversation.provider_setup import (
    _activate_role_providers,
    _encrypted_zip,
    _provider,
    _reply_token,
    _sender,
    decrypt_api_key,
)


class FakeConnection:
    """Faux `asyncpg.Connection` qui n'enregistre que les requêtes reçues."""

    def __init__(self) -> None:
        self.queries: list[tuple[str, tuple[object, ...]]] = []

    async def execute(self, query: str, *args: object) -> str:
        self.queries.append((query, args))
        return "INSERT 0 2"


def encrypted_archive(key: str, password: str = "mot-de-passe-fort") -> bytes:
    output = io.BytesIO()
    with pyzipper.AESZipFile(
        output,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as archive:
        archive.setpassword(password.encode())
        archive.writestr("cle-api.txt", key)
    return output.getvalue()


class ProviderSetupTests(unittest.TestCase):
    def test_provider_choice_is_explicit_and_unambiguous(self) -> None:
        self.assertEqual(_provider("Je choisis Claude"), "anthropic")
        self.assertEqual(_provider("CHATGPT"), "openai")
        self.assertIsNone(_provider("DeepSeek ou Claude"))
        self.assertIsNone(_provider("configure"))

    def test_sender_requires_envelope_and_from_alignment(self) -> None:
        message = EmailMessage()
        message["From"] = "Alex <operateur@mondomaine.example>"
        self.assertEqual(_sender(message, "operateur@mondomaine.example"), "operateur@mondomaine.example")
        self.assertEqual(_sender(message, "attacker@example.org"), "")

    def test_reply_token_only_comes_from_thread_headers(self) -> None:
        message = EmailMessage()
        token = "A" * 43
        message["References"] = f"<s3.{token}@sentinel.mondomaine.example>"
        message.set_content("ignore <s3.fakefakefakefakefakefake@sentinel.mondomaine.example>")
        self.assertEqual(_reply_token(message), token)

    def test_aes_zip_round_trip(self) -> None:
        archive = encrypted_archive("sk-test-12345678901234567890")
        self.assertEqual(
            decrypt_api_key(archive, "mot-de-passe-fort"),
            "sk-test-12345678901234567890",
        )

    def test_wrong_password_is_rejected_without_key_disclosure(self) -> None:
        archive = encrypted_archive("sk-test-12345678901234567890")
        with self.assertRaisesRegex(ValueError, "mot de passe ou ZIP invalide"):
            decrypt_api_key(archive, "incorrect")

    def test_unencrypted_zip_is_rejected(self) -> None:
        output = io.BytesIO()
        with pyzipper.AESZipFile(output, "w") as archive:
            archive.writestr("cle-api.txt", "x" * 32)
        with self.assertRaisesRegex(ValueError, "n'est pas chiffré"):
            decrypt_api_key(output.getvalue(), "unused")

    def test_only_one_zip_attachment_is_accepted(self) -> None:
        message = EmailMessage()
        message.set_content("Claude")
        message.add_attachment(
            encrypted_archive("sk-test-12345678901234567890"),
            maintype="application",
            subtype="zip",
            filename="maia.zip",
        )
        self.assertTrue(_encrypted_zip(message).startswith(b"PK"))

    def test_la_pose_par_email_configure_les_deux_roles(self) -> None:
        connection = FakeConnection()
        asyncio.run(
            _activate_role_providers(
                connection,
                "deepseek",
                "deepseek-chat",
                "deepseek_api_key",
                "user@example.org",
            )
        )
        self.assertEqual(len(connection.queries), 1)
        query, args = connection.queries[0]
        self.assertIn("INSERT INTO llm_role_providers", query)
        self.assertIn("VALUES ('verdict'),('conversation')", query)
        self.assertEqual(
            args,
            (
                "openai_compatible",
                "https://api.deepseek.com",
                "deepseek-chat",
                "max_tokens",
                "deepseek_api_key",
                '{"thinking":{"type":"disabled"}}',
                "user@example.org",
            ),
        )

    def test_seul_deepseek_coupe_le_raisonnement_a_la_pose_par_email(self) -> None:
        # Régression du 22/08 : DeepSeek raisonne par défaut, un dossier long
        # épuise max_tokens en raisonnement et le contenu revient vide.
        from sentimail_v3.conversation.provider_setup import _EMAIL_PRESETS

        self.assertEqual(
            _EMAIL_PRESETS["deepseek"][3], {"thinking": {"type": "disabled"}}
        )
        self.assertEqual(_EMAIL_PRESETS["openai"][3], {})
        self.assertEqual(_EMAIL_PRESETS["anthropic"][3], {})


if __name__ == "__main__":
    unittest.main()
