from __future__ import annotations

import unittest

from sentimail_v3.observation.dossier.hook import EvidenceHook
from sentimail_v3.observation.dossier.models import InvestigationContext
from sentimail_v3.observation.dossier.pipeline import run_hooks
from sentimail_v3.observation.parser import parse_message


def _context(raw: bytes) -> InvestigationContext:
    return InvestigationContext(
        raw, parse_message(raw), "sender@example.org", ["me@mondomaine.example"]
    )


class BrokenHook(EvidenceHook):
    name = "broken"
    version = "test"

    async def observe(self, context: InvestigationContext):  # type: ignore[no-untyped-def]
        del context
        raise RuntimeError("failure is evidence, not a pipeline failure")


class DossierTests(unittest.IsolatedAsyncioTestCase):
    async def test_collects_charge_and_defence_without_verdict(self) -> None:
        raw = b"""Authentication-Results: rspamd.sentimail; dmarc=pass; dkim=pass; spf=pass\r
From: Alice <alice@example.org>\r
Reply-To: Help <help@example.net>\r
To: Me <me@mondomaine.example>\r
Date: Tue, 11 Aug 2026 10:00:00 +0000\r
Message-ID: <one@example.org>\r
\r
body\r
"""
        results = await run_hooks(_context(raw))
        clues = [clue for result in results for clue in result.clues]
        codes = {clue.clue_code for clue in clues}
        self.assertIn("AUTH_DMARC_PASS", codes)
        self.assertIn("HEADERS_REPLY_TO_DIFFERENT_DOMAIN", codes)
        self.assertTrue(any(clue.direction == "favorable" for clue in clues))
        self.assertTrue(any(clue.direction == "adverse" for clue in clues))

    async def test_hook_failure_is_fail_soft(self) -> None:
        raw = b"From: sender@example.org\r\n\r\nbody"
        results = await run_hooks(_context(raw), [BrokenHook()])
        self.assertEqual(results[0].status, "error")
        self.assertEqual(results[0].error_type, "RuntimeError")

    async def test_forged_authentication_header_cannot_override_relay_result(self) -> None:
        raw = b"""Authentication-Results: rspamd.sentimail; dmarc=pass; dkim=pass\r
Authentication-Results: rspamd.sentimail; dmarc=fail; dkim=fail\r
From: Alice <alice@example.org>\r
To: Me <me@mondomaine.example>\r
\r
body\r
"""
        results = await run_hooks(_context(raw))
        codes = {clue.clue_code for result in results for clue in result.clues}
        self.assertIn("AUTH_DMARC_PASS", codes)
        self.assertNotIn("AUTH_DMARC_FAIL", codes)

    async def test_correlates_urgency_action_and_sensitive_request(self) -> None:
        raw = b"""From: Security <security@example.org>\r
To: Me <me@mondomaine.example>\r
Subject: ACTION URGENTE POUR VOTRE COMPTE\r
Content-Type: text/plain; charset=utf-8\r
\r
Votre compte sera suspendu. Cliquez immediatement pour verifier votre mot de passe.\r
"""
        results = await run_hooks(_context(raw))
        clues = [clue for result in results for clue in result.clues]
        codes = {clue.clue_code for clue in clues}
        self.assertIn("CONTENT_URGENCY", codes)
        self.assertIn("CONTENT_SENSITIVE_REQUEST", codes)
        self.assertIn("CONTENT_SOCIAL_ENGINEERING_COMBINATION", codes)

    async def test_one_time_link_expiration_is_context_not_coercion(self) -> None:
        raw = b"""Authentication-Results: rspamd.sentimail; dmarc=pass; dkim=pass; spf=pass\r
From: Security <security@example.org>\r
To: Me <me@mondomaine.example>\r
Subject: Your secure link expires in 10 minutes\r
Content-Type: text/plain; charset=utf-8\r
\r
Use this one-time sign-in link. It expires in 10 minutes.\r
"""
        results = await run_hooks(_context(raw))
        codes = {clue.clue_code for result in results for clue in result.clues}
        self.assertIn("CONTENT_EXPECTED_ONE_TIME_EXPIRATION", codes)
        self.assertIn("CONTENT_ONE_TIME_CREDENTIAL_PROVIDED_NOT_REQUESTED", codes)
        self.assertNotIn("CONTENT_URGENCY", codes)
        self.assertNotIn("CONTENT_SENSITIVE_REQUEST", codes)
        self.assertNotIn("CONTENT_SOCIAL_ENGINEERING_COMBINATION", codes)

    async def test_verification_de_compte_prime_sur_un_pied_de_page_commercial(
        self,
    ) -> None:
        raw = """From: Seafy <no-reply@seafy.com>\r
To: Me <me@mondomaine.example>\r
Subject: Vérifie ton compte Seafy\r
Content-Type: text/html; charset=utf-8\r
\r
<html><body><h1>Vérifie ton compte</h1><p>Utilise ce lien sécurisé.</p>
<footer>Paiement, facture et politique de remboursement</footer></body></html>\r
""".encode()
        results = await run_hooks(_context(raw))
        content = next(result for result in results if result.hook_name == "content")
        self.assertEqual(
            content.facts["content_context"]["purpose"], "one_time_authentication"
        )
        self.assertNotEqual(content.facts["content_context"]["purpose"], "payment")

    async def test_objet_francais_verifie_ton_compte_est_reconnu(self) -> None:
        raw = """From: Seafy <no-reply@seafy.com>\r
To: Me <me@mondomaine.example>\r
Subject: Vérifie ton compte Seafy\r
Content-Type: text/html; charset=utf-8\r
\r
<html><body><p>Finalise ton inscription.</p>
<footer>Paiement, facture et politique de remboursement</footer></body></html>\r
""".encode()
        results = await run_hooks(_context(raw))
        content = next(result for result in results if result.hook_name == "content")
        self.assertEqual(
            content.facts["content_context"]["purpose"], "account_security"
        )

    async def test_entering_otp_is_distinct_from_disclosing_it(self) -> None:
        expected = b"""From: Security <security@example.org>\r
To: Me <me@mondomaine.example>\r
Subject: Verification code\r
Content-Type: text/plain; charset=utf-8\r
\r
Enter this one-time verification code to sign in.\r
"""
        expected_results = await run_hooks(_context(expected))
        expected_codes = {
            clue.clue_code for result in expected_results for clue in result.clues
        }
        self.assertIn("CONTENT_EXPECTED_ONE_TIME_CODE_INPUT", expected_codes)
        self.assertNotIn("CONTENT_SENSITIVE_REQUEST", expected_codes)

        disclosure = b"""From: Support <support@example.org>\r
To: Me <me@mondomaine.example>\r
Subject: Verification code\r
Content-Type: text/plain; charset=utf-8\r
\r
Send us your one-time verification code by reply.\r
"""
        disclosure_results = await run_hooks(_context(disclosure))
        disclosure_codes = {
            clue.clue_code for result in disclosure_results for clue in result.clues
        }
        self.assertIn("CONTENT_SENSITIVE_REQUEST", disclosure_codes)

    async def test_coercive_wire_transfer_keeps_full_context(self) -> None:
        raw = b"""From: Direction <direction@example.org>\r
To: Me <me@mondomaine.example>\r
Subject: URGENT virement\r
Content-Type: text/plain; charset=utf-8\r
\r
Envoyez immediatement un virement vers cet IBAN, sinon une penalite sera appliquee.\r
"""
        results = await run_hooks(_context(raw))
        clues = [clue for result in results for clue in result.clues]
        by_code = {clue.clue_code: clue for clue in clues}
        self.assertIn("CONTENT_URGENCY", by_code)
        self.assertIn("CONTENT_SENSITIVE_REQUEST", by_code)
        self.assertIn("CONTENT_SOCIAL_ENGINEERING_COMBINATION", by_code)
        self.assertEqual(
            by_code["CONTENT_URGENCY"].facts["purpose"], "financial_transfer"
        )
        self.assertEqual(
            by_code["CONTENT_SENSITIVE_REQUEST"].facts["categories"],
            ["bank_account"],
        )

    async def test_detects_deceptive_link_and_static_url_risk(self) -> None:
        raw = b"""From: Alice <alice@example.org>\r
To: Me <me@mondomaine.example>\r
Content-Type: text/html; charset=utf-8\r
\r
<a href=\"https://login.example.zip:8443/check\">https://example.org</a>\r
"""
        results = await run_hooks(_context(raw))
        clues = [clue for result in results for clue in result.clues]
        codes = {clue.clue_code for clue in clues}
        self.assertIn("URL_STATIC_RISK", codes)
        self.assertIn("URL_DECEPTIVE_LINK_TEXT", codes)
        display_difference = next(
            clue for clue in clues if clue.clue_code == "URL_DECEPTIVE_LINK_TEXT"
        )
        self.assertEqual(display_difference.direction, "neutral")
        self.assertEqual(display_difference.strength, 0)

    async def test_detects_dangerous_double_extension(self) -> None:
        raw = b"""From: Alice <alice@example.org>\r
To: Me <me@mondomaine.example>\r
MIME-Version: 1.0\r
Content-Type: application/octet-stream; name=\"facture.pdf.exe\"\r
Content-Disposition: attachment; filename=\"facture.pdf.exe\"\r
Content-Transfer-Encoding: base64\r
\r
TVqQAAMAAAAEAAAA\r
"""
        results = await run_hooks(_context(raw))
        codes = {
            clue.clue_code for result in results for clue in result.clues
        }
        self.assertIn("ATTACHMENT_DOUBLE_EXTENSION", codes)

    async def test_rspamd_phishing_heuristic_is_not_material_or_double_counted(self) -> None:
        raw = b"""X-Spamd-Result: default: False [12.00 / 6.00]; PHISHING(8.00)\r
From: Alice <alice@example.org>\r
To: Me <me@mondomaine.example>\r
\r
body\r
"""
        results = await run_hooks(_context(raw))
        clues = [clue for result in results for clue in result.clues]
        codes = {clue.clue_code for clue in clues}
        self.assertNotIn("RSPAMD_MATERIAL_SYMBOL", codes)
        self.assertIn("RSPAMD_PHISHING_HEURISTIC", codes)
        self.assertIn("RSPAMD_HIGH_SCORE", codes)
        self.assertTrue(
            all(
                clue.direction == "neutral"
                for clue in clues
                if clue.clue_code in {"RSPAMD_PHISHING_HEURISTIC", "RSPAMD_HIGH_SCORE"}
            )
        )

    async def test_rspamd_virus_remains_material(self) -> None:
        raw = b"""X-Spamd-Result: default: True [12.00 / 6.00]; CLAM_VIRUS(10.00)\r
From: Alice <alice@example.org>\r
To: Me <me@mondomaine.example>\r
\r
body\r
"""
        results = await run_hooks(_context(raw))
        clues = [clue for result in results for clue in result.clues]
        material = next(
            clue for clue in clues if clue.clue_code == "RSPAMD_MATERIAL_SYMBOL"
        )
        self.assertEqual(material.direction, "adverse")
        self.assertEqual(material.strength, 100)

    async def test_rspamd_records_weak_absence_of_reputation_hits(self) -> None:
        raw = b"""X-Spamd-Result: default: False [4.95 / 100.00]; VIOLATED_DIRECT_SPF(3.50)[]; MIME_HTML_ONLY(0.20)[]\r
From: News <news@example.org>\r
To: Me <me@mondomaine.example>\r
\r
body\r
"""
        results = await run_hooks(_context(raw))
        clues = [clue for result in results for clue in result.clues]
        reputation = next(
            clue for clue in clues if clue.clue_code == "RSPAMD_NO_REPUTATION_HIT"
        )
        self.assertEqual(reputation.direction, "favorable")
        self.assertEqual(reputation.strength, 5)

    async def test_transactional_forged_sender_is_not_material_fraud(self) -> None:
        raw = b"""Authentication-Results: rspamd.sentimail; dmarc=pass; dkim=pass; spf=pass\r
X-Spamd-Result: default: False [1.60 / 100.00]; FORGED_SENDER(0.30)[]; MIME_HTML_ONLY(0.20)[]\r
From: Service <noreply@notifications.example.org>\r
Return-Path: <bounce@notifications.example.org>\r
To: Me <me@mondomaine.example>\r
Content-Type: text/html; charset=utf-8\r
\r
<style>.mobile { display:none }</style><p>Votre colis arrive.</p>\r
"""
        results = await run_hooks(_context(raw))
        clues = [clue for result in results for clue in result.clues]
        codes = {clue.clue_code for clue in clues}
        self.assertNotIn("RSPAMD_MATERIAL_SYMBOL", codes)
        self.assertIn("RSPAMD_LOW_SCORE", codes)
        self.assertIn("RSPAMD_TRANSACTIONAL_ENVELOPE_VARIATION", codes)
        self.assertNotIn("CONTENT_OBFUSCATION", codes)
        self.assertIn("CONTENT_NO_SENSITIVE_PRESSURE", codes)

    async def test_tracking_tokens_inside_plain_text_urls_are_not_obfuscation(self) -> None:
        token = b"A" * 64
        raw = (
            b"From: Service <service@example.org>\r\n"
            b"To: Me <me@mondomaine.example>\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Consultez https://example.org/newsletter?id=" + token + b"\r\n"
        )
        results = await run_hooks(_context(raw))
        codes = {clue.clue_code for result in results for clue in result.clues}
        self.assertNotIn("CONTENT_OBFUSCATION", codes)

    async def test_detects_address_hidden_in_deceptive_display_name(self) -> None:
        raw = b"""From: \"billing@trusted-bank.com\" <attacker@evil.com>\r
To: Me <me@mondomaine.example>\r
Return-Path: <attacker@evil.com>\r
Message-ID: <one@evil.com>\r
\r
body\r
"""
        results = await run_hooks(_context(raw))
        codes = {
            clue.clue_code for result in results for clue in result.clues
        }
        self.assertIn("IDENTITY_DISPLAY_NAME_EMAIL_MISMATCH", codes)

    async def test_detects_mixed_script_sender_identity(self) -> None:
        raw = (
            "From: Pаypal <billing@example.org>\r\n"
            "To: Me <me@mondomaine.example>\r\n\r\nbody\r\n"
        ).encode()
        results = await run_hooks(_context(raw))
        clues = [clue for result in results for clue in result.clues]
        homograph = next(
            clue for clue in clues if clue.clue_code == "IDENTITY_UNICODE_HOMOGRAPH"
        )
        self.assertEqual(homograph.direction, "adverse")
        self.assertIn("U+0430", str(homograph.facts))

    async def test_ascii_lookalike_is_context_not_charge(self) -> None:
        raw = b"""From: Micr0soft <billing@micr0soft.example>\r
To: Me <me@mondomaine.example>\r
\r
body\r
"""
        results = await run_hooks(_context(raw))
        clues = [clue for result in results for clue in result.clues]
        lookalike = next(
            clue for clue in clues if clue.clue_code == "IDENTITY_ASCII_LOOKALIKE"
        )
        self.assertEqual(lookalike.direction, "neutral")
        self.assertEqual(lookalike.strength, 0)

    async def test_lowercase_l_read_as_capital_i_at_camelcase_join(self) -> None:
        # « Primelnfos » : un l minuscule (U+006C) là où « PrimeInfos » porte un
        # I majuscule. C'est le sens l->I, l'inverse du I->l déjà couvert.
        raw = (
            "From: Primelnfos <admin@aclscertification.org>\r\n"
            "To: Me <me@mondomaine.example>\r\n\r\nbody\r\n"
        ).encode()
        results = await run_hooks(_context(raw))
        clues = [clue for result in results for clue in result.clues]
        lookalike = next(
            clue for clue in clues if clue.clue_code == "IDENTITY_ASCII_LOOKALIKE"
        )
        # Le fait reste neutre - à charge de l'arbitre de le contextualiser -,
        # mais il doit au moins être vu, sur le nom d'affichage, à l'offset du l.
        self.assertEqual(lookalike.direction, "neutral")
        markers = lookalike.facts.get("markers", [])
        self.assertTrue(
            any(
                m.get("field") == "display_name" and m.get("looks_like") == "I"
                for m in markers
            ),
            markers,
        )

    async def test_ordinary_titlecase_names_do_not_flag_their_l(self) -> None:
        # Le l minuscule est partout dans les vrais noms ; le signal n'a de sens
        # qu'à une jointure camelCase. Ces noms courants ne doivent rien émettre.
        for name in ("Charlie Martin", "Village Voice", "William Bell", "Berlin"):
            raw = (
                f"From: {name} <hello@example.org>\r\n"
                "To: Me <me@mondomaine.example>\r\n\r\nbody\r\n"
            ).encode()
            results = await run_hooks(_context(raw))
            codes = {clue.clue_code for result in results for clue in result.clues}
            self.assertNotIn("IDENTITY_ASCII_LOOKALIKE", codes, name)

    async def test_single_script_international_domain_is_not_a_charge(self) -> None:
        raw = b"""From: Service <billing@xn--e1afmkfd.xn--p1ai>\r
To: Me <me@mondomaine.example>\r
\r
body\r
"""
        results = await run_hooks(_context(raw))
        clues = [clue for result in results for clue in result.clues]
        codes = {clue.clue_code for clue in clues}
        self.assertIn("IDENTITY_IDN_CONTEXT", codes)
        self.assertNotIn("IDENTITY_UNICODE_HOMOGRAPH", codes)

    async def test_active_html_is_material_content_evidence(self) -> None:
        raw = b"""From: Alice <alice@example.org>\r
To: Me <me@mondomaine.example>\r
Content-Type: text/html; charset=utf-8\r
\r
<form action=\"https://evil.example\"><input name=\"password\"></form>\r
"""
        results = await run_hooks(_context(raw))
        codes = {
            clue.clue_code for result in results for clue in result.clues
        }
        self.assertIn("CONTENT_ACTIVE_HTML", codes)


if __name__ == "__main__":
    unittest.main()
