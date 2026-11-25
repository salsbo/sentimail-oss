"""Un domaine littéral inachevé ne fait pas disparaître le courrier."""

from __future__ import annotations

import unittest
from email import policy
from email.parser import BytesParser

from sentimail_v3.observation.entities import extract_entities
from sentimail_v3.observation.parser import parse_email, parse_message
from sentimail_v3.observation.visible_content import build_visible_content


def message(header: str = "From") -> bytes:
    return (
        f"{header}: sender@[\r\n"
        + ("From: sender@example.org\r\n" if header != "From" else "")
        + "To: recipient@example.net\r\n"
        "Subject: =?utf-8?q?Essai_synth=C3=A9tique?=\r\n"
        "X-Custom: inchangé\r\n"
        "X-Custom: seconde valeur\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n\r\nCorps synthétique."
    ).encode()


class EntetesMalformesTests(unittest.TestCase):
    def test_fixture_reproduit_le_defaut_python_sans_courrier_reel(self):
        original = BytesParser(policy=policy.default).parsebytes(message())
        try:
            original.get("From")
        except AttributeError as exc:
            self.assertIn("all_defects", str(exc))
        # Le test reste valable sur une version Python ayant corrigé sa stdlib.
        parsed = parse_message(message())
        self.assertEqual(parsed.message["body_text"], "Corps synthétique.")

    def test_repli_conserve_brut_defaut_et_autres_entetes(self):
        for name in ("From", "Sender", "Reply-To", "Resent-From", "Cc"):
            with self.subTest(header=name):
                raw = message(name)
                parsed = parse_message(raw)
                row = next(row for row in parsed.headers if row["name_normalized"] == name.casefold())
                self.assertEqual(row["value_raw"], "sender@[")
                self.assertEqual(row["value_decoded"], "sender@[")
                self.assertIn("InvalidHeaderDefect", parsed.message["parser_defects"])
                self.assertIn({"header": name.casefold(), "error_type": "AttributeError"},
                              parsed.facts["header_decode_errors"])
                self.assertEqual(parsed.message["subject"], "Essai synthétique")
                customs = [h["value_raw"] for h in parsed.headers if h["name_normalized"] == "x-custom"]
                self.assertEqual(customs, ["inchangé", "seconde valeur"])
                self.assertEqual(build_visible_content(parsed.message["body_text"], parsed.message["body_html"])["text"], "Corps synthétique.")
                # get()/get_all() doivent rester tolérants pour tous les lecteurs.
                safe = parse_email(raw)
                self.assertEqual(str(safe.get_all(name)[0]), "sender@[")
                self.assertIn("InvalidHeaderDefect", [type(d).__name__ for d in safe.defects])

    def test_extraction_entites_utilise_aussi_le_lecteur_tolerant(self):
        raw = message()
        parsed = parse_message(raw)
        entities = extract_entities(raw, parsed, "sender@example.org", ["recipient@example.net"])
        self.assertTrue(any(e["role"] == "envelope_from" for e in entities))
        self.assertFalse(any(e["entity_type"] == "address" and e["role"] == "from" for e in entities))
