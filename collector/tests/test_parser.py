from __future__ import annotations

import unittest

from sentimail_v3.observation.entities import extract_entities
from sentimail_v3.observation.parser import parse_message
from sentimail_v3.observation.storage import _raw_facts, ingest_key

RAW = b"""Received: from sender.example (sender.example [203.0.113.9])\r
 by mx.example with ESMTPS id abc for <user@example.org>; Tue, 11 Aug 2026 10:00:00 +0000\r
From: Alice <alice@sender.example>\r
To: User <user@example.org>\r
Date: Tue, 11 Aug 2026 10:00:00 +0000\r
Message-ID: <sample@sender.example>\r
Subject: Test =?utf-8?q?SMTP?=\r
X-Custom: first\r
X-Custom: second\r
MIME-Version: 1.0\r
Content-Type: multipart/mixed; boundary=demo\r
\r
--demo\r
Content-Type: text/plain; charset=utf-8\r
\r
Visit https://example.net/path?q=1 from 198.51.100.7.\r
--demo\r
Content-Type: application/octet-stream; name=file.bin\r
Content-Disposition: attachment; filename=file.bin\r
Content-Transfer-Encoding: base64\r
\r
AAEC\r
--demo--\r
"""


class ParserTests(unittest.TestCase):
    def test_reverse_dns_name_is_not_parsed_as_an_ip(self) -> None:
        raw = (
            b"From: sender@example.org\r\n"
            b"To: recipient@example.net\r\n"
            b"Received: from 93.184.216.92.rev.sfr.net\r\n\r\nbody"
        )
        parsed = parse_message(raw)
        entities = extract_entities(
            raw, parsed, "sender@example.org", ["recipient@example.net"]
        )
        ips = [
            item["value_normalized"] for item in entities if item["entity_type"] == "ip"
        ]
        self.assertNotIn("93.184.216.92", ips)

    def test_preserves_order_duplicates_and_mime(self) -> None:
        parsed = parse_message(RAW)
        custom = [
            header
            for header in parsed.headers
            if header["name_normalized"] == "x-custom"
        ]
        self.assertEqual(
            [header["value_raw"] for header in custom], ["first", "second"]
        )
        self.assertEqual(parsed.facts["duplicate_headers"], {"x-custom": 2})
        self.assertEqual(len(parsed.parts), 3)
        self.assertEqual(parsed.facts["attachment_count"], 1)
        self.assertIn("Visit https://example.net", parsed.message["body_text"])

    def test_extracts_addresses_domains_ips_urls_and_hashes(self) -> None:
        parsed = parse_message(RAW)
        entities = extract_entities(
            RAW, parsed, "bounce@sender.example", ["user@example.org"]
        )
        kinds = {entity["entity_type"] for entity in entities}
        self.assertTrue(
            {"address", "domain", "ip", "url", "message_id", "hash"} <= kinds
        )
        self.assertTrue(
            any(entity["value_normalized"] == "example.net" for entity in entities)
        )

    def test_raw_facts_and_idempotency(self) -> None:
        facts = _raw_facts(RAW)
        self.assertEqual(facts["line_ending"], "crlf")
        self.assertGreater(facts["headers_size_bytes"], 0)
        first = ingest_key(RAW, "a@example.org", ["b@example.org"])
        second = ingest_key(RAW, "a@example.org", ["b@example.org"])
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()


class ScrubTests(unittest.TestCase):
    def test_un_entete_mal_decode_redevient_lisible(self) -> None:
        from sentimail_v3.observation.parser import scrub

        # Les octets C3 A9 (« é » en UTF-8) decodes en surrogateescape : c'est
        # exactement ce qui a fait tourner en boucle le message metro.rs.
        casse = "R\udcc3\udca9clamez votre bon"
        self.assertEqual(scrub(casse), "Réclamez votre bon")
        scrub(casse).encode("utf-8")  # stockable, sinon ça lève

    def test_un_octet_reellement_invalide_devient_un_remplacement(self) -> None:
        from sentimail_v3.observation.parser import scrub

        self.assertEqual(scrub("ok\udcff"), "ok�")

    def test_une_chaine_saine_ressort_intacte(self) -> None:
        from sentimail_v3.observation.parser import scrub

        self.assertEqual(scrub("Déjà vu — ok"), "Déjà vu — ok")

    def test_un_message_aux_entetes_cassees_se_capture(self) -> None:
        from sentimail_v3.observation.parser import parse_message

        raw = (
            b"From: Metro <promo@emails.metro.rs>\r\n"
            b"Subject: Dernier avis : R\xc3\xa9clamez votre bon\r\n"
            b"X-Broken: \xc3\xa9\xff brut\r\n"
            b"Content-Type: text/plain\r\n\r\nCorps.\r\n"
        )
        parsed = parse_message(raw)
        str(parsed.message["subject"]).encode("utf-8")
        self.assertIn("Réclamez", str(parsed.message["subject"]))
        for row in parsed.headers:
            str(row["value_decoded"]).encode("utf-8")
            str(row["value_raw"]).encode("utf-8")
