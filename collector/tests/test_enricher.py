from __future__ import annotations

import unittest

from sentimail_v3.observation.enricher import _rdap_countries, _rdap_events


class EnricherTests(unittest.TestCase):
    def test_extracts_all_rdap_events(self) -> None:
        events = _rdap_events(
            {
                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": "2020-01-01T00:00:00Z",
                    },
                    {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
                ]
            }
        )
        self.assertEqual(events["registration"], ["2020-01-01T00:00:00Z"])
        self.assertEqual(events["expiration"], ["2030-01-01T00:00:00Z"])

    def test_extracts_rdap_country(self) -> None:
        self.assertEqual(_rdap_countries({"country": "fr"}), ["FR"])

    def test_country_extraction_ignores_uppercase_address_tokens(self) -> None:
        data = {
            "country": "FR",
            "vcardArray": [
                "vcard",
                [["adr", {"label": "CS 80001 PARIS RM 12", "cc": "FR"}, "text", []]],
            ],
        }
        self.assertEqual(_rdap_countries(data), ["FR"])


if __name__ == "__main__":
    unittest.main()
