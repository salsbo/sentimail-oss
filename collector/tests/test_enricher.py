from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from sentimail_v3.observation import enricher
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


class EnricherDnsResolverTests(unittest.IsolatedAsyncioTestCase):
    async def test_reuses_single_timed_resolver_including_for_ptr(self) -> None:
        fake_resolver = SimpleNamespace(
            timeout=0.0,
            lifetime=0.0,
            resolve=AsyncMock(return_value=[SimpleNamespace(to_text=lambda: "mail.example.org.")]),
        )
        with patch.object(enricher, "_DNS_RESOLVER", None), \
             patch.object(enricher.dns.asyncresolver, "Resolver", return_value=fake_resolver) as factory, \
             patch.object(enricher.dns.asyncresolver, "resolve", side_effect=AssertionError("default resolver interdit")), \
             patch.object(enricher, "_rdap", new=AsyncMock(return_value={"countries": ["FR"]})), \
             patch.object(enricher, "_cymru_ip", new=AsyncMock(return_value={"asn": "15169"})):
            first = enricher._dns_resolver()
            second = enricher._dns_resolver()
            result = await enricher._enrich_ip(object(), "8.8.8.8")  # type: ignore[arg-type]

        factory.assert_called_once()
        self.assertIs(first, second)
        self.assertEqual(first.timeout, 3.0)
        self.assertEqual(first.lifetime, 5.0)
        self.assertEqual(result["reverse_dns"], ["mail.example.org."])
        fake_resolver.resolve.assert_awaited_once_with("8.8.8.8.in-addr.arpa", "PTR")


if __name__ == "__main__":
    unittest.main()
