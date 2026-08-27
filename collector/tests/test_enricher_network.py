from __future__ import annotations

import os
import unittest

import httpx
from sentimail_v3.observation.enricher import _enrich_domain, _enrich_ip


@unittest.skipUnless(os.environ.get("RUN_NETWORK_TESTS"), "test reseau desactive")
class EnricherNetworkTests(unittest.IsolatedAsyncioTestCase):
    async def test_rdap_dns_domain_and_ip(self) -> None:
        async with httpx.AsyncClient(follow_redirects=True, timeout=12) as client:
            domain = await _enrich_domain(client, "mondomaine.example")
            ip = await _enrich_ip(client, "1.1.1.1")
        self.assertEqual(domain["registered_domain"], "mondomaine.example")
        self.assertIn("dns", domain)
        self.assertIn("rdap", domain)
        self.assertIn("creation_date", domain)
        self.assertIn("rdap", ip)
        self.assertIn("asn", ip)


if __name__ == "__main__":
    unittest.main()
