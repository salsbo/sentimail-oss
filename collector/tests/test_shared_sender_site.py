"""Une absence de page partagée ne déclenche pas une seconde navigation."""

from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from sentimail_v3.observation import deep_analysis as deep
from test_parser import RAW


class SharedSenderSiteTests(unittest.IsolatedAsyncioTestCase):
    async def test_les_enqueteurs_partagent_aussi_les_refus_et_interstitiels(self):
        for registres in ({"financial"}, set()):
            for resultat in (
                ({}, 1.0, "NetworkError"),
                ({"body_excerpt": "Enable JavaScript and cookies to continue"}, 1.0, None),
                ({"body_excerpt": "Une activité publiée"}, 1.0, None),
            ):
                with self.subTest(registres=registres, resultat=resultat):
                    pool = SimpleNamespace(
                        fetchval=AsyncMock(return_value=RAW),
                        fetch=AsyncMock(return_value=[]),
                    )
                    reponses = {
                        "_analyze_urls": ([], True, {}),
                        "_analyze_attachments": ([], True),
                        "_history": {"sender_domain": "exemple.org"},
                        "_message_is_dmarc_aligned": False,
                        "_nature_facts": {}, "_content_context": {},
                        "_headers_facts": {}, "_domain_ages": {},
                        "_domain_organisations": {}, "run_deep_hooks": [],
                        "match_campaign": None, "_fetch_url_analysis": resultat,
                    }
                    with ExitStack() as stack:
                        mocks = {nom: stack.enter_context(patch.object(
                            deep, nom, AsyncMock(return_value=valeur)
                        )) for nom, valeur in reponses.items()}
                        stack.enter_context(patch.object(deep, "load_key", return_value=None))
                        stack.enter_context(patch.object(deep, "reveal", return_value=RAW))
                        stack.enter_context(patch.object(deep, "activity_registers", return_value=registres))
                        stack.enter_context(patch.object(deep, "_signals", return_value=[]))
                        rapport = await deep.analyze_message(
                            pool, None, SimpleNamespace(raw_eml_key_file=""), "message"
                        )
                    mocks["_fetch_url_analysis"].assert_awaited_once()
                    contexte = mocks["run_deep_hooks"].await_args.args[1]
                    attendu = None if resultat[2] or "cookies" in str(resultat[0]) else {
                        "apex": "exemple.org", "text": "Une activité publiée"
                    }
                    self.assertEqual(contexte.sender_site, attendu)
                    self.assertTrue(rapport["attachments_complete"])
