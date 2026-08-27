"""Une plateforme d'envoi mutualisée authentifie la plateforme, pas la marque.

Un message parti d'un compte SendGrid/Mailgun/SES jetable passe SPF/DKIM/DMARC
parfaitement : l'authentification est vraie, mais elle n'engage que
l'hébergeur d'envoi, jamais la marque affichée. Ce fait doit être NEUTRE - il
retire à l'authentification son crédit de légitimité de marque sans accuser
seul : la quasi-totalité de l'emailing honnête passe par ces mêmes plateformes.
"""

from __future__ import annotations

import unittest

from sentimail_v3.code.shared_esp import shared_esp_provider


class ReferentielTests(unittest.TestCase):
    def test_les_domaines_bounce_mutualises_sont_reconnus(self) -> None:
        for domaine, attendu in (
            ("bounces.sendgrid.net", "sendgrid"),
            ("u1807017.wl123.sendgrid.net", "sendgrid"),
            ("email.mailgun.org", "mailgun"),
            ("bounce.mail.brevo.com", "brevo"),
            ("amazonses.com", "amazonses"),
        ):
            with self.subTest(domaine=domaine):
                self.assertEqual(shared_esp_provider(domaine), attendu)

    def test_un_domaine_propre_n_est_pas_mutualise(self) -> None:
        for domaine in ("mondomaine.example", "primevideo.com", "mail.mabanque.fr", ""):
            with self.subTest(domaine=domaine):
                self.assertIsNone(shared_esp_provider(domaine))

    def test_un_domaine_bounce_dedie_de_client_n_est_pas_mutualise(self) -> None:
        # Un client sérieux configure son propre domaine de bounce : l'apex
        # n'est plus celui de la plateforme.
        self.assertIsNone(shared_esp_provider("bounce.newsletter.decathlon.fr"))


class HookTests(unittest.IsolatedAsyncioTestCase):
    async def _codes(self, raw: bytes, envelope: str):
        from sentimail_v3.observation.dossier.hooks.authentication import (
            AuthenticationHook,
        )
        from sentimail_v3.observation.dossier.models import InvestigationContext
        from sentimail_v3.observation.parser import parse_message

        context = InvestigationContext(
            raw, parse_message(raw), envelope, ["me@mondomaine.example"]
        )
        clues, facts = await AuthenticationHook().observe(context)
        return {c.clue_code: c for c in clues}, facts

    def _message(self, extra_headers: str = "") -> bytes:
        return (
            "From: Prim'Video Support <do-not-reply@evt.com>\r\n"
            "To: Me <me@mondomaine.example>\r\n"
            "Subject: Offre\r\n"
            "Message-ID: <a@evt.com>\r\n"
            "Authentication-Results: rspamd.sentimail; dkim=pass "
            "header.d=sendgrid.net; spf=pass; dmarc=pass\r\n"
            f"{extra_headers}"
            "\r\n"
            "corps\r\n"
        ).encode()

    async def test_l_infra_mutualisee_est_signalee_neutre(self) -> None:
        codes, _ = await self._codes(
            self._message(),
            "bounces+1807017-85f9-me=mondomaine.example@sendgrid.net",
        )
        self.assertIn("AUTH_SHARED_ESP_INFRASTRUCTURE", codes)
        self.assertEqual(codes["AUTH_SHARED_ESP_INFRASTRUCTURE"].direction, "neutral")

    async def test_un_envoi_sur_domaine_propre_ne_signale_rien(self) -> None:
        raw = (
            "From: Banque <service@mabanque.fr>\r\n"
            "To: Me <me@mondomaine.example>\r\n"
            "Subject: Relevé\r\n"
            "Message-ID: <a@mabanque.fr>\r\n"
            "Authentication-Results: rspamd.sentimail; dkim=pass "
            "header.d=mabanque.fr; spf=pass; dmarc=pass\r\n"
            "\r\ncorps\r\n"
        ).encode()
        codes, _ = await self._codes(raw, "bounce@mabanque.fr")
        self.assertNotIn("AUTH_SHARED_ESP_INFRASTRUCTURE", codes)

    async def test_les_marqueurs_d_en_tete_suffisent(self) -> None:
        # geopod-ismtpd dans un Received trahit SendGrid même sans return-path.
        codes, _ = await self._codes(
            self._message(
                "Received: from x (geopod-ismtpd-1.sendgrid.net) by mx\r\n"
            ),
            "me@mondomaine.example",
        )
        self.assertIn("AUTH_SHARED_ESP_INFRASTRUCTURE", codes)


if __name__ == "__main__":
    unittest.main()
