"""Le juge lit ce que le destinataire lit, y compris sur un mail HTML seul.

Le 16 septembre 2026, le dossier de M-a9e895 portait un `body_text` vide et
`html_included: false` : le juge a vu l'objet, le From, les en-têtes et l'URL,
jamais « paiement accepté », le RIB, « 69,90 € » ni « annulation sous 14
jours ». Sa phrase « avis de renouvellement avec un lien de gestion » venait
de l'objet et du libellé du lien. 29,5 % du courrier de septembre est en HTML
seul.
"""

from __future__ import annotations

import unittest

from sentimail_v3.judgment.verdict_engine import _build_dossier

HTML = (
    "<html><head><style>p{margin:0}</style></head><body>"
    "<p>prime</p><p>CONFIRMÉ</p><p>Votre paiement a été accepté</p>"
    "<p>RIB FR7630006000011234567890189</p><p>Montant 69,90 €</p>"  # audit-ok: IBAN d'exemple publié, ne désigne aucun compte
    "<a href='https://exemple.test/'>Gérer mon abonnement</a>"
    "<p>Annulation possible sous 14 jours via le lien ci-dessus.</p>"
    "</body></html>"
)


class _Pool:
    """Une base réduite au message : tout le reste est vide."""

    def __init__(self, body_text: str | None, body_html: str | None) -> None:
        self.body_text = body_text
        self.body_html = body_html

    async def fetchrow(self, query: str, *args: object) -> dict[str, object]:
        return {
            "investigation_id": "inv",
            "investigation_status": "complete",
            "mode": "observation",
            "favorable_points": 0,
            "adverse_points": 0,
            "neutral_clues": 0,
            "completed_at": None,
            "investigation_summary": {},
            "code_name": "Code Sentinel",
            "code_version": "0.1.0",
            "message_id": "msg",
            "smtp_peer_ip": "192.0.2.1",
            "smtp_helo": "mx",
            "smtp_protocol": "ESMTP",
            "smtp_tls": {},
            "smtp_authenticated": False,
            "envelope_from": "bounces@exemple.test",
            "envelope_recipients": ["amartin@mondomaine.example"],
            "raw_size_bytes": 1,
            "headers_size_bytes": 1,
            "body_size_bytes": 1,
            "line_count": 1,
            "contains_8bit": False,
            "contains_nul": False,
            "line_ending": "CRLF",
            "internet_message_id": "<x@exemple.test>",
            "subject": "Achat confirmé",
            "from_header": "Annuel-Famille <noreply@exemple.test>",
            "to_header": "amartin@mondomaine.example",
            "cc_header": None,
            "reply_to_header": None,
            "return_path_header": None,
            "header_date_raw": None,
            "header_date": None,
            "header_date_parse_error": None,
            "mime_version": "1.0",
            "root_content_type": "text/html",
            "root_charset": "utf-8",
            "root_transfer_encoding": None,
            "body_text": self.body_text,
            "body_html": self.body_html,
            "parser_defects": [],
            "facts": {},
        }

    async def fetch(self, query: str, *args: object) -> list[object]:
        return []


class DossierTexteVisibleTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_mail_html_seul_donne_son_texte_au_juge(self) -> None:
        dossier = await _build_dossier(_Pool(None, HTML), "inv", {"complete": True})  # type: ignore[arg-type]
        texte = str(dossier["message"]["body_text"])
        self.assertIn("Votre paiement a été accepté", texte)
        self.assertIn("69,90", texte)
        self.assertIn("Annulation possible sous 14 jours", texte)
        self.assertNotIn("margin", texte)
        self.assertEqual(dossier["privacy"]["text_source"], "html_visible_text")

    async def test_le_html_brut_ne_part_pas_au_juge(self) -> None:
        dossier = await _build_dossier(_Pool(None, HTML), "inv", {"complete": True})  # type: ignore[arg-type]
        self.assertNotIn("body_html", dossier["message"])
        self.assertFalse(dossier["privacy"]["html_included"])

    async def test_le_texte_brut_garde_la_priorite(self) -> None:
        dossier = await _build_dossier(_Pool("Bonjour en clair", HTML), "inv", {"complete": True})  # type: ignore[arg-type]
        self.assertEqual(dossier["message"]["body_text"], "Bonjour en clair")
        self.assertEqual(dossier["privacy"]["text_source"], "text/plain")


class ContexteProfondTests(unittest.TestCase):
    def test_les_enqueteurs_lisent_le_meme_texte_que_le_juge(self) -> None:
        from sentimail_v3.observation.deep_analysis import _readable_body
        from sentimail_v3.observation.parser import parse_message

        raw = (
            "From: a@exemple.test\r\nTo: b@mondomaine.example\r\nSubject: S\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
            + HTML
        ).encode("utf-8")
        corps = _readable_body(parse_message(raw))
        self.assertIn("Gérer mon abonnement", corps)
        self.assertIn("Prime", corps.title())

    def test_l_analyse_profonde_passe_par_cette_lecture(self) -> None:
        import inspect

        from sentimail_v3.observation import deep_analysis

        source = inspect.getsource(deep_analysis.analyze_message)
        self.assertIn("_readable_body(", source)
        self.assertNotIn('body=str(parsed.message.get("body_text")', source)


if __name__ == "__main__":
    unittest.main()
