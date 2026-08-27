"""Une pièce jointe « image » ou « document » qui est en fait une appli web.

Le SVG et le HTML joints sont les vecteurs en plus forte croissance : un .svg
annoncé comme image contient une page de phishing (script, formulaire), un
.html reconstruit le payload côté navigateur (blob base64 + atob). Le fichier
n'a pas de lien scannable dans le mail : c'est son contenu qui trahit.
"""

from __future__ import annotations

import base64
import unittest

from sentimail_v3.observation.dossier.hooks.attachments import AttachmentHook
from sentimail_v3.observation.dossier.models import InvestigationContext
from sentimail_v3.observation.parser import parse_message


def _with_attachment(filename: str, ctype: str, body: bytes) -> bytes:
    b64 = base64.b64encode(body).decode()
    return (
        "From: a@b.c\r\nTo: me@mondomaine.example\r\nSubject: x\r\n"
        'Content-Type: multipart/mixed; boundary="X"\r\n\r\n'
        "--X\r\nContent-Type: text/plain\r\n\r\nBonjour\r\n"
        f"--X\r\nContent-Type: {ctype}; name=\"{filename}\"\r\n"
        f'Content-Disposition: attachment; filename="{filename}"\r\n'
        f"Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--X--\r\n"
    ).encode()


async def _codes(filename: str, ctype: str, body: bytes):
    raw = _with_attachment(filename, ctype, body)
    ctx = InvestigationContext(raw, parse_message(raw), "a@b.c", ["me@mondomaine.example"])
    clues, _ = await AttachmentHook().observe(ctx)
    return {c.clue_code: c for c in clues}


class SvgTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_svg_avec_script_est_signale(self) -> None:
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>location="http://evil.top"</script></svg>'
        codes = await _codes("image.svg", "image/svg+xml", svg)
        self.assertIn("ATTACHMENT_ACTIVE_MARKUP", codes)
        self.assertEqual(codes["ATTACHMENT_ACTIVE_MARKUP"].direction, "adverse")

    async def test_un_svg_avec_formulaire_est_signale(self) -> None:
        svg = (
            b'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject>'
            b'<form><input type="password"></form></foreignObject></svg>'
        )
        codes = await _codes("logo.svg", "image/svg+xml", svg)
        self.assertIn("ATTACHMENT_ACTIVE_MARKUP", codes)

    async def test_un_vrai_svg_graphique_ne_declenche_rien(self) -> None:
        svg = (
            b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" '
            b'height="10"/><text>Logo</text><path d="M0 0"/></svg>'
        )
        codes = await _codes("logo.svg", "image/svg+xml", svg)
        self.assertNotIn("ATTACHMENT_ACTIVE_MARKUP", codes)


class HtmlTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_html_joint_avec_smuggling_est_signale(self) -> None:
        html = (
            b"<html><body><script>var d=atob('SGVsbG8gd29ybGQ...');"
            b"var b=new Blob([d]);var u=URL.createObjectURL(b);</script>"
            b"</body></html>"
        )
        codes = await _codes("facture.html", "text/html", html)
        self.assertIn("ATTACHMENT_ACTIVE_MARKUP", codes)

    async def test_un_html_joint_avec_formulaire_mot_de_passe(self) -> None:
        html = b'<html><body><form><input type="password" name="p"></form></body></html>'
        codes = await _codes("login.html", "text/html", html)
        self.assertIn("ATTACHMENT_ACTIVE_MARKUP", codes)

    async def test_un_html_statique_ne_declenche_rien(self) -> None:
        html = b"<html><body><h1>Votre re\xc3\xa7u</h1><p>Merci</p></body></html>"
        codes = await _codes("recu.html", "text/html", html)
        self.assertNotIn("ATTACHMENT_ACTIVE_MARKUP", codes)


if __name__ == "__main__":
    unittest.main()
