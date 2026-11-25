"""HTTP et Chromium réels, sans réseau extérieur, dans l'image du rendu.

Exécuter avec le server.py courant monté sur /app/server.py et ce test sur
/tests/test_server.py. Aucun service de production ni contenu réel n'est lu.
"""

from __future__ import annotations

import base64
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest
from urllib.error import URLError
from urllib.request import Request, urlopen

from PIL import Image
from pyzbar.pyzbar import decode

_QR_MATRIX = """
0000000000000000000000000000000000000
0000000000000000000000000000000000000
0000000000000000000000000000000000000
0000000000000000000000000000000000000
0000111111100101011010110011111110000
0000100000101110101101111010000010000
0000101110100100011100101010111010000
0000101110100101111000000010111010000
0000101110101011101101110010111010000
0000100000100101010110110010000010000
0000111111101010101010101011111110000
0000000000000111011011111000000000000
0000101010100010001111011000100100000
0000111101000101101011001010010010000
0000101111111100110001100011101110000
0000001010001001100101110100100100000
0000011000100001000111001110010110000
0000011000010011110010001110010010000
0000100110101111001011001101110110000
0000111001011000111111101101010100000
0000110000111010001001000110010110000
0000000110011101001010001110011010000
0000101111100001010001001110100110000
0000011110010001100101001001110100000
0000100011111010000011011111100000000
0000000000001100010011011000101110000
0000111111100010001001011010110110000
0000100000100000011111001000110100000
0000101110101110101111001111100110000
0000101110100101111010000100101110000
0000101110101111110010100001110010000
0000100000100101000001111010000100000
0000111111101110101001011001100110000
0000000000000000000000000000000000000
0000000000000000000000000000000000000
0000000000000000000000000000000000000
0000000000000000000000000000000000000
""".strip().splitlines()


def qr_png() -> bytes:
    image = Image.new("RGB", (len(_QR_MATRIX[0]), len(_QR_MATRIX)), "white")
    for y, row in enumerate(_QR_MATRIX):
        for x, bit in enumerate(row):
            if bit == "1":
                image.putpixel((x, y), (0, 0, 0))
    image = image.resize((222, 222), Image.Resampling.NEAREST)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


class RenderHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        cls.url = f"http://127.0.0.1:{port}"
        cls.process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "server:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd="/app", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic()+20
        while time.monotonic() < deadline:
            try:
                with urlopen(Request(cls.url+"/health", headers={"User-Agent": "Mozilla/5.0 (compatible)"}), timeout=1) as response:
                    if json.load(response)["status"] == "ok":
                        return
            except (URLError, TimeoutError):
                time.sleep(0.05)
            if cls.process.poll() is not None:
                raise RuntimeError("le serveur de rendu local ne démarre pas")
        cls.process.kill()
        cls.process.wait()
        raise RuntimeError("le navigateur de rendu local ne devient pas disponible")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.process.terminate()
        try:
            cls.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.process.kill()
            cls.process.wait()

    def render(self, html: str, width: int = 900) -> Image.Image:
        body = json.dumps({"html": html, "width": width}).encode()
        request = Request(self.url+"/render", body, headers={
            "Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (compatible)"})
        with urlopen(request, timeout=10) as response:
            self.assertEqual(response.headers.get_content_type(), "image/png")
            image = Image.open(io.BytesIO(response.read())).convert("RGB")
        return image

    def test_html_court_garde_900_pixels_et_le_contenu_visible(self) -> None:
        image = self.render('<div style="width:200px;height:200px;background:#12ab34">Texte court</div>')
        self.assertEqual(image.size, (900, 900))
        self.assertEqual(image.getpixel((100, 100)), (18, 171, 52))

    def test_html_tres_long_ne_capture_que_1200_pixels_sans_perdre_le_bas_conserve(self) -> None:
        image = self.render('<div style="height:200000px;background:#12ab34">Texte long</div>')
        self.assertEqual(image.size, (900, 1200))
        self.assertEqual(image.getpixel((100, 1100)), (18, 171, 52))

    def test_qr_reel_est_masque_apres_la_capture_bornee(self) -> None:
        source = qr_png()
        self.assertEqual(decode(Image.open(io.BytesIO(source)))[0].data,
                         b"https://example.invalid/confirmation")
        image = self.render('<img src="data:image/png;base64,'+base64.b64encode(source).decode()+'">')
        self.assertEqual(image.size, (900, 900))
        self.assertEqual(decode(image), [])

    def test_largeur_contractuelle_et_miniature_restent_valides(self) -> None:
        image = self.render('<p>Largeur minimale</p>', width=480)
        self.assertEqual(image.size, (480, 900))
        output = io.BytesIO()
        image.save(output, format="PNG")
        request = Request(self.url+"/thumbnail?width=240", output.getvalue(), headers={
            "Content-Type": "image/png", "User-Agent": "Mozilla/5.0 (compatible)"})
        with urlopen(request, timeout=10) as response:
            thumbnail = Image.open(io.BytesIO(response.read()))
        self.assertEqual(thumbnail.size, (240, 450))


if __name__ == "__main__":
    unittest.main()
