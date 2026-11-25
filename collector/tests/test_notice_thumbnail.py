from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import httpx

from sentimail_v3.conversation.review_notice import PREVIEW_CID
from sentimail_v3.observation.preview import THUMBNAIL_WIDTH, thumbnail

ORIGINAL = b"\x89PNG\r\n\x1a\n" + b"O" * 4096
MINIATURE = b"\x89PNG\r\n\x1a\n" + b"m" * 256


def _client(reponse: httpx.Response, vues: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        vues.append(request)
        return reponse

    return httpx.MockTransport(handler)


class MiniatureTests(unittest.IsolatedAsyncioTestCase):
    """L'image du corps doit être légère ; la pièce jointe reste intègre.

    Une capture pèse 211 ko en moyenne et 1,2 Mo au pire. L'envoyer deux fois
    telle quelle doublerait le poids d'un avis lu sur un téléphone.
    """

    async def _appeler(self, reponse: httpx.Response) -> tuple[bytes | None, list]:
        vues: list[httpx.Request] = []
        transport = _client(reponse, vues)
        original_client = httpx.AsyncClient

        def fabrique(*args, **kwargs):
            kwargs["transport"] = transport
            return original_client(*args, **kwargs)

        with patch("sentimail_v3.observation.preview.httpx.AsyncClient", fabrique):
            return await thumbnail(ORIGINAL, "http://render-sandbox:8092"), vues

    async def test_la_miniature_vient_du_bac_a_sable_de_rendu(self) -> None:
        rendu, vues = await self._appeler(
            httpx.Response(200, content=MINIATURE, headers={"content-type": "image/png"})
        )
        self.assertEqual(rendu, (MINIATURE, "image/png"))
        self.assertEqual(len(vues), 1)
        self.assertTrue(str(vues[0].url).startswith("http://render-sandbox:8092/thumbnail"))
        self.assertEqual(vues[0].content, ORIGINAL)

    async def test_la_largeur_demandee_est_celle_de_l_avis(self) -> None:
        _, vues = await self._appeler(
            httpx.Response(200, content=MINIATURE, headers={"content-type": "image/png"})
        )
        self.assertEqual(vues[0].url.params["width"], str(THUMBNAIL_WIDTH))

    async def test_un_bac_a_sable_en_panne_ne_casse_pas_l_avis(self) -> None:
        rendu, _ = await self._appeler(httpx.Response(503))
        self.assertIsNone(rendu)

    async def test_le_jpeg_du_bac_a_sable_est_accepte_avec_son_type(self) -> None:
        # La miniature n'a qu'un rôle : être vue. Le bac à sable choisit le
        # format le plus léger, le collector transporte le type qu'il annonce.
        rendu, _ = await self._appeler(
            httpx.Response(200, content=MINIATURE, headers={"content-type": "image/jpeg"})
        )
        self.assertEqual(rendu, (MINIATURE, "image/jpeg"))

    async def test_une_reponse_qui_n_est_pas_une_image_est_refusee(self) -> None:
        rendu, _ = await self._appeler(
            httpx.Response(200, content=b"<html>", headers={"content-type": "text/html"})
        )
        self.assertIsNone(rendu)

    async def test_une_miniature_plus_lourde_que_l_original_est_ecartee(self) -> None:
        # Sur une capture déjà minuscule, réencoder peut grossir : dans ce cas
        # la miniature n'apporte rien et l'original suffit.
        gonflee = b"\x89PNG\r\n\x1a\n" + b"x" * 999_999
        rendu, _ = await self._appeler(
            httpx.Response(200, content=gonflee, headers={"content-type": "image/png"})
        )
        self.assertIsNone(rendu)


class _Pool:
    """La file d'envoi portant les deux exemplaires de la capture."""

    def __init__(self, avec_miniature: bool) -> None:
        self._avec_miniature = avec_miniature

    async def fetchrow(self, query, *args):
        if "instance_identity" in str(query):
            return None
        return {
            "id": 1,
            "action_id": "11111111-1111-1111-1111-111111111111",
            "conversation_id": "22222222-2222-2222-2222-222222222222",
            "recipient": "moi@mondomaine.example",
            "sender": "MAIA <maia@mondomaine.example>",
            "reply_to": "maia@sentinel.mondomaine.example",
            "subject": "[SentiMail] Ton avis",
            "body_text": "corps",
            "body_html": f'<p>avant</p><img src="cid:{PREVIEW_CID}"><p>après</p>',
            "attempts": 1,
            "attachment_content": ORIGINAL,
            "attachment_filename": "capture-email-neutralisee.png",
            "attachment_content_type": "image/png",
            "inline_content": MINIATURE if self._avec_miniature else None,
            "inline_filename": (
                "apercu-email.jpg" if self._avec_miniature else None
            ),
            "inline_content_type": "image/jpeg" if self._avec_miniature else None,
        }

    async def execute(self, query, *args):
        return "UPDATE 1"

    async def fetchval(self, query, *args):
        return None

    def acquire(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def transaction(self):
        return self


async def _envoyer(avec_miniature: bool):
    from sentimail_v3.conversation.assistant import _send_outbox

    envois: list[object] = []

    async def _capture(message, **kwargs):
        envois.append(message)
        return {}

    from sentimail_v3.identity import reset_cache

    reset_cache()
    settings = SimpleNamespace(
        assistant_token_secret="secret",
        action_address="maia@sentinel.mondomaine.example",
        action_aliases=(),
        assistant_sender="MAIA <maia@mondomaine.example>",
        probe_recipient="sonde@mondomaine.example",
        relay_host="relay",
        relay_port=25,
    )
    with patch("sentimail_v3.conversation.assistant.aiosmtplib.send", new=_capture):
        await _send_outbox(_Pool(avec_miniature), settings)  # type: ignore[arg-type]
    assert envois, "aucun message envoyé"
    return envois[0]


class EnvoiDeLaCaptureTests(unittest.IsolatedAsyncioTestCase):
    """La miniature dans le corps, pour reconnaître ; l'original joint, pour lire.

    L'original avait cessé de partir en pièce jointe : le poids de l'avis
    doublait pour un fichier que personne n'ouvrait. Le 6 septembre 2026, il
    est redemandé - la miniature ne se lit pas, et une image rattachée au corps
    ne s'ouvre pas en grand dans tous les clients. Il repart donc, sous un nom
    qui dit à quoi il sert.
    """

    async def test_la_miniature_est_l_image_du_corps(self) -> None:
        message = await _envoyer(True)
        corps = [
            part
            for part in message.walk()
            if part.get("Content-ID") == f"<{PREVIEW_CID}>"
        ]
        self.assertEqual(len(corps), 1)
        self.assertEqual(corps[0].get_payload(decode=True), MINIATURE)

    async def test_l_original_part_en_piece_jointe_pour_etre_lu_en_grand(self) -> None:
        message = await _envoyer(True)
        jointes = [
            part
            for part in message.walk()
            if part.get_content_disposition() == "attachment"
        ]
        self.assertEqual(len(jointes), 1)
        self.assertEqual(jointes[0].get_filename(), "message-en-grand.png")
        self.assertEqual(jointes[0].get_payload(decode=True), ORIGINAL)

    async def test_sans_miniature_l_original_tient_les_deux_roles(self) -> None:
        # Le bac à sable peut échouer : l'avis part quand même, avec l'original
        # affiché, plutôt qu'avec une image cassée.
        message = await _envoyer(False)
        corps = [
            part
            for part in message.walk()
            if part.get("Content-ID") == f"<{PREVIEW_CID}>"
        ]
        self.assertEqual(len(corps), 1)
        self.assertEqual(corps[0].get_payload(decode=True), ORIGINAL)

    async def test_la_miniature_ne_voyage_qu_une_fois(self) -> None:
        message = await _envoyer(True)
        images = [
            p for p in message.walk()
            if p.get_content_type() in {"image/png", "image/jpeg"}
        ]
        self.assertEqual(len(images), 2)
        self.assertEqual(
            [p.get_payload(decode=True) for p in images].count(MINIATURE), 1
        )

    async def test_sans_miniature_l_original_ne_part_pas_deux_fois(self) -> None:
        message = await _envoyer(False)
        images = [
            p for p in message.walk()
            if p.get_content_type() in {"image/png", "image/jpeg"}
        ]
        self.assertEqual(len(images), 1)

    async def test_la_miniature_garde_le_type_annonce(self) -> None:
        message = await _envoyer(True)
        corps = [
            p for p in message.walk() if p.get("Content-ID") == f"<{PREVIEW_CID}>"
        ]
        self.assertEqual(corps[0].get_content_type(), "image/jpeg")


if __name__ == "__main__":
    unittest.main()
