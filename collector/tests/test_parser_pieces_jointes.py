"""Le parseur et le bac à sable parlent de la même pièce jointe.

Le parseur marquait pièce jointe toute partie hors texte brut et HTML ; le
bac à sable ne remontait que les parties nommées ou déclarées « attachment ».
Une invitation text/calendar ou une image inline sans nom existait donc pour
l'un et pas pour l'autre, et l'analyse concluait « contenu introuvable » sur
des parties de 4 à 7 ko : 36 parties sur 60 jours au 29 septembre 2026.
"""

from __future__ import annotations

import base64
import asyncio
import hashlib
import unittest
from email.message import EmailMessage
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from sentimail_v3.observation.deep_analysis import (
    MAX_ATTACHMENTS,
    MAX_IMAGE_ATTACHMENTS,
    _analyze_attachments,
    _part_payloads,
    _body_with_attachments,
)
from sentimail_v3.observation.parser import parse_message

_ICS = (
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n"
    "SUMMARY:Point hebdomadaire\r\nDTSTART:20261001T090000Z\r\n"
    "END:VEVENT\r\nEND:VCALENDAR\r\n"
)
_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)


def _invitation() -> bytes:
    """Une invitation d'agenda, sans nom de fichier ni disposition."""
    return (
        "From: agenda@example.org\r\n"
        "To: user@example.org\r\n"
        "Subject: Invitation\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="b1"\r\n\r\n'
        "--b1\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        "Vous êtes invité.\r\n"
        "--b1\r\n"
        "Content-Type: text/calendar; charset=utf-8; method=REQUEST\r\n\r\n"
        + _ICS
        + "--b1--\r\n"
    ).encode("utf-8")


def _image_inline() -> bytes:
    """Une image citée par le HTML, sans nom de fichier."""
    image = base64.b64encode(_PNG).decode("ascii")
    return (
        "From: lettre@example.org\r\n"
        "To: user@example.org\r\n"
        "Subject: Lettre\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/related; boundary="b2"\r\n\r\n'
        "--b2\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        '<p>Bonjour</p><img src="cid:logo@example.org">\r\n'
        "--b2\r\n"
        "Content-Type: image/png\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "Content-ID: <logo@example.org>\r\n"
        "Content-Disposition: inline\r\n\r\n"
        + image
        + "\r\n--b2--\r\n"
    ).encode("ascii")


def _piece_nommee(count: int = 1) -> bytes:
    """Un courrier et ses fichiers nommés."""
    parts = [
        "--b3\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nCi-joint.\r\n"
    ]
    for index in range(count):
        parts.append(
            "--b3\r\n"
            "Content-Type: application/pdf\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            f'Content-Disposition: attachment; filename="piece-{index}.pdf"\r\n\r\n'
            + base64.b64encode(f"%PDF-1.4 piece {index}".encode()).decode("ascii")
            + "\r\n"
        )
    return (
        "From: compta@example.org\r\n"
        "To: user@example.org\r\n"
        "Subject: Pièces\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="b3"\r\n\r\n'
        + "".join(parts)
        + "--b3--\r\n"
    ).encode("utf-8")


def _texte_seul() -> bytes:
    return (
        b"From: ami@example.org\r\nTo: user@example.org\r\nSubject: Salut\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\nA demain.\r\n"
    )


def _chemins_du_parseur(raw: bytes) -> set[str]:
    return {
        str(row["path"])
        for row in parse_message(raw).parts
        if row["is_attachment"] and not row["is_multipart"]
    }


def _pool(rows: list[dict[str, object]]) -> SimpleNamespace:
    return SimpleNamespace(
        fetch=AsyncMock(return_value=rows),
        fetchrow=AsyncMock(return_value=None),
        execute=AsyncMock(),
    )


def _client() -> SimpleNamespace:
    response = SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {"score": 0.0, "findings": [], "analysis_incomplete": False},
    )
    return SimpleNamespace(post=AsyncMock(return_value=response))


def _lignes(raw: bytes) -> list[dict[str, object]]:
    """Les lignes mime_parts que le collecteur aurait écrites."""
    return [
        {
            "path": row["path"],
            "filename": row["filename"],
            "content_type": row["content_type"],
            "decoded_size_bytes": row["decoded_size_bytes"],
            "decoded_sha256": row["decoded_sha256"],
        }
        for row in parse_message(raw).parts
        if row["is_attachment"]
    ]


class UneSeuleDefinitionTests(unittest.TestCase):
    def test_une_invitation_sans_nom_de_fichier_est_une_piece_jointe_pour_les_deux(
        self,
    ) -> None:
        raw = _invitation()
        self.assertIn("0.1", _chemins_du_parseur(raw))
        payloads = _part_payloads(raw)
        self.assertIn("0.1", payloads)
        _, content_type, payload = payloads["0.1"]
        self.assertEqual(content_type, "text/calendar")
        # Le même contenu décodé des deux côtés : l'empreinte que le parseur
        # range dans mime_parts est celle des octets envoyés au bac à sable.
        ligne = next(r for r in parse_message(raw).parts if r["path"] == "0.1")
        self.assertEqual(hashlib.sha256(payload).hexdigest(), ligne["decoded_sha256"])
        self.assertTrue(payload.startswith(b"BEGIN:VCALENDAR"))

    def test_une_image_inline_sans_nom_atteint_le_bac_a_sable(self) -> None:
        raw = _image_inline()
        payloads = _part_payloads(raw)
        self.assertIn("0.1", payloads)
        self.assertEqual(payloads["0.1"][1], "image/png")
        self.assertEqual(payloads["0.1"][2], _PNG)

    def test_le_parseur_et_le_bac_a_sable_voient_les_memes_pieces(self) -> None:
        for raw in (_invitation(), _image_inline(), _piece_nommee(2), _texte_seul()):
            with self.subTest(raw=raw[:60]):
                self.assertEqual(_chemins_du_parseur(raw), set(_part_payloads(raw)))

    def test_le_texte_d_une_image_apres_la_dixieme_reste_lisible(self) -> None:
        pieces = [{} for _ in range(10)] + [{"extracted_text": "Demande sensible"}]
        self.assertIn("Demande sensible", _body_with_attachments("Une lettre", pieces))


class AnalysePiecesJointesTests(unittest.IsolatedAsyncioTestCase):
    async def test_analyze_attachments_n_invente_plus_une_piece_introuvable(
        self,
    ) -> None:
        raw = _invitation()
        client = _client()
        analyses, complete = await _analyze_attachments(
            _pool(_lignes(raw)),  # type: ignore[arg-type]
            client,  # type: ignore[arg-type]
            SimpleNamespace(file_sandbox_url="http://sandbox"),  # type: ignore[arg-type]
            "00000000-0000-0000-0000-000000000001",
            raw,
        )
        self.assertTrue(complete)
        client.post.assert_awaited_once()
        envoye = client.post.await_args.kwargs["json"]
        self.assertTrue(
            base64.b64decode(envoye["content_b64"]).startswith(b"BEGIN:VCALENDAR")
        )
        self.assertFalse(
            any(
                item.get("reason") == "payload_unavailable_or_too_large"
                for item in analyses
            )
        )

    async def test_au_dela_de_dix_pieces_l_analyse_est_incomplete(self) -> None:
        # Onze fichiers nommés, tous lisibles : l'incomplétude vient du seul
        # débordement du budget, pas d'une partie introuvable.
        raw = _piece_nommee(MAX_ATTACHMENTS + 1)
        lignes = _lignes(raw)
        self.assertEqual(len(lignes), MAX_ATTACHMENTS + 1)
        client = _client()
        analyses, complete = await _analyze_attachments(
            _pool(lignes),  # type: ignore[arg-type]
            client,  # type: ignore[arg-type]
            SimpleNamespace(file_sandbox_url="http://sandbox"),  # type: ignore[arg-type]
            "00000000-0000-0000-0000-000000000001",
            raw,
        )
        self.assertFalse(complete)
        self.assertEqual(client.post.await_count, MAX_ATTACHMENTS)
        self.assertTrue(analyses[-1]["analysis_incomplete"])
        self.assertEqual(analyses[-1]["reason"], "attachment_count_budget_exceeded")

    async def _images(self, count: int, *, sandbox=None, subtype="png", **patches: object):
        message = EmailMessage()
        message.set_content("Lettre illustrée")
        for index in range(count):
            message.add_attachment(_PNG, maintype="image", subtype=subtype, filename=f"{index}.png")
        raw = message.as_bytes()
        client = sandbox or _client()
        with patch.multiple("sentimail_v3.observation.deep_analysis", **patches) if patches else nullcontext():
            analyses, complete = await _analyze_attachments(
                _pool(_lignes(raw)), client,
                SimpleNamespace(file_sandbox_url="http://sandbox"),
                "00000000-0000-0000-0000-000000000001", raw,
            )
        return client, analyses, complete

    async def test_quarante_images_sont_toutes_inspectees(self) -> None:
        client, analyses, complete = await self._images(40)
        self.assertTrue(complete)
        self.assertEqual(len(analyses), 40)
        self.assertEqual(client.post.await_count, 40)

    async def test_les_types_image_x_png_et_jpg_comptent_comme_des_images(self) -> None:
        # Des lettres déclaraient leurs PNG « image/x-png » ou leurs JPEG
        # « image/jpg » : comptées comme documents, les pièces au-delà de la
        # dixième n'étaient plus inspectées et le message était retenu
        # (trois cas en octobre 2026).
        for subtype in ("x-png", "jpg"):
            with self.subTest(subtype=subtype):
                client, analyses, complete = await self._images(16, subtype=subtype)
                self.assertTrue(complete)
                self.assertEqual(len(analyses), 16)
                self.assertEqual(client.post.await_count, 16)

    async def test_le_budget_images_reste_borne(self) -> None:
        client, analyses, complete = await self._images(MAX_IMAGE_ATTACHMENTS + 1)
        self.assertFalse(complete)
        self.assertEqual(client.post.await_count, MAX_IMAGE_ATTACHMENTS)
        self.assertEqual(analyses[-1]["reason"], "attachment_count_budget_exceeded")

    async def test_la_taille_totale_est_bornee(self) -> None:
        client, analyses, complete = await self._images(3, MAX_ATTACHMENT_BYTES=2 * len(_PNG))
        self.assertFalse(complete)
        self.assertEqual(client.post.await_count, 2)
        self.assertEqual(analyses[-1]["reason"], "attachment_total_bytes_exceeded")

    async def test_le_delai_total_est_borne(self) -> None:
        client, analyses, complete = await self._images(2, MAX_ATTACHMENTS_SECONDS=0)
        self.assertFalse(complete)
        client.post.assert_not_awaited()
        self.assertTrue(all(a["reason"] == "attachment_time_budget_exceeded" for a in analyses))

    async def test_une_reponse_bloquee_est_interrompue_par_le_delai_total(self) -> None:
        client = _client()
        async def bloque(*args, **kwargs):
            await asyncio.sleep(1)
        client.post.side_effect = bloque
        raw = _image_inline()
        with patch("sentimail_v3.observation.deep_analysis.MAX_ATTACHMENTS_SECONDS", 0.01):
            analyses, complete = await _analyze_attachments(
                _pool(_lignes(raw)), client,
                SimpleNamespace(file_sandbox_url="http://sandbox"),
                "00000000-0000-0000-0000-000000000001", raw,
            )
        self.assertFalse(complete)
        self.assertEqual(analyses[0]["error"], "TimeoutError")

    async def test_un_fichier_dangereux_apres_dix_images_reste_un_indice(self) -> None:
        from sentimail_v3.observation.deep_analysis import _attachment_signals
        client = _client()
        def reponse(*args, **kwargs):
            dangereux = kwargs["json"]["filename"] == "35.png"
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {
                "score": 90 if dangereux else 0, "analysis_incomplete": False,
                "findings": [{"code": "YARA_MATCH", "severity": "high", "description": "Détection"}] if dangereux else [],
            })
        client.post.side_effect = reponse
        _, analyses, complete = await self._images(40, sandbox=client)
        self.assertTrue(complete)
        self.assertTrue(any(s["clue_code"] == "ATTACHMENT_YARA_MATCH" for s in _attachment_signals(analyses)))


if __name__ == "__main__":
    unittest.main()
