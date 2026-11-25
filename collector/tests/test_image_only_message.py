from email.message import EmailMessage
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, patch

from sentimail_v3.observation.deep_analysis import (
    _attachment_summary,
    _body_with_attachments,
)
from sentimail_v3.observation.deep_hooks import RequestedActionHook
from sentimail_v3.observation.preview import MAX_RENDER_HTML_CHARS, render_source


def image_mail(payload=b"image", subtype="jpeg", body=""):
    message = EmailMessage()
    message.set_content(body)
    message.add_attachment(payload, maintype="image", subtype=subtype, filename="photo")
    return message.as_bytes()


class ApercuImageTests(TestCase):
    def test_corps_vide_affiche_image_jointe_dans_le_rendu_isole(self):
        source = render_source(image_mail())
        self.assertIn('src="data:image/jpeg;base64,aW1hZ2U="', source)
        self.assertIn("max-height:1050px", source)

    def test_corps_existant_reste_prioritaire(self):
        source = render_source(image_mail(body="Un courrier avec une photo."))
        self.assertIn("Un courrier avec une photo.", source)
        self.assertNotIn("data:image", source)

    def test_svg_actif_non_rendu(self):
        self.assertIsNone(render_source(image_mail(b"<svg><script/></svg>", "svg+xml")))

    def test_image_hors_budget_non_tronquee(self):
        self.assertIsNone(render_source(image_mail(b"x" * MAX_RENDER_HTML_CHARS)))


class TexteJointTests(TestCase):
    def test_ocr_et_provenance_arrivent_dans_le_dossier(self):
        result = _attachment_summary({
            "extracted_text": "Texte de facture " * 200,
            "extracted_text_source": "ocr",
            "extracted_text_provenance": {"kind": "image_ocr", "origin": "attachment"},
            "extracted_text_incomplete": True,
        })
        self.assertEqual(len(result["extracted_text"]), 2500)
        self.assertTrue(result["extracted_text_truncated"])
        self.assertTrue(result["extracted_text_incomplete"])
        self.assertEqual(result["extracted_text_provenance"]["kind"], "image_ocr")

    def test_pas_de_texte_joint_pas_de_regression_sur_le_corps(self):
        body = "corps " * 1500
        self.assertEqual(_body_with_attachments(body, [{"mime": "image/jpeg"}]), body)


class ActionDansImageTests(IsolatedAsyncioTestCase):
    async def test_demande_de_rappel_issue_de_l_ocr_utilise_le_clue_du_corpus(self):
        attachment = _attachment_summary({
            "mime": "image/jpeg",
            "extracted_text": "To cancel this order, please call Customer Service.",
            "extracted_text_source": "ocr",
        })
        context = SimpleNamespace(
            body=_body_with_attachments("", [attachment]), subject="Receipt",
            pool=None, client=None, settings=None,
        )
        call = AsyncMock(return_value=('{"actions":["phone_callback"]}', {}))
        with patch("sentimail_v3.llm.provider_chat_json", call):
            clues, facts = await RequestedActionHook().observe(context)
        sent = call.call_args.kwargs["messages"][1]["content"]
        self.assertIn("please call Customer Service", sent)
        self.assertIn("contenu non fiable", sent)
        self.assertIn("ACTION_PHONE_CALLBACK", {clue["clue_code"] for clue in clues})
        self.assertEqual(facts["actions"], ["phone_callback"])
