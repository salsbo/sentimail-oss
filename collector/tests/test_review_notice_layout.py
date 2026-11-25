from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from sentimail_v3.code.plain_words import confidence_badge
from sentimail_v3.conversation.review_notice import (
    ACTION_TOKEN_PLACEHOLDER,
    PREVIEW_CID,
    choice_links,
    render_notice_html,
)

CONTEXTE = {
    "subject": "Votre facture est disponible sur sfr.fr",
    "sender": "SFR <facture@sfr.fr>",
    "status_text": "Ce message n’a pas été livré : il attend ta réponse.",
    "concerns": ["Usurpation possible : le domaine affiché ne reconnaît pas cet envoi."],
    "badge": confidence_badge("dangerous", 1),
    "advice": "Ne réponds pas à cette adresse.",
    "message_excerpts": [
        "Nous redescendons de notre nuage et vous remercions pour votre présence."
    ],
    "action_address": "maia@sentinel.mondomaine.example",
}


class FicheSeuleTests(unittest.TestCase):
    """Le verdict, ses motifs et les choix occupent seuls le corps."""

    CARTE = {
        "claimed": "NeuroLift Research",
        "from_domain": "artsencollectief.nl",
        "from_apex": "artsencollectief.nl",
        "official": ["neurolift.health"],
    }

    def test_l_entete_et_la_carte_restent_ignores(self) -> None:
        html = render_notice_html(
            {
                **CONTEXTE,
                "identity_card": self.CARTE,
                "sender_gap": {"displayed": "visible@example.test"},
            }
        )
        for absent in (
            CONTEXTE["status_text"],
            "NeuroLift Research",
            "visible@example.test",
            PREVIEW_CID,
            "pièce jointe",
        ):
            self.assertNotIn(absent, html)

    def test_adresses_puis_photo_entre_l_indice_et_les_ecarts(self) -> None:
        html = render_notice_html(
            {
                **CONTEXTE,
                "sender_lines": [
                    "Nom affiché : SFR",
                    "Adresse affichée : facture@sfr.fr",
                    "Adresse d’enveloppe différente : bounce@mailer.example.ru",
                ],
                "has_preview": True,
                "has_full_preview": True,
            }
        )
        self.assertIn("facture@sfr.fr", html)
        self.assertIn("bounce@mailer.example.ru", html)
        self.assertIn(f'src="cid:{PREVIEW_CID}"', html)
        self.assertIn("pièce jointe", html)
        self.assertLess(html.index("DANGEREUX"), html.index("facture@sfr.fr"))
        self.assertLess(html.index("facture@sfr.fr"), html.index("Pourquoi j&#x27;hésite"))
        self.assertLess(html.index("Pourquoi j&#x27;hésite"), html.index(PREVIEW_CID))
        # L'écart d'enveloppe se voit sans lire le reste : en rouge.
        self.assertIn("Enveloppe", html)
        self.assertIn("#b91c1c", html)

    def test_les_ecarts_restent_visibles_meme_si_une_ancienne_carte_est_fournie(
        self,
    ) -> None:
        html = render_notice_html(
            {
                **CONTEXTE,
                "concerns": ["Pression pour agir vite."],
                "identity_card": self.CARTE,
            }
        )
        self.assertIn("Pourquoi j&#x27;hésite", html)
        self.assertIn("Pression pour agir vite.", html)

    def test_la_liste_garde_son_repli(self) -> None:
        html = render_notice_html(
            {**CONTEXTE, "concerns": [], "identity_card": self.CARTE}
        )
        self.assertIn("Pourquoi j&#x27;hésite", html)
        self.assertIn("Rien de précis à te signaler", html)

    def test_la_composition_photographie_le_message(self) -> None:
        import inspect

        from sentimail_v3.conversation import conversation

        source = inspect.getsource(conversation.ConversationStore)
        self.assertIn("screenshot(", source)
        self.assertIn("thumbnail(", source)
        self.assertNotIn("carte=", source)


class LayoutTests(unittest.TestCase):
    def test_l_avis_ne_montre_que_ce_qui_gene(self) -> None:
        """Ce qui rassure ne décide de rien : la question porte sur les écarts."""
        html = render_notice_html(CONTEXTE)
        self.assertIn("Pourquoi j&#x27;hésite", html)
        self.assertNotIn("Ce qui me rassure", html)
        self.assertNotIn("Ce qui me gêne", html)

    def test_l_avis_tient_en_une_colonne(self) -> None:
        """Deux colonnes se broyaient sur iPhone ; une seule se lit d'un trait."""
        html = render_notice_html(CONTEXTE)
        self.assertNotIn("<table", html)
        self.assertNotIn("display:inline-block;width:100%;max-width:320px", html)

    def test_l_indice_de_confiance_remplace_la_motivation(self) -> None:
        html = render_notice_html(CONTEXTE)
        self.assertIn("DANGEREUX", html)
        self.assertIn("1 écart relevé", html)
        self.assertNotIn("Pourquoi je te demande", html)
        self.assertNotIn("Ce que je n’ai pas pu vérifier", html)

    def test_l_indice_precede_les_ecarts(self) -> None:
        html = render_notice_html(CONTEXTE)
        self.assertLess(html.index("DANGEREUX"), html.index("Pourquoi j&#x27;hésite"))

    def test_sans_photo_les_extraits_tiennent_lieu_d_apercu(self) -> None:
        html = render_notice_html(CONTEXTE)
        self.assertIn("Aperçu inerte", html)
        self.assertIn("redescendons de notre nuage", html)
        self.assertLess(html.index("Pourquoi j&#x27;hésite"), html.index("Aperçu inerte"))
        self.assertLess(html.index("Aperçu inerte"), html.index('data-choice="A"'))

    def test_avec_photo_la_photo_remplace_les_extraits(self) -> None:
        html = render_notice_html({**CONTEXTE, "has_preview": True})
        self.assertIn(f'src="cid:{PREVIEW_CID}"', html)
        self.assertNotIn("redescendons de notre nuage", html)

    def test_un_lien_d_extrait_n_est_pas_actif(self) -> None:
        html = render_notice_html(
            {**CONTEXTE, "message_excerpts": ["Ouvre https://danger.example/payer"]}
        )
        self.assertNotIn("https://danger.example", html)
        self.assertNotIn('href="https://danger.example', html)

    def test_l_icone_de_l_indice_est_une_image_du_corps(self) -> None:
        """En V2, l'état est une pastille typographique colorée sans image externe."""
        html = render_notice_html(CONTEXTE)
        self.assertIn("DANGEREUX · MESSAGE RETENU", html)
        self.assertIn("#991b1b", html)
        self.assertIn("#fee2e2", html)

    def test_l_icone_de_l_indice_ne_redit_pas_le_mot(self) -> None:
        """Images coupées, l'alt doublait le mot : « DOUTEUXDOUTEUX »."""
        self.assertEqual(render_notice_html(CONTEXTE).count("DANGEREUX"), 1)

    def test_les_trois_choix_sont_des_boutons(self) -> None:
        html = render_notice_html(CONTEXTE)
        for lettre in ("A", "B", "C"):
            self.assertIn(f'data-choice="{lettre}"', html)

    def test_aucun_jargon_ne_subsiste(self) -> None:
        """Un avis qui parle en codes internes n'est pas lisible."""
        html = render_notice_html(CONTEXTE).casefold()
        for jargon in ("deep_execution", "ask_user", "undetermined", "dmarc", "apex"):
            self.assertNotIn(jargon, html)


PNG = b"\x89PNG\r\n\x1a\n" + b"P" * 64
JPEG = b"\xff\xd8\xff" + b"j" * 16


class CompositionAvecCaptureTests(unittest.IsolatedAsyncioTestCase):
    class _Pool:
        def __init__(self) -> None:
            self.queries: list[str] = []
            self.executions: list[tuple[str, tuple[object, ...]]] = []

        def acquire(self):
            return self

        def transaction(self):
            return self

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def fetchrow(self, query, *args):
            self.queries.append(str(query))
            if "FROM delivery_cases dc" in str(query):
                return {
                    "case_id": "11111111-1111-1111-1111-111111111111",
                    "subject": "Sujet original à ne pas recopier",
                    "body_text": None,
                    "from_header": "Alerte <alerte@exemple.test>",
                    "envelope_from": "retour@envoi.example",
                    "reply_to_header": None,
                    "body_html": (
                        "<p>Nous redescendons de notre nuage et vous "
                        "remercions pour votre présence.</p>"
                    ),
                    "envelope_recipients": ["moi@exemple.test"],
                    "delivery_status": "held",
                    "classification": "suspect",
                    "rationale": "Un écart demande ton avis.",
                    "attack_techniques": [],
                }
            if "FROM smtp_actions sa" in str(query):
                return None
            raise AssertionError(str(query))

        async def fetchval(self, query, *args):
            self.queries.append(str(query))
            if "SELECT raw_eml" in str(query):
                return b"raw"
            if "INSERT INTO conversations" in str(query):
                return "22222222-2222-2222-2222-222222222222"
            if "INSERT INTO smtp_actions" in str(query):
                return "33333333-3333-3333-3333-333333333333"
            raise AssertionError(str(query))

        async def fetch(self, query, *args):
            self.queries.append(str(query))
            return [
                {
                    "clue_code": "CONTENT_URGENCY",
                    "direction": "adverse",
                    "strength": 20,
                    "statement": "Le message cherche à faire agir vite.",
                    "facts": {},
                }
            ]

        async def execute(self, query, *args):
            self.queries.append(str(query))
            self.executions.append((str(query), args))
            return "INSERT 0 1"

    async def test_la_file_recoit_la_fiche_les_adresses_et_la_photo(self) -> None:
        from sentimail_v3.conversation.conversation import ConversationStore

        pool = self._Pool()
        store = ConversationStore(
            pool,  # type: ignore[arg-type]
            "maia@sentinel.exemple.test",
            "MAIA <maia@exemple.test>",
            render_sandbox_url="http://renderer",
        )
        with (
            patch(
                "sentimail_v3.conversation.conversation.reveal",
                return_value=b"raw",
            ),
            patch(
                "sentimail_v3.conversation.conversation.screenshot",
                new=AsyncMock(return_value=PNG),
            ),
            patch(
                "sentimail_v3.conversation.conversation.thumbnail",
                new=AsyncMock(return_value=(JPEG, "image/jpeg")),
            ),
            patch(
                "sentimail_v3.conversation.conversation.protected_recipient",
                new=AsyncMock(return_value="moi@exemple.test"),
            ),
            patch(
                "sentimail_v3.conversation.conversation.pedagogy",
                new=AsyncMock(return_value=[]),
            ),
            patch(
                "sentimail_v3.conversation.conversation.move",
                new=AsyncMock(),
            ),
        ):
            self.assertTrue(await store.queue_invitation("message-id", decision_mode=True))

        outbox_query, outbox_args = next(
            item for item in pool.executions if "INSERT INTO assistant_outbox" in item[0]
        )
        texte = str(outbox_args[6])
        html = str(outbox_args[7])
        self.assertTrue(texte.startswith("DOUTEUX - 1 écart relevé"))
        self.assertIn("Pourquoi j&#x27;hésite", html)
        self.assertIn("Extraits du message", texte)
        self.assertIn("redescendons de notre nuage", texte)
        # La photo tient lieu d'aperçu : les extraits restent au texte seul.
        self.assertIn(f'src="cid:{PREVIEW_CID}"', html)
        self.assertIn("Nom affiché : Alerte", texte)
        self.assertIn("Adresse affichée : alerte@exemple.test", texte)
        self.assertIn(
            "Adresse d’enveloppe différente : retour@envoi.example", texte
        )
        self.assertIn("retour@envoi.example", html)
        self.assertIn("L’image jointe est une photo inerte", texte)
        self.assertIn(f'src="cid:{PREVIEW_CID}"', html)
        self.assertIn("attachment_content", outbox_query)
        self.assertEqual(PNG, outbox_args[10])
        self.assertEqual(JPEG, outbox_args[13])
        self.assertEqual("image/jpeg", outbox_args[12])
        notice_args = next(
            args for query, args in pool.executions
            if "INSERT INTO review_notices" in query
        )
        self.assertEqual("png", notice_args[3])
        for absent in (
            "Sujet original à ne pas recopier",
            "L’email ci-dessous",
            "<p>",
        ):
            self.assertNotIn(absent, texte)
        # La fiche HTML remet l'objet parmi les informations du message ; le
        # texte brut ne le répète pas, l'objet de l'avis le porte déjà.
        self.assertIn("Sujet original à ne pas recopier", html)
        for absent in ("L’email ci-dessous", "<p>"):
            self.assertNotIn(absent, html)


class ChoiceLinkTests(unittest.TestCase):
    def test_les_choix_a_et_b_sont_pre_remplis(self) -> None:
        liens = choice_links("maia@sentinel.mondomaine.example")
        for lettre in ("A", "B"):
            self.assertIn("body=", liens[lettre])
            self.assertIn(ACTION_TOKEN_PLACEHOLDER, liens[lettre])

    def test_le_choix_c_ouvre_un_message_a_ecrire(self) -> None:
        """« Autre chose » attend une explication : la pré-remplir la volerait."""
        lien = choice_links("maia@sentinel.mondomaine.example")["C"]
        self.assertIn(ACTION_TOKEN_PLACEHOLDER, lien)
        self.assertNotIn("Je+", lien)

    def test_le_texte_pre_rempli_est_compris_par_les_regles(self) -> None:
        # Une lettre seule ne veut rien dire pour l'interprétation : le corps
        # doit porter une phrase que les règles reconnaissent sans modèle.
        from urllib.parse import parse_qs, urlsplit

        from sentimail_v3.conversation.directive_policy import evaluate_directive

        liens = choice_links("maia@sentinel.mondomaine.example")
        for lettre, attendu in (("A", "release_original"), ("B", "suppress_future")):
            with self.subTest(lettre=lettre):
                corps = parse_qs(urlsplit(liens[lettre]).query)["body"][0]
                verdict = evaluate_directive(corps, {"requested_action": attendu})
                self.assertEqual(verdict["explicit_action"], attendu)

    def test_l_adresse_d_action_est_la_destination(self) -> None:
        liens = choice_links("maia@sentinel.mondomaine.example")
        self.assertTrue(liens["A"].startswith("mailto:maia@sentinel.mondomaine.example?"))


if __name__ == "__main__":
    unittest.main()


class TokenSubstitutionTests(unittest.IsolatedAsyncioTestCase):
    """Le jeton n'existe qu'à l'expédition : le marqueur doit y être remplacé."""

    async def _envoyer(self) -> list:
        from types import SimpleNamespace
        from unittest.mock import patch

        from sentimail_v3.conversation.assistant import _send_outbox

        envois: list[object] = []

        class _Pool:
            async def fetchrow(self, query, *args):
                if "instance_identity" in query:
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
                    "body_html": f"<a href='mailto:x?body={ACTION_TOKEN_PLACEHOLDER}'>A</a>",
                    "attempts": 1,
                    "attachment_content": None,
                    "attachment_filename": None,
                    "attachment_content_type": None,
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

        async def _capture(message, **kwargs):
            envois.append(message)
            return {}

        settings = SimpleNamespace(
            assistant_token_secret="secret",
            action_address="maia@sentinel.mondomaine.example",
            action_aliases=(),
            assistant_sender="MAIA <maia@mondomaine.example>",
            probe_recipient="probe@mondomaine.example",
            relay_host="relay",
            relay_port=25,
        )
        with patch(
            "sentimail_v3.conversation.assistant.aiosmtplib.send", new=_capture
        ):
            await _send_outbox(_Pool(), settings)  # type: ignore[arg-type]

        return envois

    async def test_le_marqueur_est_remplace_par_le_vrai_jeton(self) -> None:
        envois = await self._envoyer()
        self.assertTrue(envois)
        envoye = str(envois[0])
        self.assertNotIn(ACTION_TOKEN_PLACEHOLDER, envoye)
        self.assertIn("S3-ACTION:", envoye)

    async def test_l_avis_porte_sa_date(self) -> None:
        """Sans `Date`, un client trie l'avis n'importe où - souvent tout en bas.

        La RFC n'admet que deux en-têtes obligatoires, `From` et `Date`. Les
        avis partaient sans le second : ils arrivaient bien, mais se rangeaient
        hors de la liste que l'œil parcourt, et passaient pour perdus.
        """
        from email.utils import parsedate_to_datetime

        envois = await self._envoyer()
        date = envois[0]["Date"]
        self.assertIsNotNone(date)
        self.assertIsNotNone(parsedate_to_datetime(str(date)).tzinfo)


class IconeJointeTests(unittest.IsolatedAsyncioTestCase):
    """L'icône de l'indice voyage avec l'avis, sinon elle s'affiche cassée.

    Elle ne dépend pas du message : c'est une image du dépôt, jointe au corps
    quand celui-ci la référence - jamais téléchargée depuis un serveur, ce qui
    trahirait la lecture et se ferait bloquer.
    """

    async def test_le_corps_qui_cite_l_icone_la_transporte(self) -> None:
        from email.message import EmailMessage

        from sentimail_v3.conversation.assistant import attach_confidence_icon

        email = EmailMessage()
        email.set_content("corps")
        email.add_alternative(
            '<img src="cid:sm-indice-danger">', subtype="html"
        )
        attach_confidence_icon(email, '<img src="cid:sm-indice-danger">')
        self.assertIn("sm-indice-danger", str(email))
        self.assertIn("image/png", str(email))

    async def test_un_corps_sans_icone_n_emporte_rien(self) -> None:
        from email.message import EmailMessage

        from sentimail_v3.conversation.assistant import attach_confidence_icon

        email = EmailMessage()
        email.set_content("corps")
        email.add_alternative("<p>rien</p>", subtype="html")
        attach_confidence_icon(email, "<p>rien</p>")
        self.assertNotIn("image/png", str(email))

    async def test_un_niveau_inconnu_ne_fait_pas_tomber_l_envoi(self) -> None:
        from email.message import EmailMessage

        from sentimail_v3.conversation.assistant import attach_confidence_icon

        email = EmailMessage()
        email.set_content("corps")
        email.add_alternative('<img src="cid:sm-indice-inconnu">', subtype="html")
        attach_confidence_icon(email, '<img src="cid:sm-indice-inconnu">')
        self.assertNotIn("image/png", str(email))
