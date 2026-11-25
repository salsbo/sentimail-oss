"""Une réponse en HTML seul se lit sans sa citation, comme une réponse en texte.

Le 28 septembre 2026, une réponse iPhone (M-d8df0e) ne portait qu'une partie
HTML : « À », la signature, puis l'avis cité en entier. Le texte visible tenait
sur une seule ligne, la découpe de la citation ne voyait rien, et les mots du
bouton A recopiés dans la citation ont décidé à la place de la personne.

Les gabarits ci-dessous reprennent la structure des clients observés, avec des
adresses et des objets inventés.
"""

from __future__ import annotations

import unittest

from sentimail_v3.conversation.action_tokens import ACTION_MARKER_RE
from sentimail_v3.conversation.assistant import _preformatted_choice
from sentimail_v3.conversation.confirmation_code import code_hash, confirms
from sentimail_v3.conversation.conversation import readable_body, strip_quoted_reply
from sentimail_v3.conversation.digest import read_reply
from sentimail_v3.conversation.reply_reference import body_action_token
from sentimail_v3.observation.dossier.hooks.visible_text import (
    reply_html_text,
    visible_html_text,
)

AVIS_CITE = (
    "<div>Message suspect</div>"
    "<div>N'utilise aucun lien du message.</div>"
    "<div>Expéditeur</div><div>offres@boutique.example.org</div>"
    "<div>Que veux-tu faire ?</div>"
    "<div>A - Je le veux</div><div>Cet expéditeur est fiable, livre-le-moi</div>"
    "<div>B - Non merci</div><div>C’est indésirable, bloque cet expéditeur</div>"
    "<div>C - Autre chose</div><div>J’explique à MAIA</div>"
    "<div>Si les boutons ne fonctionnent pas, réponds simplement A, B ou C.</div>"
)


def _reponse(html: str) -> str:
    return strip_quoted_reply(readable_body(None, html))


class ClientsObservesTests(unittest.TestCase):
    def test_la_reponse_iphone_garde_la_lettre_et_perd_l_avis_cite(self) -> None:
        html = (
            '<html class="apple-mail-supports-explicit-dark-mode"><head>'
            '<meta http-equiv="content-type" content="text/html; charset=utf-8">'
            '</head><body dir="auto">À<br id="lineBreakAtBeginningOfSignature">'
            '<div dir="ltr">Sent from my iPhone</div><div dir="ltr"><br>'
            '<blockquote type="cite">On 27 Sep 2026, at 18:02, MAIA '
            "&lt;maia@example.org&gt; wrote:<br><br></blockquote></div>"
            '<blockquote type="cite"><div dir="ltr">﻿<style>.sm-col '
            "{ display: block !important; }</style>"
            + AVIS_CITE
            + "</div></blockquote></body></html>"
        )
        texte = _reponse(html)
        self.assertEqual(texte, "À\nSent from my iPhone")
        self.assertEqual(_preformatted_choice(texte), ("A", "Sent from my iPhone"))

    def test_gmail_coupe_a_la_citation(self) -> None:
        html = (
            '<div dir="ltr">B</div><br><div class="gmail_quote '
            'gmail_quote_container"><div dir="ltr" class="gmail_attr">Le lun. '
            "28 sept. 2026 à 10:00, MAIA &lt;maia@example.org&gt; a écrit :<br>"
            '</div><blockquote class="gmail_quote" style="margin:0px 0px 0px '
            '0.8ex">' + AVIS_CITE + "</blockquote></div>"
        )
        texte = _reponse(html)
        self.assertEqual(texte, "B")
        self.assertEqual(_preformatted_choice(texte)[0], "B")

    def test_outlook_web_coupe_a_l_en_tete(self) -> None:
        # L'en-tête vit dans #divRplyFwdMsg et l'original le suit en frère :
        # c'est la ligne « De : » qui coupe, pas un conteneur.
        html = (
            '<div dir="ltr">B</div><div id="appendonsend"></div>'
            '<hr style="display:inline-block;width:98%" tabindex="-1">'
            '<div id="divRplyFwdMsg" dir="ltr"><font face="Calibri"><b>De :</b> '
            "MAIA &lt;maia@example.org&gt;<br><b>Envoyé :</b> lundi 28 "
            "septembre 2026 10:00<br><b>À :</b> personne@example.org<br>"
            "<b>Objet :</b> Ton avis</font><div>&nbsp;</div></div>"
            "<div><div>Que veux-tu faire ?</div>"
            "<div>A - Livre-le, cet expéditeur est fiable</div></div>"
        )
        self.assertEqual(_reponse(html), "B")

    def test_outlook_bureau_coupe_a_l_en_tete(self) -> None:
        html = (
            '<div class="WordSection1"><p class="MsoNormal">B<o:p></o:p></p>'
            '<p class="MsoNormal"><o:p>&nbsp;</o:p></p>'
            '<div style="border:none;border-top:solid #E1E1E1 1.0pt">'
            '<p class="MsoNormal"><b>De&nbsp;:</b> MAIA &lt;maia@example.org&gt;'
            "<br><b>Envoyé&nbsp;:</b> lundi 28 septembre 2026 10:00<br>"
            "<b>Objet&nbsp;:</b> Ton avis</p></div>"
            '<p class="MsoNormal">A - Livre-le, cet expéditeur est fiable</p></div>'
        )
        self.assertEqual(_reponse(html), "B")

    def test_thunderbird_coupe_a_l_attribution(self) -> None:
        html = (
            "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; "
            'charset=UTF-8"></head><body><p>A<br></p><div class="moz-cite-prefix">'
            "Le 28/09/2026 à 10:00, MAIA a écrit&nbsp;:<br></div>"
            '<blockquote type="cite" cite="mid:s3.abc@example.org">'
            + AVIS_CITE
            + "</blockquote></body></html>"
        )
        texte = _reponse(html)
        self.assertEqual(texte, "A")
        self.assertEqual(_preformatted_choice(texte)[0], "A")

    def test_nouvel_outlook_conteneur_de_reference(self) -> None:
        html = (
            '<div dir="ltr">A</div><div dir="ltr"><br></div>'
            '<div id="ms-outlook-mobile-signature"><div dir="ltr">Envoyé à '
            "partir de Outlook pour iOS</div></div>"
            '<div id="mail-editor-reference-message-container">'
            '<div class="ms-outlook-mobile-reference-message"><b>De :</b> MAIA'
            "<br><b>Objet :</b> Ton avis<br>" + AVIS_CITE + "</div></div>"
        )
        self.assertEqual(_preformatted_choice(_reponse(html))[0], "A")

    def test_une_reponse_sous_la_citation_est_gardee(self) -> None:
        html = '<blockquote type="cite">' + AVIS_CITE + "</blockquote><div>B</div>"
        self.assertEqual(_reponse(html), "B")


class LignesTests(unittest.TestCase):
    def test_les_blocs_font_des_lignes_et_les_inline_non(self) -> None:
        html = (
            "<p>un</p><div>deux</div>trois<br>quatre"
            "<ul><li>cinq</li><li>six</li></ul>"
            "<p><b>De :</b> X</p><p><span>mot</span><i>collé</i></p>"
        )
        self.assertEqual(
            reply_html_text(html),
            "un\ndeux\ntrois\nquatre\ncinq\nsix\nDe : X\nmotcollé",
        )

    def test_la_citation_est_marquee_a_chaque_niveau(self) -> None:
        html = (
            "<div>réponse</div><blockquote>premier<blockquote>second"
            "</blockquote>retour</blockquote><div>fin</div>"
        )
        self.assertEqual(
            reply_html_text(html),
            "réponse\n> premier\n> > second\n> retour\nfin",
        )

    def test_un_changement_de_niveau_coupe_la_ligne(self) -> None:
        html = "avant<span class=\"gmail_quote\">dedans</span>après"
        self.assertEqual(reply_html_text(html), "avant\n> dedans\naprès")

    def test_style_et_script_restent_muets(self) -> None:
        html = (
            "<style>p{color:red}</style><script>alert(1)</script>"
            "<template>modèle</template><svg><text>dessin</text></svg>"
            "<p>visible</p>"
        )
        self.assertEqual(reply_html_text(html), "visible")

    def test_un_html_casse_ne_leve_pas(self) -> None:
        for html in (
            "<div><blockquote><p>un</div></span></blockquote>deux<<<>><!--",
            "</br></blockquote></p>texte",
            "<![if !supportLists]>1.<![endif]>point",
            "<p>" * 5000 + "profond",
        ):
            with self.subTest(html=html[:40]):
                self.assertIsInstance(reply_html_text(html), str)
        self.assertEqual(reply_html_text(None), "")  # type: ignore[arg-type]

    def test_les_hooks_lisent_encore_la_citation(self) -> None:
        texte = visible_html_text(
            "<p>réponse</p><blockquote>texte cité<br>suite</blockquote>"
        )
        self.assertIn("texte cité", texte)
        self.assertNotIn("\n", texte)
        self.assertNotIn(">", texte)


class LecteursDuCorpsTests(unittest.TestCase):
    def test_le_bulletin_coche_dans_une_citation_html_se_lit(self) -> None:
        html = (
            "<div>Voici</div><blockquote type=\"cite\">"
            "<div>Récapitulatif D-abc123</div><div>1. Objet</div>"
            "<div>[x] A [ ] B [ ] C</div></blockquote>"
        )
        corps = readable_body(None, html)
        lecture = read_reply(strip_quoted_reply(corps), corps, "D-abc123", 1)
        self.assertEqual(
            [(value.number, value.choice) for value in lecture.decisions], [(1, "A")]
        )

    def test_le_marqueur_daction_se_lit_encore_apres_une_ligne_citee(self) -> None:
        # Le marqueur et le code ne sont pas ancrés en début de ligne. Ce test
        # le fixe : une citation devenue « > » ne doit pas les faire disparaître.
        jeton = "t" * 43
        html = (
            "<blockquote>avis cité</blockquote>"
            f"<div>S3-ACTION:{jeton}</div>"
        )
        corps = readable_body(None, html)
        self.assertTrue(corps.startswith("> avis cité\n"))
        self.assertEqual(body_action_token(corps), jeton)
        cite = readable_body(None, f"<blockquote>S3-ACTION:{jeton}</blockquote>")
        self.assertTrue(cite.startswith(">"))
        self.assertEqual(ACTION_MARKER_RE.search(cite).group(1), jeton)

        html = "<blockquote>avis cité</blockquote><div>CONFIRME MAIA 7K3M9P</div>"
        texte = strip_quoted_reply(readable_body(None, html))
        self.assertTrue(confirms(texte, code_hash("7K3M9P")))


if __name__ == "__main__":
    unittest.main()
