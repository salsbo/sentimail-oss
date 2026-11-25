from __future__ import annotations

import inspect
import re
import unittest
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qs, urlsplit

from sentimail_v3.conversation.junk_notice import (
    JUNK_TOKEN_PLACEHOLDER,
    junk_choice_links,
    render_junk_html,
)

CONTEXTE = {
    "subject": "Reverse dementia in weeks? Bill Gates says yes",
    "sender": "Alzheimer's Alert <support@rockbook.hu>",
    "verdict": "spam",
    "reasons": [
        "Authentification : échec",
        "Contenu : pression pour agir vite",
        "Activité : sans rapport avec l’expéditeur",
    ],
    "message_excerpts": [
        "Reverse dementia naturally in just a few weeks.",
        "Visit https://hostile.example before midnight.",
    ],
    # Ces anciens blocs ne doivent plus allonger l'avis.
    "lessons": [{"advice": "N’utilise aucun lien du message."}],
    "identity_card": {
        "claimed": "Alzheimer's Alert",
        "from_domain": "rockbook.hu",
        "from_apex": "rockbook.hu",
        "official": ["example.invalid"],
    },
    "has_preview": True,
    "action_address": "maia@sentinel.mondomaine.example",
    "reference": "M-10eb8e",
}


class RenduTelegraphiqueTests(unittest.TestCase):
    def test_l_avis_tient_aux_faits_utiles(self) -> None:
        html = render_junk_html(dict(CONTEXTE))
        self.assertIn("CLASSÉ EN INDÉSIRABLES · AUCUNE ACTION REQUISE", html)
        self.assertIn(">De<", html)
        self.assertIn("support@rockbook.hu", html)
        self.assertIn(">Objet<", html)
        self.assertIn("Reverse dementia", html)
        self.assertIn(">Motifs</div>", html)
        for raison in CONTEXTE["reasons"]:
            self.assertIn(str(raison), html)

    def test_la_photo_du_message_est_montree(self) -> None:
        html = render_junk_html(dict(CONTEXTE))
        self.assertIn('src="cid:capture-email-neutralisee"', html)
        self.assertLess(html.index(">Motifs</div>"), html.index("cid:capture-email"))
        self.assertNotIn("cid:capture-email", render_junk_html({**CONTEXTE, "has_preview": False}))

    def test_adresse_affichee_et_adresse_reelle_sont_montrees(self) -> None:
        html = render_junk_html(
            {
                **CONTEXTE,
                "sender_lines": [
                    "Nom affiché : Alzheimer's Alert",
                    "Adresse affichée : support@rockbook.hu",
                    "Adresse d’enveloppe différente : bounce@mailer.example.ru",
                ],
            }
        )
        self.assertIn("Adresse affichée", html)
        self.assertIn("support@rockbook.hu", html)
        self.assertIn("Adresse d’enveloppe différente", html)
        self.assertIn("bounce@mailer.example.ru", html)
        self.assertNotIn("<strong>De</strong>", html)

    def test_les_anciens_blocs_ne_sont_plus_affiches(self) -> None:
        html = render_junk_html(dict(CONTEXTE))
        for absent in (
            "Aperçu de l’email",
            "Qui écrit",
            "example.invalid",
            "N’utilise aucun lien",
            "Que veux-tu faire",
        ):
            self.assertNotIn(absent, html)

    def test_de_courts_extraits_du_corps_restent_visibles(self) -> None:
        html = render_junk_html(dict(CONTEXTE))
        self.assertIn("Aperçu inerte", html)
        self.assertIn("Reverse dementia naturally", html)

    def test_les_liens_des_extraits_ne_sont_pas_actifs(self) -> None:
        html = render_junk_html(dict(CONTEXTE))
        self.assertNotIn("https://hostile.example", html)
        self.assertNotIn('href="https://hostile.example', html)

    def test_trois_motifs_au_plus(self) -> None:
        html = render_junk_html(
            {**CONTEXTE, "reasons": ["Un", "Deux", "Trois", "Quatre"]}
        )
        self.assertIn("Trois", html)
        self.assertNotIn("Quatre", html)

    def test_un_seul_bouton_livre_dans_la_boite(self) -> None:
        html = render_junk_html(dict(CONTEXTE))
        self.assertEqual(1, len(re.findall(r'data-choice="[A-Z]"', html)))
        self.assertIn('data-choice="A"', html)
        self.assertIn("Livrer dans ma boîte", html)
        self.assertNotIn('data-choice="B"', html)
        self.assertNotIn('data-choice="C"', html)

    def test_le_repli_sans_motif_reste_telegraphique(self) -> None:
        html = render_junk_html({**CONTEXTE, "reasons": []})
        self.assertIn("Analyse : plusieurs indices concordants", html)
        self.assertNotIn("faisceau", html.casefold())

    def test_un_danger_reste_visible_sans_changer_la_structure(self) -> None:
        html = render_junk_html({**CONTEXTE, "verdict": "dangerous"})
        self.assertIn("DANGEREUX · CLASSÉ EN INDÉSIRABLES", html)
        self.assertIn("Livrer dans ma boîte", html)

    def test_la_reference_est_visible(self) -> None:
        self.assertIn("M-10eb8e", render_junk_html(dict(CONTEXTE)))

    def test_les_valeurs_hostiles_sont_echappees(self) -> None:
        html = render_junk_html(
            {
                **CONTEXTE,
                "sender": '<img src=x onerror="x">',
                "reasons": ["<b>x</b>"],
                "message_excerpts": ["<script>x</script>"],
            }
        )
        self.assertNotIn("<img src=x", html)
        self.assertNotIn("<b>x</b>", html)
        self.assertNotIn("<script>", html)


class LiensTests(unittest.TestCase):
    def test_seule_la_livraison_est_proposee(self) -> None:
        liens = junk_choice_links("maia@sentinel.mondomaine.example")
        self.assertEqual(["A"], list(liens))

    def test_le_choix_a_demande_la_livraison(self) -> None:
        from sentimail_v3.conversation.directive_policy import evaluate_directive

        lien = junk_choice_links("maia@sentinel.mondomaine.example")["A"]
        corps = parse_qs(urlsplit(lien).query)["body"][0]
        verdict = evaluate_directive(corps, {"requested_action": "release_original"})
        self.assertEqual(verdict["explicit_action"], "release_original")

    def test_l_objet_porte_le_jeton_machine(self) -> None:
        lien = junk_choice_links("maia@sentinel.mondomaine.example")["A"]
        sujet = parse_qs(urlsplit(lien).query)["subject"][0]
        corps = parse_qs(urlsplit(lien).query)["body"][0]
        self.assertIn(JUNK_TOKEN_PLACEHOLDER, sujet)
        self.assertNotIn(JUNK_TOKEN_PLACEHOLDER, corps)


class EnveloppeTests(unittest.TestCase):
    ORIGINAL = (
        b"From: Alzheimer's Alert <support@rockbook.hu>\r\n"
        b"To: operateur@mondomaine.example\r\n"
        b"Subject: Reverse dementia in weeks? Bill Gates says yes\r\n"
        b"Message-ID: <hostile@rockbook.example>\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b'<html><body><a href="https://hostile.example">CLIQUE ICI</a></body></html>\r\n'
    )

    def _enveloppe(self, **extra: object):
        from sentimail_v3.execution.delivery import build_junk_envelope

        params: dict[str, object] = {
            "reasons": list(CONTEXTE["reasons"]),
            "lessons": [{"name": "Technique", "advice": "Conseil long."}],
            "preview": b"\x89PNG\r\n\x1a\n" + b"0" * 40,
            "full_preview": b"image pleine",
            "identity_card": CONTEXTE["identity_card"],
            "action_address": "maia@sentinel.mondomaine.example",
            "assistant_sender": "MAIA - SentiMail <maia@mondomaine.example>",
            "recipient": "operateur@mondomaine.example",
            "message_id": "10eb8e56-8444-4502-9b2d-c0434e4a26cc",
            "envelope_from": "bounce@mailer.example.ru",
        }
        params.update(extra)
        brut = build_junk_envelope(self.ORIGINAL, "spam", **params)  # type: ignore[arg-type]
        return BytesParser(policy=policy.default).parsebytes(brut)

    def test_l_original_est_remplace_par_de_courts_extraits(self) -> None:
        source = self._enveloppe().as_bytes()
        self.assertNotIn(b"hostile.example", source)
        self.assertIn(b"CLIQUE ICI", source)

    def test_la_miniature_est_dans_le_corps_et_la_capture_jointe(self) -> None:
        enveloppe = self._enveloppe()
        miniatures = [
            part for part in enveloppe.walk()
            if part.get("Content-ID") == "<capture-email-neutralisee>"
        ]
        jointes = [
            part for part in enveloppe.walk()
            if part.get_content_disposition() == "attachment"
        ]
        self.assertEqual(1, len(miniatures))
        self.assertEqual(["message-en-grand.png"], [p.get_filename() for p in jointes])

    def test_sans_capture_aucune_image_ne_voyage(self) -> None:
        enveloppe = self._enveloppe(preview=None)
        images = [
            part for part in enveloppe.walk()
            if part.get_content_maintype() == "image"
        ]
        self.assertEqual([], images)
        html = str(enveloppe.get_body(preferencelist=("html",)).get_content())
        self.assertNotIn("cid:capture-email", html)

    def test_entetes_et_objet_restent_exploitables(self) -> None:
        enveloppe = self._enveloppe()
        self.assertIn("maia@mondomaine.example", str(enveloppe["From"]))
        self.assertIn("operateur@mondomaine.example", str(enveloppe["To"]))
        self.assertIn("maia@sentinel.mondomaine.example", str(enveloppe["Reply-To"]))
        self.assertIn("Indésirable - Reverse dementia", str(enveloppe["Subject"]))
        self.assertIn("rockbook.hu", str(enveloppe["X-SentiMail-Original-From"]))
        self.assertEqual("spam", str(enveloppe["X-Sentimail-Verdict"]))

    def test_versions_html_et_texte_portent_la_meme_fiche(self) -> None:
        enveloppe = self._enveloppe()
        texte = str(enveloppe.get_body(preferencelist=("plain",)).get_content())
        html = str(enveloppe.get_body(preferencelist=("html",)).get_content())
        self.assertIn("Classé dans Indésirables", texte)
        self.assertIn("CLASSÉ EN INDÉSIRABLES", html)
        self.assertIn("Extraits du message", texte)
        self.assertIn("Aperçu inerte", html)
        for attendu in (
            "support@rockbook.hu",
            "Adresse affichée",
            "Adresse d’enveloppe différente",
            "bounce@mailer.example.ru",
            "Reverse dementia",
            "Authentification : échec",
            "CLIQUE ICI",
            "Livrer dans ma boîte",
            "M-10eb8e",
        ):
            self.assertIn(attendu, texte)
            self.assertIn(attendu, html)
        self.assertNotIn("Conseil long", texte)
        self.assertNotIn("Conseil long", html)

    def test_sans_motif_la_carte_reste_dans_l_entete_d_audit(self) -> None:
        enveloppe = self._enveloppe(reasons=[])
        entete = str(enveloppe["X-Sentimail-Classification-Reason"])
        self.assertIn("Se présente comme", entete)
        html = str(enveloppe.get_body(preferencelist=("html",)).get_content())
        self.assertNotIn("example.invalid", html)

    def test_le_jeton_est_substitue(self) -> None:
        source = self._enveloppe(token="JETON-DE-TEST").as_bytes().decode(
            "utf-8", "replace"
        )
        self.assertNotIn(JUNK_TOKEN_PLACEHOLDER, source)
        self.assertIn("JETON-DE-TEST", source)

    def test_sans_jeton_le_marqueur_ne_fuit_pas(self) -> None:
        self.assertNotIn(JUNK_TOKEN_PLACEHOLDER.encode(), self._enveloppe().as_bytes())

    def test_un_expediteur_d_avis_manquant_est_refuse(self) -> None:
        with self.assertRaises(ValueError):
            self._enveloppe(assistant_sender="")

    def test_un_destinataire_manquant_est_refuse(self) -> None:
        with self.assertRaises(ValueError):
            self._enveloppe(recipient="  ")


class MotifsTelegraphiquesTests(unittest.TestCase):
    def test_le_cas_rockbook_tient_en_trois_lignes(self) -> None:
        from sentimail_v3.code.plain_words import classification_reasons

        indices = [
            {"clue_code": "AUTH_DMARC_FAIL", "statement": ""},
            {"clue_code": "AUTH_DKIM_INCONCLUSIVE", "statement": ""},
            {"clue_code": "AUTH_SPF_SOFTFAIL", "statement": ""},
            {"clue_code": "CONTENT_URGENCY", "statement": ""},
            {"clue_code": "CORRELATION_COMPROMISED_SENDER", "statement": ""},
            {"clue_code": "SENDER_ACTIVITY_INCOHERENT", "statement": ""},
        ]
        self.assertEqual(
            [
                "Authentification : échec",
                "Contenu : pression pour agir vite",
                "Activité : sans rapport avec l’expéditeur",
            ],
            classification_reasons(indices, "", telegraphique=True),
        )

    def test_un_indice_sans_libelle_devient_une_fiche(self) -> None:
        from sentimail_v3.code.plain_words import classification_reasons

        self.assertEqual(
            ["Message : insiste pour obtenir une réponse immédiate"],
            classification_reasons(
                [
                    {
                        "clue_code": "NOUVEL_INDICE",
                        "statement": "Le message insiste pour obtenir une réponse immédiate.",
                    }
                ],
                "",
                telegraphique=True,
            ),
        )


class LivraisonBrancheeTests(unittest.TestCase):
    def test_la_livraison_classee_photographie_et_passe_l_enveloppe(self) -> None:
        from sentimail_v3.execution import delivery

        source = inspect.getsource(delivery.release_original)
        self.assertIn("build_junk_envelope", source)
        self.assertIn("await screenshot", source)
        self.assertIn("await thumbnail", source)
        self.assertIn('envelope_from=row["envelope_from"]', source)

    def test_l_ancien_bandeau_reste_le_repli_fail_soft(self) -> None:
        from sentimail_v3.execution import delivery

        source = inspect.getsource(delivery.release_original)
        self.assertLess(
            source.index("build_junk_envelope"), source.index("annotate_classified")
        )


if __name__ == "__main__":
    unittest.main()
