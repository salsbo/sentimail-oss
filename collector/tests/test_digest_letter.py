"""La mise en forme du récapitulatif : ce qu'on voit, et ce qu'on renvoie.

Le récapitulatif posait sa question en texte nu quand les avis, eux, avaient
déjà une charte : mêmes couleurs, mêmes lettres, mêmes boutons. Deux langages
pour la même question s'apprennent deux fois.

Les blocs conservent les cases et leur contexte. La réponse se fait depuis
la messagerie, sans boutons de bulletin au-dessus des messages.
"""

from __future__ import annotations

import unittest
import json
from datetime import datetime, timezone
from html import escape
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

from sentimail_v3.conversation.choice_registry import GRIS, ROUGE, VERT
from sentimail_v3.conversation.digest import digest_items, read_reply
from sentimail_v3.conversation.digest_letter import (
    ACTION_TOKEN_PLACEHOLDER,
    MAX_BULLETIN,
    ballot_mailto,
    build_text,
    render_digest_html,
)

REFERENCE = "D-3f9c1a"
ADRESSE = "maia@sentinel.mondomaine.example"


def _items(nombre: int = 3) -> list[dict[str, str]]:
    return [
        {
            "number": index,
            "subject": f"Objet numéro {index}",
            "sender": f"expediteur{index}@exemple.fr",
            "received": "18/08 à 09:12",
        }
        for index in range(1, nombre + 1)
    ]


def _requete(lien: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(lien).query)


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "a" and attributes.get("data-choice") == "bulletin":
            self.links.append(attributes["href"])


def _ballot_links(items):
    parser = _Links()
    parser.feed(render_digest_html({
        "items": items, "reference": REFERENCE, "action_address": ADRESSE,
    }))
    return parser.links


class BoutonBulletinTests(unittest.TestCase):
    def test_les_blocs_conservent_tous_les_dossiers_sans_boutons(self):
        items = [dict(item, identities=[
            f"Identité annoncée : Banque {item['number']}",
            f"Adresse affichée : {'notification-' * 8}{item['number']}@expediteur.example",
        ], addresses=[f"Adresse d’enveloppe différente : retour{item['number']}@ailleurs.example"],
            concerns=["Usurpation possible.", "Pression pour agir vite."],
            limits=["Un lien n’a pas pu être vérifié."],
        ) for item in _items(7)]
        page = render_digest_html({"items": items, "reference": REFERENCE})
        self.assertEqual(_ballot_links(items), [])
        self.assertNotIn("Répondre en cochant", page)
        self.assertNotIn("Si le bouton", page)
        for item in items:
            self.assertIn(f"{item['number']}. {item['subject']}", page)
            for value in item["identities"] + item["addresses"] + item["concerns"] + item["limits"]:
                self.assertIn(escape(value), page)
        self.assertEqual(page.count("[&nbsp;]"), 21)

    def test_un_dossier_trop_long_reste_complet_dans_son_bloc(self):
        huge = dict(_items(1)[0], sender="a" * 2000 + "@example.org")
        self.assertEqual(ballot_mailto(ADRESSE, [huge], REFERENCE), "")
        items = [huge, _items(2)[1]]
        page = render_digest_html({"items": items, "reference": REFERENCE})
        self.assertIn(huge["sender"], page)
        self.assertIn("2. Objet numéro 2", page)
        self.assertEqual(_ballot_links(items), [])

    def test_un_seul_bouton_conserve_aussi_le_contexte(self):
        item = dict(_items(1)[0], identities=["Identité annoncée : Banque",
                    "Adresse affichée : client@expediteur.example"],
                    addresses=["Adresse d’enveloppe différente : retour@ailleurs.example"],
                    concerns=["Usurpation possible."])
        body = _requete(ballot_mailto(ADRESSE, [item], REFERENCE))["body"][0]
        for value in item["identities"] + item["addresses"] + item["concerns"]:
            self.assertIn(value, body)

    def test_le_bouton_ouvre_un_message_a_l_adresse_d_action(self) -> None:
        lien = ballot_mailto(ADRESSE, _items(), REFERENCE)
        self.assertTrue(lien.startswith(f"mailto:{ADRESSE}?"))

    def test_le_jeton_vit_dans_l_objet_et_nulle_part_ailleurs(self) -> None:
        requete = _requete(ballot_mailto(ADRESSE, _items(), REFERENCE))
        self.assertIn(ACTION_TOKEN_PLACEHOLDER, requete["subject"][0])
        self.assertNotIn(ACTION_TOKEN_PLACEHOLDER, requete["body"][0])

    def test_le_corps_porte_une_ligne_de_cases_par_dossier(self) -> None:
        corps = _requete(ballot_mailto(ADRESSE, _items(), REFERENCE))["body"][0]
        for index in (1, 2, 3):
            with self.subTest(index=index):
                self.assertIn(f"{index}. Objet numéro {index}", corps)
        self.assertEqual(corps.count("[ ] A"), 3)

    def test_le_corps_porte_la_reference_du_recapitulatif(self) -> None:
        corps = _requete(ballot_mailto(ADRESSE, _items(), REFERENCE))["body"][0]
        self.assertIn(REFERENCE, corps)

    def test_les_espaces_ne_deviennent_pas_des_plus(self) -> None:
        # urlencode encode l'espace en « + », convention des formulaires web
        # qu'un client de messagerie n'applique pas à un mailto: - la consigne
        # arriverait alors truffée de « + ».
        lien = ballot_mailto(ADRESSE, _items(), REFERENCE)
        self.assertNotIn("+", urlsplit(lien).query)

    def test_le_bulletin_reste_transportable(self) -> None:
        # Au-delà de deux mille caractères, plusieurs clients tronquent l'URL
        # sans prévenir : le bulletin arriverait amputé de ses derniers
        # dossiers, cochés dans le vide.
        lien = ballot_mailto(ADRESSE, _items(MAX_BULLETIN), REFERENCE)
        self.assertLess(len(lien), 2000)

    def test_le_bulletin_dit_ce_qu_il_ne_porte_pas(self) -> None:
        # Un bulletin tronqué en silence se referme sur dix lignes alors que
        # vingt attendent : on croit avoir tout traité, et le reste dort.
        total = MAX_BULLETIN + 8
        corps = _requete(ballot_mailto(ADRESSE, _items(total), REFERENCE))["body"][0]
        portes = corps.count("[ ] A")
        self.assertIn(f"{total - portes} autre(s)", corps)
        # Il nomme le premier dossier absent, pour qu'on sache où reprendre.
        self.assertIn(f"« {portes + 1} A »", corps)

    def test_un_bulletin_complet_ne_parle_pas_d_un_reste(self) -> None:
        corps = _requete(ballot_mailto(ADRESSE, _items(3), REFERENCE))["body"][0]
        self.assertNotIn("autres", corps)

    def test_au_dela_du_maximum_le_bulletin_s_arrete(self) -> None:
        # Deux plafonds se cumulent : le nombre de dossiers et la longueur de
        # l'URL. Le second peut couper plus tôt que le premier - jamais plus
        # tard, et jamais jusqu'à ne rien proposer.
        corps = _requete(
            ballot_mailto(ADRESSE, _items(MAX_BULLETIN + 5), REFERENCE)
        )["body"][0]
        portes = corps.count("[ ] A")
        self.assertLessEqual(portes, MAX_BULLETIN)
        self.assertGreaterEqual(portes, 1)


class CorpsTexteTests(unittest.TestCase):
    def test_chaque_dossier_a_ses_cases(self) -> None:
        texte = build_text(_items(3), total=3, reference=REFERENCE, action_address=ADRESSE)
        self.assertEqual(texte.count("[ ] A"), 3)
        self.assertIn(REFERENCE, texte)

    def test_la_forme_ecrite_reste_proposee(self) -> None:
        # Cocher suppose un client qui cite. « 1 A » doit rester possible.
        texte = build_text(_items(2), total=2, reference=REFERENCE, action_address=ADRESSE)
        self.assertIn("1 A", texte)

    def test_le_reste_est_annonce(self) -> None:
        texte = build_text(_items(3), total=9, reference=REFERENCE, action_address=ADRESSE)
        self.assertIn("6", texte)


class MotifsDuRecapitulatifTests(unittest.TestCase):
    """Le dossier chargé doit rester explicable dans les deux versions envoyées."""

    def _row(self, **changes):
        row = {
            "subject": "Votre demande",
            "from_header": "Service clients <notification@support.exemple.fr>",
            "envelope_from": "retour@envoi.example",
            "reply_to_header": "Réponses <contact@reponse.example>",
            "captured_at": datetime(2026, 9, 5, 11, 22, tzinfo=timezone.utc),
            "evidence": json.dumps([
                {"clue_code": "AUTH_DMARC_FAIL", "direction": "adverse"},
                {"clue_code": "AUTH_DMARC_FAIL", "direction": "adverse"},
                {"clue_code": "URL_SANDBOX_INCOMPLETE", "direction": "neutral"},
                {"clue_code": "AUTH_DMARC_PASS", "direction": "favorable"},
            ]),
        }
        return row | changes

    def _render(self, row):
        items = digest_items([row])
        return (
            items[0],
            build_text(items, 1, REFERENCE, ADRESSE),
            render_digest_html({"items": items, "reference": REFERENCE, "action_address": ADRESSE}),
        )

    def test_les_adresses_et_motifs_du_dossier_arrivent_dans_les_deux_versions(self):
        item, texte, page = self._render(self._row())
        self.assertEqual(len(item["concerns"]), 1)
        self.assertEqual(len(item["limits"]), 1)
        for corps in (texte, page):
            self.assertIn("Adresse d’enveloppe différente : retour@envoi.example", corps)
            self.assertIn("Adresse de réponse différente : contact@reponse.example", corps)
            self.assertIn("Identité annoncée : Service clients", corps)
            self.assertIn("Adresse affichée : notification@support.exemple.fr", corps)
            self.assertIn("Pourquoi je te demande :", corps)
            self.assertIn(item["concerns"][0], corps)
            self.assertIn("Limite d’analyse :", corps)
            self.assertNotIn("AUTH_DMARC", corps)

    def test_trois_motifs_maximum_sans_repetition(self):
        evidence = [
            {"clue_code": code, "direction": "adverse"}
            for code in ("AUTH_DMARC_FAIL", "AUTH_DMARC_FAIL", "AUTH_SPF_FAIL",
                         "ATTACHMENT_YARA_MATCH", "CONTENT_ACTIVE_HTML")
        ]
        item, _, _ = self._render(self._row(evidence=evidence))
        self.assertEqual(len(item["concerns"]), 3)
        self.assertIn("malveillant", item["concerns"][-1])

    def test_une_difference_d_adresse_seule_n_invente_pas_de_grief(self):
        item, texte, page = self._render(self._row(evidence=None))
        self.assertEqual(item["concerns"], [])
        for corps in (texte, page):
            self.assertIn("Aucun point défavorable précis disponible.", corps)
            self.assertNotIn("fraude", corps)

    def test_les_adresses_identiques_ou_absentes_ne_creent_pas_d_ecart(self):
        for address in (None, "", "NOTIFICATION@SUPPORT.EXEMPLE.FR"):
            item, _, _ = self._render(self._row(envelope_from=address, reply_to_header=address))
            self.assertEqual(item["addresses"], [
                f"Adresse d’enveloppe : {address or '(non disponible)'}"
            ])

    def test_une_adresse_longue_reste_complete_et_le_html_est_echappe(self):
        address = "Service " + "client " * 12 + "<notification@support.exemple.fr>"
        motif = '<img src=x onerror="alert(1)">'
        item, texte, page = self._render(self._row(
            from_header=address,
            evidence=[{"clue_code": "", "direction": "adverse", "statement": motif}],
        ))
        self.assertIn("notification@support.exemple.fr", texte)
        self.assertIn("notification@support.exemple.fr", page)
        self.assertIn("client " * 11, texte)
        self.assertNotIn("<img", page)
        self.assertIn(escape(motif), page)

    def test_les_controles_muets_ne_masquent_pas_l_urgence(self):
        evidence = [
            {"clue_code": code, "direction": "adverse"}
            for code in ("AUTH_DKIM_INCONCLUSIVE", "AUTH_DMARC_INCONCLUSIVE",
                         "AUTH_SPF_INCONCLUSIVE", "CONTENT_URGENCY")
        ]
        item, _, _ = self._render(self._row(evidence=evidence))
        self.assertEqual(item["concerns"], [
            "Identité de l’expéditeur non vérifiable.", "Pression pour agir vite.",
        ])

    def test_les_domaines_officiels_viennent_uniquement_du_dossier(self):
        evidence = [{
            "clue_code": "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
            "direction": "adverse",
            "facts": {"facts": {
                "claimed_organisation": "Service clients",
                "from_apex": "exemple.fr", "official_apexes": ["officiel.example"],
            }},
        }]
        item, texte, page = self._render(self._row(evidence=evidence))
        for corps in (texte, page):
            self.assertIn("Domaines officiels observés : officiel.example", corps)
            self.assertIn("Usurpation possible", corps)
        evidence[0]["direction"] = "neutral"
        item, texte, _ = self._render(self._row(evidence=evidence))
        self.assertEqual(item["concerns"], [])
        self.assertNotIn("Domaines officiels", texte)

    def test_le_detournement_reste_une_hypothese_sans_doubler_le_motif(self):
        evidence = [
            {"clue_code": code, "direction": "adverse"}
            for code in ("CORRELATION_COMPROMISED_SENDER", "SENDER_ACTIVITY_INCOHERENT")
        ]
        item, _, _ = self._render(self._row(evidence=evidence))
        self.assertEqual(len(item["concerns"]), 1)
        self.assertIn("possible", item["concerns"][0])

    def test_les_motifs_ne_changent_pas_la_reponse_par_cases(self):
        _, texte, _ = self._render(self._row())
        citation = "\n".join(
            "> " + line for line in texte.replace("[ ] B", "[x] B").splitlines()
        )
        reading = read_reply("", citation, REFERENCE, mapping_size=1)
        self.assertEqual([(d.number, d.choice) for d in reading.decisions], [(1, "B")])


class PageDuRecapitulatifTests(unittest.TestCase):
    def _html(self, nombre: int = 3, total: int | None = None) -> str:
        items = _items(nombre)
        return render_digest_html(
            {
                "items": items,
                "total": total if total is not None else nombre,
                "reference": REFERENCE,
                "action_address": ADRESSE,
            }
        )

    def test_le_titre_dit_combien_de_messages_attendent(self) -> None:
        self.assertIn("3 message", self._html())

    def test_chaque_dossier_est_montre_avec_son_expediteur(self) -> None:
        page = self._html()
        self.assertIn("Objet numéro 2", page)
        self.assertIn("expediteur2@exemple.fr", page)

    def test_chaque_lettre_garde_la_couleur_des_avis(self) -> None:
        page = self._html()
        for couleur in (VERT, ROUGE, GRIS):
            with self.subTest(couleur=couleur):
                self.assertIn(couleur, page)

    def test_le_recapitulatif_ne_contient_pas_de_bouton_de_reponse(self) -> None:
        self.assertEqual(self._html().count('data-choice="bulletin"'), 0)

    def test_un_objet_hostile_ne_peut_pas_ecrire_de_balise(self) -> None:
        page = render_digest_html(
            {
                "items": [
                    {
                        "number": 1,
                        "subject": "<script>alert(1)</script>",
                        "sender": "<b>faux</b>@exemple.fr",
                        "received": "18/08 à 09:12",
                    }
                ],
                "total": 1,
                "reference": REFERENCE,
                "action_address": ADRESSE,
            }
        )
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_la_page_ne_porte_pas_le_jeton_en_clair_hors_du_lien(self) -> None:
        # Le marqueur n'existe que dans l'objet du mailto, remplacé à
        # l'expédition : il ne doit jamais s'afficher dans le texte lu.
        page = self._html()
        self.assertNotIn(f">{ACTION_TOKEN_PLACEHOLDER}", page)


if __name__ == "__main__":
    unittest.main()


class AbandonsAnnoncesTests(unittest.TestCase):
    """Ce que MAIA a cessé de suivre se dit, sans courrier de plus.

    Un dossier abandonné sort de la file en silence : rien ne distingue alors
    « tu as tout traité » de « j'ai renoncé à te le demander ». Une ligne dans
    le récapitulatif suffit à faire la différence, et n'ajoute aucun envoi.
    """

    def test_le_texte_dit_combien_ont_ete_abandonnes(self) -> None:
        texte = build_text(
            _items(2), total=2, reference=REFERENCE, action_address=ADRESSE,
            abandoned=18,
        )
        self.assertIn("18", texte)
        self.assertIn("livré", texte)

    def test_la_page_dit_combien_ont_ete_abandonnes(self) -> None:
        page = render_digest_html(
            {
                "items": _items(2),
                "total": 2,
                "reference": REFERENCE,
                "action_address": ADRESSE,
                "abandoned": 18,
            }
        )
        self.assertIn("18", page)

    def test_sans_abandon_rien_n_est_dit(self) -> None:
        texte = build_text(
            _items(2), total=2, reference=REFERENCE, action_address=ADRESSE
        )
        page = render_digest_html(
            {
                "items": _items(2),
                "total": 2,
                "reference": REFERENCE,
                "action_address": ADRESSE,
            }
        )
        self.assertNotIn("cessé de suivre", texte)
        self.assertNotIn("cessé de suivre", page)


class SuiteDeLettresTests(unittest.TestCase):
    """Le récapitulatif dit qu'une suite de lettres suffit, avec un exemple de
    la longueur de la liste envoyée."""

    def test_le_texte_donne_l_exemple_a_la_taille_de_la_liste(self) -> None:
        texte = build_text(_items(3), 3, REFERENCE, ADRESSE)
        self.assertIn("« ABA »", texte)
        self.assertIn("1 A, 2 B, 3 A", texte)
        self.assertIn("A ou B seulement", texte)

    def test_le_html_donne_le_meme_exemple(self) -> None:
        html = render_digest_html(
            {"items": _items(4), "total": 4, "reference": REFERENCE, "action_address": ADRESSE}
        )
        self.assertIn("ABAB", html)
        self.assertIn("1 A, 2 B, 3 A, 4 B", html)

    def test_un_seul_dossier_ne_propose_pas_de_suite(self) -> None:
        texte = build_text(_items(1), 1, REFERENCE, ADRESSE)
        self.assertNotIn("suite des lettres", texte)
