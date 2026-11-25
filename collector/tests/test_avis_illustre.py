"""Des motifs courts, lisibles par qui ne connaît rien à l'informatique.

M-490357 (6 septembre 2026) : trois lignes disaient la même chose avec des
mots faux (« ne publie aucune règle » pour un DNS qui ne répond pas), et
rien ne montrait le nom annoncé face au domaine qui a écrit.
"""

from __future__ import annotations

import unittest

from sentimail_v3.code.plain_words import identity_card, plain_clue, plain_points
from sentimail_v3.conversation.junk_notice import render_junk_html


def _auth(method: str, result: str) -> dict[str, object]:
    return {
        "clue_code": f"AUTH_{method.upper()}_INCONCLUSIVE",
        "statement": "énoncé du Code",
        "facts": {
            "method": method,
            "result": result,
            "from_apex": "somesepta.best",
            "claimed_organisation": "C I C",
        },
    }


class AuthentificationMuetteTests(unittest.TestCase):
    def test_trois_controles_muets_font_une_seule_ligne(self) -> None:
        lignes = plain_points(
            [_auth("dmarc", "temperror"), _auth("spf", "temperror"), _auth("dkim", "temperror")],
            3,
        )
        self.assertEqual(len(lignes), 1)
        self.assertIn("somesepta.best", lignes[0])
        self.assertNotIn("règle", lignes[0])

    def test_un_domaine_qui_ne_repond_pas_est_dit_ainsi(self) -> None:
        phrase = plain_clue("AUTH_SPF_INCONCLUSIVE", "énoncé", _auth("spf", "temperror")["facts"])
        self.assertEqual(
            phrase,
            "Je n’ai pas pu vérifier que ce message vient bien de somesepta.best : "
            "son domaine ne répond pas aux contrôles d’identité.",
        )

    def test_un_domaine_qui_ne_publie_rien_est_dit_ainsi(self) -> None:
        phrase = plain_clue("AUTH_DMARC_INCONCLUSIVE", "énoncé", _auth("dmarc", "none")["facts"])
        self.assertEqual(
            phrase,
            "Rien ne permet de vérifier que ce message vient bien de somesepta.best : "
            "son domaine ne publie pas ce qu’il faut pour cela.",
        )

    def test_un_echec_rend_les_controles_muets_sans_objet(self) -> None:
        lignes = plain_points(
            [
                {"clue_code": "AUTH_DMARC_FAIL", "statement": "x", "facts": {"from_apex": "orexemple.fr"}},
                _auth("spf", "none"),
                _auth("dkim", "none"),
            ],
            3,
        )
        self.assertEqual(len(lignes), 1)
        self.assertIn("ne reconnaît pas cet envoi", lignes[0])

    def test_sans_domaine_la_phrase_d_avant_reste(self) -> None:
        phrase = plain_clue("AUTH_DKIM_INCONCLUSIVE", "énoncé", {"method": "dkim", "result": "temperror"})
        self.assertEqual(phrase, "Rien ne prouve que le message n’a pas été modifié en chemin.")


class CarteQuiEcritTests(unittest.TestCase):
    ROWS = [
        {"clue_code": "CONTENT_URGENCY", "facts": {}},
        {
            "clue_code": "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
            "facts": {
                "claimed_organisation": "CIC",
                "from_apex": "somesepta.best",
                "from_domain": "cic-notification.sju.somesepta.best",
                "official_apexes": ["cic.fr"],
            },
        },
    ]

    def test_la_carte_dit_qui_se_presente_et_qui_ecrit(self) -> None:
        carte = identity_card(self.ROWS)
        self.assertEqual(
            carte,
            {
                "claimed": "CIC",
                "from_domain": "cic-notification.sju.somesepta.best",
                "from_apex": "somesepta.best",
                "official": ["cic.fr"],
            },
        )

    def test_sans_indice_d_identite_pas_de_carte(self) -> None:
        self.assertIsNone(identity_card([{"clue_code": "CONTENT_URGENCY", "facts": {}}]))

    def test_la_marque_imitee_fait_aussi_une_carte(self) -> None:
        carte = identity_card(
            [{"clue_code": "IDENTITY_BRAND_MISMATCH", "facts": {"brand": "paypal", "from_apex": "printerpoint.co.in"}}]
        )
        self.assertEqual(carte["claimed"], "PayPal")
        self.assertEqual(carte["from_apex"], "printerpoint.co.in")
        self.assertEqual(carte["official"], [])

    def test_la_phrase_de_l_organisation_dementie_est_courte(self) -> None:
        phrase = plain_clue(
            "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
            "énoncé du Code",
            self.ROWS[1]["facts"],
        )
        self.assertEqual(
            phrase,
            "Le nom annonce CIC, mais le message a été envoyé depuis somesepta.best, "
            "alors que CIC écrit depuis cic.fr.",
        )

    def test_l_avis_classe_remplace_la_carte_par_un_motif_court(self) -> None:
        """Une décision acquise tient en fiche ; la carte reste au dossier."""
        html = render_junk_html(
            {
                "subject": "Nouvelle demande",
                "sender": "C I C <contact@cic-notification.sju.somesepta.best>",
                "verdict": "spam",
                "reasons": ["Identité : domaine sans rapport"],
                "lessons": [],
                "identity_card": identity_card(self.ROWS),
                "action_address": "maia@exemple.test",
            }
        )
        self.assertIn("Identité : domaine sans rapport", html)
        self.assertIn("C I C", html)
        self.assertIn("cic-notification.sju.", html)
        self.assertNotIn("Se présente comme", html)
        self.assertNotIn("CIC écrit depuis", html)
        self.assertNotIn("cic.fr", html)

    def test_sans_carte_l_avis_classe_n_en_montre_pas(self) -> None:
        html = render_junk_html(
            {
                "subject": "x", "sender": "y", "verdict": "spam",
                "reasons": [], "lessons": [], "action_address": "m@e.test",
            }
        )
        self.assertNotIn("Se présente comme", html)
