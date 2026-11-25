"""Un avis se lit d'un coup d'œil : un grief, une ligne.

Le fondement d'un grief - la page lue, l'objet comparé, les trois identités
relevées - a sa place au dossier, pas dans la puce. Recopié dans l'avis, il
donnait des puces de dix lignes : le lecteur devait lire un paragraphe pour
retrouver le reproche, et l'avis ne tenait plus sur un écran de téléphone.
"""

from __future__ import annotations

import unittest

from sentimail_v3.code.plain_words import (
    classification_reasons,
    plain_limits,
    short_points,
)

# Un indice tel que le juge le range : le grief, et sous lui tout ce qui l'a
# fondé. C'est ce dernier bloc qui gonflait l'avis.
INDICE_COMPTE_DETOURNE = {
    "clue_code": "CORRELATION_COMPROMISED_SENDER",
    "statement": "Le contenu ne correspond pas à l'activité publiée (score 0.62)",
    "facts": {
        "explication": (
            "Activité publiée par Shelly Cloud sur shelly.com : « × It seems "
            "you're in . Redirect to Shelly US ? Yes, please No, thanks Shelly "
            "Europe Skip to content FREE DELIVERY for orders over 79€ Language "
            "English English Français Deutsch I… ». Objet comparé : « Alarm: "
            "Water detected by flood in amartin@example.org's house 1! »."
        ),
        "claimed_name": "Shelly Cloud",
        "from_address": "noreply0@shelly.cloud",
        "envelope_from": "noreply0@shelly.cloud",
    },
}


class MotifsCourtsTests(unittest.TestCase):
    def test_le_motif_ne_recopie_pas_le_fondement(self) -> None:
        (motif,) = short_points([INDICE_COMPTE_DETOURNE], 3)
        self.assertNotIn("shelly.com", motif)
        self.assertNotIn("FREE DELIVERY", motif)
        self.assertNotIn("Objet comparé", motif)

    def test_un_motif_tient_sur_une_phrase(self) -> None:
        for motif in short_points([INDICE_COMPTE_DETOURNE], 3):
            self.assertLessEqual(len(motif), 120, motif)
            self.assertEqual(1, motif.count("."), motif)

    def test_un_constat_absorbe_par_un_plus_fort_ne_s_ajoute_pas(self) -> None:
        """Trois contrôles muets et un échec disent une seule chose."""
        motifs = short_points(
            [
                {"clue_code": "AUTH_DMARC_FAIL", "statement": ""},
                {"clue_code": "AUTH_SPF_INCONCLUSIVE", "statement": ""},
                {"clue_code": "AUTH_DKIM_INCONCLUSIVE", "statement": ""},
                {"clue_code": "AUTH_DMARC_INCONCLUSIVE", "statement": ""},
            ],
            3,
        )
        self.assertEqual(1, len(motifs), motifs)

    def test_l_usurpation_absorbe_l_echec_d_authentification(self) -> None:
        """« Ce n'est pas eux » ne se dit qu'une fois.

        Un domaine étranger à l'organisation annoncée, un DMARC en échec et un
        premier contact de marque sont trois façons de dire la même chose. La
        plus explicite reste ; les deux autres allongeaient l'avis sans rien
        apprendre.
        """
        motifs = short_points(
            [
                {"clue_code": "AUTH_DMARC_FAIL", "statement": ""},
                {"clue_code": "CORRELATION_BRAND_FIRST_CONTACT", "statement": ""},
                {
                    "clue_code": "IDENTITY_CLAIMED_ORGANISATION_UNRELATED",
                    "statement": "",
                },
            ],
            3,
        )
        self.assertEqual(1, len(motifs), motifs)
        self.assertIn("organisation annoncée", motifs[0])

    def test_chaque_echec_d_authentification_s_efface_devant_l_usurpation(self) -> None:
        # Les codes sont ceux que les hooks émettent réellement
        # (observation/dossier/hooks/authentication.py) : un code que personne
        # n'émet ferait une règle morte, pas une règle.
        for code in (
            "AUTH_SPF_FAIL",
            "AUTH_DKIM_FAIL",
            "AUTH_DKIM_UNALIGNED",
            "CORRELATION_BRAND_FIRST_CONTACT",
        ):
            with self.subTest(code=code):
                motifs = short_points(
                    [
                        {"clue_code": code, "statement": ""},
                        {"clue_code": "IDENTITY_BRAND_MISMATCH", "statement": ""},
                    ],
                    3,
                )
                self.assertEqual(1, len(motifs), motifs)
                self.assertIn("organisation annoncée", motifs[0])

    def test_sans_usurpation_l_echec_d_authentification_se_dit(self) -> None:
        # L'absorption ne vaut que devant plus fort qu'elle : seule, la
        # défaillance d'authentification reste le motif du classement.
        motifs = short_points([{"clue_code": "AUTH_DMARC_FAIL", "statement": ""}], 3)
        self.assertEqual(1, len(motifs), motifs)

    def test_l_activite_incoherente_s_efface_devant_le_compte_detourne(self) -> None:
        motifs = short_points(
            [
                INDICE_COMPTE_DETOURNE,
                {"clue_code": "SENDER_ACTIVITY_INCOHERENT", "statement": ""},
            ],
            3,
        )
        self.assertEqual(1, len(motifs), motifs)

    def test_le_meme_grief_ne_se_repete_pas(self) -> None:
        motifs = short_points(
            [
                {"clue_code": "IDENTITY_BRAND_MISMATCH", "statement": ""},
                {"clue_code": "CORRELATION_BRAND_SPOOFING", "statement": ""},
            ],
            3,
        )
        self.assertEqual(1, len(motifs), motifs)

    def test_un_code_inconnu_garde_l_enonce_ampute_de_son_fondement(self) -> None:
        (motif,) = short_points(
            [
                {
                    "clue_code": "CODE_ABSENT_DU_VOCABULAIRE",
                    "statement": "Le message insiste pour un virement. Le compte a changé hier.",
                }
            ],
            3,
        )
        self.assertEqual("Le message insiste pour un virement.", motif)

    def test_les_limites_sont_courtes_elles_aussi(self) -> None:
        (limite,) = plain_limits(
            [
                {
                    "clue_code": "URL_SANDBOX_INCOMPLETE",
                    "statement": "",
                    "facts": {"explication": "Le lien a expiré après 20 minutes d'attente."},
                }
            ],
            2,
        )
        self.assertNotIn("20 minutes", limite)


class ClassementIndesirableTests(unittest.TestCase):
    def test_le_classement_dit_ses_motifs_en_bref(self) -> None:
        for motif in classification_reasons([INDICE_COMPTE_DETOURNE], ""):
            self.assertNotIn("shelly.com", motif)

    def test_un_classement_sans_indice_garde_la_motivation_du_juge(self) -> None:
        motifs = classification_reasons(
            [], "Un faisceau d'indices concordants désigne une campagne connue."
        )
        self.assertEqual(
            ["Un faisceau d'indices concordants désigne une campagne connue."], motifs
        )



class CarteDIdentiteTests(unittest.TestCase):
    """Quand la carte montre l'écart, les motifs ne le reformulent pas.

    La carte pose « Se présente comme / Écrit depuis / X écrit depuis » l'un
    sous l'autre : l'œil compare, sans savoir lire une adresse. Une puce qui
    répète « domaine étranger à l'organisation annoncée » juste dessous ne fait
    pas un second grief, seulement une seconde lecture du premier.
    """

    INDICE = {
        "clue_code": "IDENTITY_CLAIMED_ORGANISATION_UNRELATED",
        "statement": "",
        "facts": {
            "claimed_organisation": "NeuroLift Research",
            "from_apex": "artsencollectief.nl",
            "from_domain": "artsencollectief.nl",
            "official_apexes": ["neurolift.health"],
        },
    }

    def _carte(self) -> object:
        from sentimail_v3.code.plain_words import identity_card

        return identity_card([dict(self.INDICE)])

    def test_avec_carte_l_usurpation_ne_fait_plus_de_puce(self) -> None:
        self.assertEqual(
            [],
            classification_reasons(
                [dict(self.INDICE)], "motif du juge", carte=self._carte()
            ),
        )

    def test_le_motif_du_juge_ne_revient_pas_par_la_porte_du_repli(self) -> None:
        # Sans ce garde-fou, vider les puces ferait ressortir la motivation du
        # verdict - souvent la même phrase d'usurpation, en plus long.
        raisons = classification_reasons(
            [dict(self.INDICE)],
            "Le message se fait passer pour NeuroLift Research.",
            carte=self._carte(),
        )
        self.assertNotIn("NeuroLift", " ".join(raisons))

    def test_un_grief_d_une_autre_nature_survit_a_la_carte(self) -> None:
        raisons = classification_reasons(
            [dict(self.INDICE), {"clue_code": "CONTENT_URGENCY", "statement": ""}],
            "motif du juge",
            carte=self._carte(),
        )
        self.assertEqual(["Pression pour agir vite."], raisons)

    def test_le_domaine_sosie_se_tait_aussi_sous_la_carte(self) -> None:
        # La carte montre le sosie comme elle montre le domaine étranger :
        # « adresse créée pour ressembler à une marque connue » ressortirait
        # juste sous les deux lignes qui le donnent à voir.
        raisons = classification_reasons(
            [
                dict(self.INDICE),
                {"clue_code": "CORRELATION_COUSIN_DOMAIN_APPROACH", "statement": ""},
            ],
            "motif du juge",
            carte=self._carte(),
        )
        self.assertEqual([], raisons)

    def test_sans_carte_l_usurpation_reste_dite(self) -> None:
        raisons = classification_reasons([dict(self.INDICE)], "motif du juge", carte=None)
        self.assertEqual(
            ["Usurpation possible : domaine étranger à l’organisation annoncée."],
            raisons,
        )

    def test_une_carte_incomplete_ne_donne_aucune_ligne(self) -> None:
        # Les lignes de la carte servent jusque dans le dernier repli de la
        # livraison : une carte relue depuis la base sans son domaine ne doit
        # pas y lever d'erreur, seulement se taire.
        from sentimail_v3.code.plain_words import identity_lines

        self.assertEqual([], identity_lines({"claimed": "NeuroLift Research"}))
        self.assertEqual([], identity_lines({"from_domain": "artsencollectief.nl"}))
        self.assertEqual([], identity_lines("pas une carte"))
        self.assertEqual([], identity_lines(None))

    def test_une_carte_complete_donne_ses_trois_lignes(self) -> None:
        from sentimail_v3.code.plain_words import identity_card, identity_lines

        lignes = identity_lines(identity_card([dict(self.INDICE)]))
        self.assertEqual(
            [
                "Se présente comme : NeuroLift Research",
                "Écrit depuis : artsencollectief.nl",
                "NeuroLift Research écrit depuis : neurolift.health",
            ],
            lignes,
        )


if __name__ == "__main__":
    unittest.main()
