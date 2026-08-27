"""La mise en forme du récapitulatif : ce qu'on voit, et ce qu'on renvoie.

Le récapitulatif posait sa question en texte nu quand les avis, eux, avaient
déjà une charte : mêmes couleurs, mêmes lettres, mêmes boutons. Deux langages
pour la même question s'apprennent deux fois.

Il porte aussi le bulletin : un bouton ouvre une réponse déjà écrite, où il ne
reste qu'à cocher. Ce corps prérempli voyage dans une URL - donc il reste
court, et il ne transporte jamais le jeton d'action, qui vit dans l'objet.
"""

from __future__ import annotations

import unittest
from urllib.parse import parse_qs, urlsplit

from sentimail_v3.conversation.choice_answers import GRIS, ROUGE, VERT
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


class BoutonBulletinTests(unittest.TestCase):
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

    def test_le_bouton_de_reponse_est_present_une_seule_fois(self) -> None:
        self.assertEqual(self._html().count('data-choice="bulletin"'), 1)

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
