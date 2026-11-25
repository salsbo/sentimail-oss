from __future__ import annotations

import re
import unittest

from sentimail_v3.conversation.choice_answers import render_choices
from sentimail_v3.conversation.choice_registry import GRIS, ROUGE, VERT

CHOIX = (
    ("A", "Livre-le-moi", "C’était une erreur", VERT),
    ("B", "Bien classé", "Bloque les prochains", ROUGE),
    ("C", "Autre chose", "J’explique à MAIA", GRIS),
)
LIENS = {
    "A": "mailto:maia@sentinel.mondomaine.example?body=A",
    "B": "mailto:maia@sentinel.mondomaine.example?body=B",
    "C": "mailto:maia@sentinel.mondomaine.example?body=C",
}


class FormeDuBoutonTests(unittest.TestCase):
    """Trois petits boutons colorés, la lettre dans le bouton.

    Les liens soulignés se lisaient comme du texte : rien ne disait qu'il
    fallait cliquer. Les pavés pleine largeur qu'on avait avant occupaient plus
    de hauteur que l'explication. Un bouton compact tient les deux.
    """

    def test_chaque_lettre_porte_sa_couleur_de_fond(self) -> None:
        rendu = render_choices(CHOIX, LIENS)
        attendus = {
            "A": f"background:{VERT}",
            "B": "color:#b91c1c;background:#ffffff;border:1px solid #fecaca",
            "C": "color:#334155;background:#ffffff;border:1px solid #cbd5e1",
        }
        for lettre, style in attendus.items():
            with self.subTest(lettre=lettre):
                bloc = re.search(
                    r'data-choice="%s"(.*?)</a>' % lettre, rendu, re.S
                )
                self.assertIsNotNone(bloc)
                self.assertIn(style, bloc.group(0))

    def test_la_lettre_est_dans_le_bouton(self) -> None:
        rendu = render_choices(CHOIX, LIENS)
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                bloc = re.search(
                    r'data-choice="%s".*?</a>' % lettre, rendu, re.S
                ).group(0)
                self.assertIn(f">{lettre}<", bloc)

    def test_le_texte_du_bouton_est_blanc(self) -> None:
        # A est plein (texte blanc), B et C sont en contour lisible sur fond blanc.
        rendu = render_choices(CHOIX, LIENS)
        self.assertEqual(rendu.count("color:#ffffff"), 1)
        self.assertIn("color:#b91c1c", rendu)
        self.assertIn("color:#334155", rendu)

    def test_les_boutons_restent_petits(self) -> None:
        # « tout petits » : au plus 13px de texte, au plus 8px de marge interne.
        rendu = render_choices(CHOIX, LIENS)
        for taille in re.findall(r"font-size:(\d+)px", rendu):
            self.assertLessEqual(int(taille), 13)
        for haut, _cote in re.findall(r"padding:(\d+)px (\d+)px", rendu):
            self.assertLessEqual(int(haut), 8)

    def test_ils_tiennent_sur_une_ligne(self) -> None:
        # Empilés, trois pavés reprenaient la hauteur qu'on avait supprimée.
        rendu = render_choices(CHOIX, LIENS)
        self.assertNotIn("display:block", rendu)
        self.assertEqual(rendu.count("display:inline-block"), 3)

    def test_deux_boutons_ne_se_touchent_jamais(self) -> None:
        # Sans séparateur dans la source, un client qui jette la marge affiche
        # « B · Non sollicitéC · Autre chose ».
        rendu = render_choices(CHOIX, LIENS)
        self.assertNotIn("</a><a ", rendu)
        self.assertEqual(rendu.count("</a>&nbsp;<a "), len(CHOIX) - 1)

    def test_le_soulignement_disparait(self) -> None:
        # Un bouton souligné se lit comme un lien mal rendu.
        self.assertIn("text-decoration:none", render_choices(CHOIX, LIENS))

    def test_le_libelle_reste_lisible(self) -> None:
        rendu = render_choices(CHOIX, LIENS)
        for titre in ("Livre-le-moi", "Bien classé", "Autre chose"):
            with self.subTest(titre=titre):
                self.assertIn(titre, rendu)


class GarantiesConserveesTests(unittest.TestCase):
    """Ce que le changement de forme ne doit pas emporter."""

    def test_un_schema_interdit_est_toujours_refuse(self) -> None:
        with self.assertRaises(ValueError):
            render_choices(CHOIX, dict(LIENS, A="javascript:alert(1)"))

    def test_une_couleur_hors_forme_est_toujours_refusee(self) -> None:
        mauvais = (("A", "t", "s", "red;background:url(x)"),)
        with self.assertRaises(ValueError):
            render_choices(mauvais, {"A": LIENS["A"]})

    def test_le_libelle_reste_echappe(self) -> None:
        piege = (("A", "<script>", "x", VERT),)
        rendu = render_choices(piege, {"A": LIENS["A"]})
        self.assertNotIn("<script>", rendu)
        self.assertIn("&lt;script&gt;", rendu)

    def test_le_lien_reste_celui_qu_on_donne(self) -> None:
        rendu = render_choices(CHOIX, LIENS)
        self.assertIn("mailto:maia@sentinel.mondomaine.example?body=A", rendu)

    def test_l_ordre_des_reponses_est_conserve(self) -> None:
        rendu = render_choices(CHOIX, LIENS)
        self.assertLess(rendu.index('data-choice="A"'), rendu.index('data-choice="B"'))
        self.assertLess(rendu.index('data-choice="B"'), rendu.index('data-choice="C"'))


class LesTroisSurfacesTests(unittest.TestCase):
    """Chaque surface ne propose que les gestes encore utiles."""

    def test_le_gris_remplace_le_noir_partout(self) -> None:
        from sentimail_v3.conversation.choice_registry import choice_presentations

        self.assertEqual(
            [choix.color for choix in choice_presentations("review")],
            [VERT, ROUGE, GRIS],
        )
        self.assertEqual(
            [choix.color for choix in choice_presentations("junk")], [VERT]
        )

    def test_le_jeu_de_boutons_suit_la_situation(self) -> None:
        """Doute -> A, B et C ; indésirable -> A ; livré -> aucun bouton.

        Un classement acquis n'a qu'un geste utile, sa récupération ; seul le
        doute offre les trois. Un message livré n'en porte aucun : écrits dans
        son corps, ils repartaient chez l'expéditeur dans chaque réponse citée.
        """
        from sentimail_v3.conversation.choice_registry import choice_presentations

        self.assertEqual(
            [choice.letter for choice in choice_presentations("review")],
            ["A", "B", "C"],
        )
        self.assertEqual(
            [choice.letter for choice in choice_presentations("junk")], ["A"]
        )
        with self.assertRaises(ValueError):
            choice_presentations("delivered")


if __name__ == "__main__":
    unittest.main()
