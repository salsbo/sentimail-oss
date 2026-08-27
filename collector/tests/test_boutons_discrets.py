from __future__ import annotations

import re
import unittest

from sentimail_v3.conversation.choice_answers import (
    GRIS,
    ROUGE,
    VERT,
    render_choices,
)

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
        for lettre, couleur in (("A", VERT), ("B", ROUGE), ("C", GRIS)):
            with self.subTest(lettre=lettre):
                bloc = re.search(
                    r'data-choice="%s"(.*?)</a>' % lettre, rendu, re.S
                )
                self.assertIsNotNone(bloc)
                self.assertIn(f"background:{couleur}", bloc.group(0))

    def test_la_lettre_est_dans_le_bouton(self) -> None:
        rendu = render_choices(CHOIX, LIENS)
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                bloc = re.search(
                    r'data-choice="%s".*?</a>' % lettre, rendu, re.S
                ).group(0)
                self.assertIn(f">{lettre}<", bloc)

    def test_le_texte_du_bouton_est_blanc(self) -> None:
        # Du texte sombre sur un fond vert ou rouge ne se lit pas.
        rendu = render_choices(CHOIX, LIENS)
        self.assertEqual(rendu.count("color:#ffffff"), 3)

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
    """La même forme aux trois endroits qui demandent une réponse."""

    def test_le_gris_remplace_le_noir_partout(self) -> None:
        from sentimail_v3.conversation import junk_notice, review_notice
        from sentimail_v3.execution import delivery

        self.assertEqual(
            [choix[-1] for choix in review_notice._CHOICES], [VERT, ROUGE, GRIS]
        )
        self.assertEqual(
            [choix[-1] for choix in junk_notice._CHOICES], [VERT, GRIS]
        )
        self.assertEqual(
            [choix[-1] for choix in delivery._FEEDBACK_CHOICES][-1], GRIS
        )

    def test_le_jeu_de_boutons_suit_la_situation(self) -> None:
        """Livré -> B et C ; doute -> A, B et C ; indésirable -> A et C.

        Un message livré n'a pas de « livre-le-moi » ; un classement acquis
        n'a pas de « bien classé » ; seul le doute offre les trois gestes.
        """
        from sentimail_v3.conversation import junk_notice, review_notice
        from sentimail_v3.execution import delivery

        self.assertEqual([c[0] for c in review_notice._CHOICES], ["A", "B", "C"])
        self.assertEqual([c[0] for c in junk_notice._CHOICES], ["A", "C"])
        self.assertEqual([c[0] for c in delivery._FEEDBACK_CHOICES], ["B", "C"])


if __name__ == "__main__":
    unittest.main()
