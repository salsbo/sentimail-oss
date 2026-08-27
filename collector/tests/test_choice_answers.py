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
    ("A", "Je le veux", "Cet expéditeur est fiable, livre-le-moi", VERT),
    ("B", "Non merci", "C’est indésirable, bloque cet expéditeur", ROUGE),
    ("C", "Autre chose", "J’explique à MAIA", GRIS),
)
LIENS = {"A": "mailto:a@x?body=A", "B": "mailto:b@x?body=B", "C": "mailto:c@x?body=C"}


def _lien(html: str, lettre: str) -> str:
    trouve = re.search(rf'<a [^>]*data-choice="{lettre}".*?</a>', html, re.S)
    assert trouve is not None, f"réponse {lettre} absente"
    return trouve.group(0)


class BoutonCompactTests(unittest.TestCase):
    """Un bouton, mais petit. Les deux échecs précédents disent la mesure.

    Les pavés pleine largeur occupaient plus de hauteur que l'explication
    qu'ils concluaient : sur un téléphone il fallait faire défiler pour
    retrouver ce que MAIA avait dit. Les liens soulignés qui leur ont succédé
    tenaient en trois lignes, mais se lisaient comme du texte - rien ne disait
    qu'il fallait cliquer.
    """

    def test_chaque_reponse_est_un_bouton_colore(self) -> None:
        html = render_choices(CHOIX, LIENS)
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                self.assertRegex(_lien(html, lettre), r"background:#[0-9a-fA-F]{6}")

    def test_aucune_hauteur_n_est_imposee(self) -> None:
        # « line-height » est une interligne, pas une boîte : c'est la hauteur
        # fixe qui fabriquait un pavé.
        html = render_choices(CHOIX, LIENS)
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                self.assertNotRegex(_lien(html, lettre), r"(?<!line-)height:")

    def test_la_marge_interne_reste_petite(self) -> None:
        html = render_choices(CHOIX, LIENS)
        for haut, cote in re.findall(r"padding:\s*(\d+)px\s+(\d+)px", html):
            self.assertLessEqual(int(haut), 8)
            self.assertLessEqual(int(cote), 14)

    def test_le_texte_reste_de_taille_ordinaire(self) -> None:
        html = render_choices(CHOIX, LIENS)
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                tailles = [
                    int(value)
                    for value in re.findall(r"font-size:\s*([0-9]+)px", _lien(html, lettre))
                ]
                self.assertTrue(tailles)
                self.assertLessEqual(max(tailles), 14)

    def test_les_reponses_tiennent_sur_une_ligne(self) -> None:
        # Empilés, trois boutons reprendraient la hauteur qu'on cherche à
        # rendre. Compacts, ils tiennent côte à côte.
        html = render_choices(CHOIX, LIENS)
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                self.assertIn("display:inline-block", _lien(html, lettre))

    def test_le_bouton_n_est_pas_souligne(self) -> None:
        # Un bouton souligné se lit comme un lien mal rendu.
        html = render_choices(CHOIX, LIENS)
        self.assertIn("text-decoration:none", _lien(html, "A"))

    def test_l_ordre_des_reponses_est_conserve(self) -> None:
        html = render_choices(CHOIX, LIENS)
        self.assertLess(html.index('data-choice="A"'), html.index('data-choice="B"'))
        self.assertLess(html.index('data-choice="B"'), html.index('data-choice="C"'))


class CouleurTests(unittest.TestCase):
    """La couleur dit la lettre : vert, rouge, gris."""

    def test_chaque_lettre_porte_sa_couleur_de_fond(self) -> None:
        html = render_choices(CHOIX, LIENS)
        for lettre, couleur in (("A", VERT), ("B", ROUGE), ("C", GRIS)):
            with self.subTest(lettre=lettre):
                self.assertIn(f"background:{couleur}", _lien(html, lettre))

    def test_le_texte_du_bouton_est_blanc(self) -> None:
        # Du texte sombre sur un fond vert ou rouge ne se lit pas.
        html = render_choices(CHOIX, LIENS)
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                self.assertIn("color:#ffffff", _lien(html, lettre))


class JeuPartielTests(unittest.TestCase):
    """Un message déjà livré n'a pas de réponse « livre-le-moi »."""

    def test_le_jeu_reduit_ne_montre_que_ses_reponses(self) -> None:
        html = render_choices(CHOIX[1:], LIENS)
        self.assertNotIn('data-choice="A"', html)
        self.assertIn('data-choice="B"', html)
        self.assertIn('data-choice="C"', html)

    def test_une_reponse_seule_reste_affichee(self) -> None:
        html = render_choices(CHOIX[1:2], LIENS)
        self.assertIn('data-choice="B"', html)
        self.assertNotIn('data-choice="C"', html)


class LienTests(unittest.TestCase):
    def test_chaque_reponse_porte_son_lien(self) -> None:
        html = render_choices(CHOIX, LIENS)
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                self.assertIn(f'href="{LIENS[lettre]}"', _lien(html, lettre))

    def test_le_libelle_reste_lisible_apres_echappement(self) -> None:
        choix = (("A", "Je le <veux>", "Rien & rien", VERT),)
        html = render_choices(choix, {"A": "mailto:a@x"})
        self.assertIn("&lt;veux&gt;", html)
        self.assertIn("&amp;", html)

    def test_la_lettre_et_le_libelle_sont_dans_le_lien(self) -> None:
        # Le lien doit se suffire : « A » seul ne dit pas ce qu'il déclenche.
        lien = _lien(render_choices(CHOIX, LIENS), "A")
        self.assertIn("A", lien)
        self.assertIn("Je le veux", lien)



class EchappementTests(unittest.TestCase):
    """L'échappement appartient au module, pas à la mémoire de l'appelant.

    Les libellés étaient échappés, l'adresse du lien ne l'était pas : seul le
    pied de page du message livré s'en chargeait de son côté. Un appelant de
    plus, ou un oubli, et une adresse d'action mal formée sortait du gabarit.
    Aucun de ces champs n'est aujourd'hui rempli par un correspondant, mais le
    contrat doit tenir sans dépendre de qui appelle.
    """

    def test_une_adresse_ne_peut_pas_sortir_de_l_attribut(self) -> None:
        piege = 'mailto:a@x?subject="><script>alert(1)</script>'
        html = render_choices(CHOIX[:1], {"A": piege})
        self.assertNotIn("<script>", html)
        self.assertIn("&quot;", html)

    def test_l_apostrophe_est_aussi_encodee(self) -> None:
        html = render_choices(CHOIX[:1], {"A": "mailto:a@x?body=l'un"})
        self.assertIn("&#x27;", html)

    def test_l_appelant_n_a_pas_a_echapper_lui_meme(self) -> None:
        # Un appelant qui échapperait en plus produirait des « &amp;amp; » :
        # le module échappe une fois, et une seule.
        html = render_choices(CHOIX[:1], {"A": "mailto:a@x?a=1&b=2"})
        self.assertIn("&amp;", html)
        self.assertNotIn("&amp;amp;", html)

    def test_seuls_les_schemas_attendus_sont_acceptes(self) -> None:
        for piege in ("javascript:alert(1)", "data:text/html,<script>", "vbscript:x"):
            with self.subTest(schema=piege):
                with self.assertRaises(ValueError):
                    render_choices(CHOIX[:1], {"A": piege})

    def test_la_couleur_ne_peut_pas_injecter_du_style(self) -> None:
        # Un échappement HTML ne protège pas un attribut de style : la couleur
        # est donc vérifiée sur sa forme, pas seulement échappée.
        for piege in ("red;background:url(x)", "#zzzzzz", "expression(1)", ""):
            with self.subTest(couleur=piege):
                with self.assertRaises(ValueError):
                    render_choices((("A", "t", "s", piege),), {"A": "mailto:a@x"})

    def test_les_couleurs_hexadecimales_passent(self) -> None:
        for bonne in (VERT, ROUGE, GRIS, "#abc"):
            with self.subTest(couleur=bonne):
                self.assertIn(
                    f"background:{bonne}",
                    render_choices((("A", "t", "s", bonne),), {"A": "mailto:a@x"}),
                )

    def test_les_schemas_legitimes_passent(self) -> None:
        for bon in ("mailto:a@x", "https://exemple.fr/repondre"):
            with self.subTest(schema=bon):
                self.assertIn("data-choice", render_choices(CHOIX[:1], {"A": bon}))

if __name__ == "__main__":
    unittest.main()
