"""Les cases cochées d'un récapitulatif, lues telles qu'elles reviennent.

Une réponse arrive de deux façons : le bulletin qu'un bouton a prérempli, où
les cases sont dans le texte saisi, et la citation qu'on coche à même l'écran,
où chaque ligne est préfixée. Les deux disent la même chose et doivent se lire
pareil.

Ce qui n'est pas coché ne décide rien, et ce qui a été coché sur un
récapitulatif précédent ne décide pas d'aujourd'hui : la référence du
récapitulatif garde chaque bulletin dans son envoi.
"""

from __future__ import annotations

import unittest

from sentimail_v3.conversation.digest import parse_ballot

REFERENCE = "D-3f9c1a"
AUTRE_REFERENCE = "D-77b0e2"

BULLETIN = f"""Bonjour MAIA,

Coche d'un x, une seule case par message. Récapitulatif {REFERENCE}

1. Facture Free Mobile
   [x] A livrer   [ ] B bloquer   [ ] C autre :

2. Relance impayée
   [ ] A livrer   [x] B bloquer   [ ] C autre :

Merci !
"""

CITATION = f"""C'est bon pour moi.

> 7 message(s) attendent ton avis. Récapitulatif {REFERENCE}
>
> 1. Facture Free Mobile
>    [ ] A livrer   [x] B bloquer   [ ] C autre
>
> 2. Relance impayée
>    [x] A livrer   [ ] B bloquer   [ ] C autre
"""


class BulletinPrerempliTests(unittest.TestCase):
    def test_une_case_cochee_decide_son_numero(self) -> None:
        lecture = parse_ballot(BULLETIN, REFERENCE)
        self.assertEqual(
            [(d.number, d.choice) for d in lecture.decisions],
            [(1, "A"), (2, "B")],
        )

    def test_une_case_vide_ne_decide_rien(self) -> None:
        texte = f"Récapitulatif {REFERENCE}\n1. Objet\n   [ ] A   [ ] B   [ ] C"
        self.assertEqual(parse_ballot(texte, REFERENCE).decisions, [])

    def test_une_decision_cochee_n_est_pas_interpretee(self) -> None:
        # Elle est écrite par la personne, au même titre qu'un « 1 A » : elle
        # ne doit pas hériter des réserves qui pèsent sur ce qu'un modèle a cru
        # comprendre.
        lecture = parse_ballot(BULLETIN, REFERENCE)
        self.assertTrue(all(not d.interpreted for d in lecture.decisions))

    def test_les_graphies_de_coche_usuelles_sont_admises(self) -> None:
        for coche in ("x", "X", "✓", "✔", "*"):
            with self.subTest(coche=coche):
                texte = (
                    f"Récapitulatif {REFERENCE}\n3. Objet\n"
                    f"   [{coche}] A   [ ] B   [ ] C"
                )
                lecture = parse_ballot(texte, REFERENCE)
                self.assertEqual(
                    [(d.number, d.choice) for d in lecture.decisions], [(3, "A")]
                )

    def test_un_c_coche_garde_son_explication(self) -> None:
        texte = (
            f"Récapitulatif {REFERENCE}\n4. Objet\n"
            "   [ ] A   [ ] B   [x] C : je le connais, c’est mon fournisseur"
        )
        lecture = parse_ballot(texte, REFERENCE)
        self.assertEqual(lecture.decisions[0].choice, "C")
        self.assertIn("mon fournisseur", lecture.decisions[0].detail)

    def test_une_case_sans_numero_ne_decide_rien(self) -> None:
        texte = f"Récapitulatif {REFERENCE}\n[x] A livrer"
        self.assertEqual(parse_ballot(texte, REFERENCE).decisions, [])


class CitationCocheeTests(unittest.TestCase):
    def test_une_case_cochee_dans_la_citation_est_lue(self) -> None:
        lecture = parse_ballot(CITATION, REFERENCE)
        self.assertEqual(
            [(d.number, d.choice) for d in lecture.decisions],
            [(1, "B"), (2, "A")],
        )

    def test_les_marques_de_citation_imbriquees_ne_genent_pas(self) -> None:
        texte = f">> Récapitulatif {REFERENCE}\n>> 5. Objet\n>>    [x] A   [ ] B   [ ] C"
        lecture = parse_ballot(texte, REFERENCE)
        self.assertEqual([(d.number, d.choice) for d in lecture.decisions], [(5, "A")])


class DeuxCasesCocheesTests(unittest.TestCase):
    """Deux réponses pour un même message : on ne devine pas laquelle vaut."""

    TEXTE = (
        f"Récapitulatif {REFERENCE}\n1. Objet\n   [x] A livrer   [x] B bloquer   [ ] C"
    )

    def test_aucune_decision_n_est_prise(self) -> None:
        self.assertEqual(parse_ballot(self.TEXTE, REFERENCE).decisions, [])

    def test_le_numero_est_signale_comme_ambigu(self) -> None:
        self.assertEqual(parse_ballot(self.TEXTE, REFERENCE).conflicts, [1])


class ReferenceDuRecapitulatifTests(unittest.TestCase):
    """Un bulletin d'hier, cité dans un fil, ne décide pas d'aujourd'hui.

    Les numéros ne valent que dans leur envoi. Sans cette garde, une réponse
    donnée hier et recitée aujourd'hui appliquerait ses croix aux dossiers du
    jour - c'est-à-dire livrerait un message que personne n'a regardé.
    """

    def test_un_bulletin_d_un_autre_recapitulatif_est_ignore(self) -> None:
        lecture = parse_ballot(BULLETIN, AUTRE_REFERENCE)
        self.assertEqual(lecture.decisions, [])

    def test_seul_le_bloc_de_la_bonne_reference_est_lu(self) -> None:
        texte = (
            f"Récapitulatif {REFERENCE}\n1. Aujourd’hui\n   [x] A   [ ] B   [ ] C\n"
            f"\n> Récapitulatif {AUTRE_REFERENCE}\n> 1. Hier\n>    [ ] A   [x] B   [ ] C\n"
        )
        lecture = parse_ballot(texte, REFERENCE)
        self.assertEqual([(d.number, d.choice) for d in lecture.decisions], [(1, "A")])

    def test_des_cases_sans_reference_ne_decident_rien(self) -> None:
        texte = "1. Objet\n   [x] A   [ ] B   [ ] C"
        self.assertEqual(parse_ballot(texte, REFERENCE).decisions, [])


if __name__ == "__main__":
    unittest.main()


class AccuseDesCasesAmbiguesTests(unittest.TestCase):
    """Deux croix pour un message : il faut le dire, pas l'oublier."""

    def test_l_accuse_nomme_le_numero_ambigu(self) -> None:
        from sentimail_v3.conversation.digest import acknowledgement

        texte = acknowledgement([], [], remaining=2, ambiguous=[3])
        self.assertIn("3", texte)
        self.assertIn("une seule", texte.casefold())

    def test_sans_ambiguite_rien_n_est_dit(self) -> None:
        from sentimail_v3.conversation.digest import DigestDecision, acknowledgement

        texte = acknowledgement(
            [(DigestDecision(1, "A", ""), "Facture")], [], remaining=0
        )
        self.assertNotIn("une seule case", texte)
