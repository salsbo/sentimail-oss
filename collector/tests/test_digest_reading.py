"""Ce qu'une réponse au récapitulatif décide, quelle que soit sa forme.

Trois formes coexistent désormais : le couple écrit (« 1 A »), la case cochée,
et la lettre seule quand un seul dossier attend. Elles se lisent au même
endroit, dans cet ordre : ce que la personne a écrit de sa main l'emporte sur
ce qu'elle a coché ailleurs dans le message, parce qu'une correction s'écrit
après coup, au-dessus de la citation.
"""

from __future__ import annotations

import asyncio
import unittest

from sentimail_v3.conversation.digest import mapping_for_reply, read_reply

REFERENCE = "D-3f9c1a"

CITATION = f"""> 3 message(s) attendent ton avis. Récapitulatif {REFERENCE}
>
> 1. Facture Free Mobile
>    [x] A   [ ] B   [ ] C :
>
> 2. Relance impayée
>    [ ] A   [x] B   [ ] C :
"""


class LectureCombineeTests(unittest.TestCase):
    def test_les_cases_seules_decident(self) -> None:
        lecture = read_reply("", CITATION, REFERENCE, mapping_size=3)
        self.assertEqual(
            [(d.number, d.choice) for d in lecture.decisions], [(1, "A"), (2, "B")]
        )

    def test_la_forme_ecrite_reste_lue(self) -> None:
        lecture = read_reply("1 B", "1 B", REFERENCE, mapping_size=3)
        self.assertEqual([(d.number, d.choice) for d in lecture.decisions], [(1, "B")])

    def test_ce_qui_est_ecrit_l_emporte_sur_ce_qui_est_coche(self) -> None:
        # La citation dit « 1 A » ; au-dessus, la personne a écrit « 1 B ».
        # C'est une correction : elle vient après, elle gagne.
        lecture = read_reply("1 B", "1 B\n" + CITATION, REFERENCE, mapping_size=3)
        choix = {d.number: d.choice for d in lecture.decisions}
        self.assertEqual(choix[1], "B")
        self.assertEqual(choix[2], "B")

    def test_une_lettre_seule_decide_quand_un_seul_dossier_attend(self) -> None:
        lecture = read_reply("A", "A", REFERENCE, mapping_size=1)
        self.assertEqual([d.choice for d in lecture.decisions], ["A"])
        self.assertEqual(lecture.decisions[0].number, 0)

    def test_une_lettre_seule_ne_decide_rien_quand_plusieurs_attendent(self) -> None:
        self.assertEqual(read_reply("A", "A", REFERENCE, mapping_size=4).decisions, [])

    def test_un_message_vide_ne_decide_rien(self) -> None:
        lecture = read_reply("", "", REFERENCE, mapping_size=3)
        self.assertEqual(lecture.decisions, [])
        self.assertEqual(lecture.conflicts, [])

    def test_une_ambiguite_est_remontee(self) -> None:
        texte = f"Récapitulatif {REFERENCE}\n1. Objet\n   [x] A   [x] B   [ ] C"
        self.assertEqual(read_reply("", texte, REFERENCE, mapping_size=3).conflicts, [1])

    def test_sans_reference_les_cases_ne_decident_pas(self) -> None:
        # Un récapitulatif d'avant cette version n'a pas de référence : ses
        # cases n'existent pas, et rien ne doit être deviné à leur place.
        lecture = read_reply("2 A", "2 A", "", mapping_size=3)
        self.assertEqual([(d.number, d.choice) for d in lecture.decisions], [(2, "A")])


class _FauxPool:
    def __init__(self, ligne: dict[str, object] | None) -> None:
        self.ligne = ligne

    async def fetchrow(self, query: str, *args: object) -> dict[str, object] | None:
        return self.ligne


class ReferenceRetrouveeTests(unittest.TestCase):
    """La référence vit avec la numérotation, dans l'action consommée."""

    def test_la_numerotation_et_la_reference_reviennent_ensemble(self) -> None:
        pool = _FauxPool({"digest": {"1": "uuid-1"}, "digest_ref": REFERENCE})
        mapping, reference = asyncio.run(mapping_for_reply(pool, "cm-1"))
        self.assertEqual(mapping, {"1": "uuid-1"})
        self.assertEqual(reference, REFERENCE)

    def test_un_ancien_recapitulatif_revient_sans_reference(self) -> None:
        pool = _FauxPool({"digest": {"1": "uuid-1"}, "digest_ref": None})
        mapping, reference = asyncio.run(mapping_for_reply(pool, "cm-1"))
        self.assertEqual(mapping, {"1": "uuid-1"})
        self.assertEqual(reference, "")

    def test_une_reponse_hors_recapitulatif_ne_donne_rien(self) -> None:
        mapping, reference = asyncio.run(mapping_for_reply(_FauxPool(None), "cm-1"))
        self.assertEqual(mapping, {})
        self.assertEqual(reference, "")


if __name__ == "__main__":
    unittest.main()


class SequenceTests(unittest.TestCase):
    """Sur téléphone, cocher est pénible : une suite de lettres, dans l'ordre
    des dossiers, décide les uns après les autres. A et B seulement : un C
    appelle une explication, qu'une suite ne porte pas."""

    def _lire(self, texte: str, taille: int = 5):
        return read_reply(texte, texte, REFERENCE, mapping_size=taille)

    def test_une_suite_collee_decide_dans_l_ordre(self) -> None:
        lecture = self._lire("ABAAB")
        self.assertEqual(
            [(d.number, d.choice) for d in lecture.decisions],
            [(1, "A"), (2, "B"), (3, "A"), (4, "A"), (5, "B")],
        )
        self.assertTrue(lecture.sequence)

    def test_les_separateurs_et_les_minuscules_passent(self) -> None:
        for texte in ("a, b, a", "A B A", "A\nB\nA", "a-b-a", "A ; B ; A"):
            with self.subTest(texte=texte):
                lecture = self._lire(texte)
                self.assertEqual(
                    [(d.number, d.choice) for d in lecture.decisions],
                    [(1, "A"), (2, "B"), (3, "A")],
                )

    def test_une_suite_plus_courte_decide_les_premiers(self) -> None:
        lecture = self._lire("AB")
        self.assertEqual([(d.number, d.choice) for d in lecture.decisions], [(1, "A"), (2, "B")])

    def test_une_suite_plus_longue_ne_decide_rien_et_le_dit(self) -> None:
        lecture = self._lire("ABAAB", taille=3)
        self.assertEqual(lecture.decisions, [])
        self.assertFalse(lecture.sequence)
        self.assertIn("5 lettres", lecture.note)
        self.assertIn("3 message", lecture.note)

    def test_un_c_n_entre_pas_dans_une_suite(self) -> None:
        lecture = self._lire("ABC")
        self.assertEqual(lecture.decisions, [])
        self.assertFalse(lecture.sequence)
        self.assertEqual(lecture.note, "")

    def test_un_mot_en_plus_n_est_pas_une_suite(self) -> None:
        lecture = self._lire("AB merci")
        self.assertEqual(lecture.decisions, [])
        self.assertFalse(lecture.sequence)

    def test_une_lettre_seule_n_est_pas_une_suite(self) -> None:
        """Une lettre quand plusieurs attendent : on ignore de quoi elle parle."""
        lecture = self._lire("A")
        self.assertEqual(lecture.decisions, [])
        self.assertFalse(lecture.sequence)

    def test_les_croix_l_emportent_sur_la_suite(self) -> None:
        lecture = read_reply("BA", "BA\n" + CITATION, REFERENCE, mapping_size=3)
        self.assertEqual([(d.number, d.choice) for d in lecture.decisions], [(1, "A"), (2, "B")])
        self.assertFalse(lecture.sequence)

    def test_le_couple_ecrit_l_emporte_sur_la_suite(self) -> None:
        lecture = self._lire("1 B\nAB")
        self.assertEqual([(d.number, d.choice) for d in lecture.decisions], [(1, "B")])
        self.assertFalse(lecture.sequence)
