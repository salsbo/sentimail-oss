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
