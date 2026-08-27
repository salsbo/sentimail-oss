"""Le trajet complet d'une réponse : ce qui part, coché, revient compris.

Les deux moitiés sont testées chacune de son côté - la lettre sait écrire des
cases, le lecteur sait les lire. Rien ne garantit qu'elles parlent de la même
chose : il suffit d'un libellé changé d'un côté pour que les croix cessent
d'être vues de l'autre, sans qu'aucun test ne bouge.

Ce trajet-ci coche le bulletin réellement produit, dans les deux formes où il
revient - le corps prérempli et la citation - et vérifie que la décision arrive.
"""

from __future__ import annotations

import unittest
from urllib.parse import parse_qs, urlsplit

from sentimail_v3.conversation.digest import read_reply
from sentimail_v3.conversation.digest_letter import ballot_mailto, build_text

REFERENCE = "D-3f9c1a"
ADRESSE = "maia@sentinel.mondomaine.example"
DOSSIERS = [
    {
        "number": 1,
        "subject": "Votre facture Free Mobile de juillet",
        "sender": "noreply@free.fr",
        "received": "18/08 à 09:12",
    },
    {
        "number": 2,
        "subject": "2 factures restent impayées",
        "sender": "recouvrement@exemple.fr",
        "received": "18/08 à 11:40",
    },
    {
        "number": 3,
        "subject": "Rejoignez notre programme",
        "sender": "contact@partenaire.example",
        "received": "19/08 à 08:05",
    },
]


def _cocher(texte: str, numero: int, lettre: str) -> str:
    """Met une croix comme le ferait quelqu'un, dans la bonne ligne."""
    lignes = texte.split("\n")
    courant: int | None = None
    for index, ligne in enumerate(lignes):
        depouillee = ligne.lstrip("> ").strip()
        if depouillee[:2].rstrip(".") .isdigit() and ". " in depouillee:
            courant = int(depouillee.split(".", 1)[0])
        if courant == numero and f"[ ] {lettre}" in ligne:
            lignes[index] = ligne.replace(f"[ ] {lettre}", f"[x] {lettre}", 1)
            return "\n".join(lignes)
    raise AssertionError(f"case {numero} {lettre} introuvable")


class BulletinPrerempliTests(unittest.TestCase):
    def _corps(self) -> str:
        lien = ballot_mailto(ADRESSE, DOSSIERS, REFERENCE)
        return parse_qs(urlsplit(lien).query)["body"][0]

    def test_les_croix_posees_sur_le_bulletin_reviennent_comprises(self) -> None:
        corps = _cocher(_cocher(self._corps(), 1, "A"), 3, "B")
        lecture = read_reply(corps, corps, REFERENCE, mapping_size=3)
        self.assertEqual(
            [(d.number, d.choice) for d in lecture.decisions], [(1, "A"), (3, "B")]
        )

    def test_une_explication_ecrite_apres_le_c_est_conservee(self) -> None:
        corps = _cocher(self._corps(), 2, "C").replace(
            "[x] C : ", "[x] C : c’est mon comptable, garde-le"
        )
        lecture = read_reply(corps, corps, REFERENCE, mapping_size=3)
        self.assertEqual(lecture.decisions[0].choice, "C")
        self.assertIn("comptable", lecture.decisions[0].detail)


class CitationCocheeTests(unittest.TestCase):
    """Répondre sans le bouton : on coche dans le texte cité, tel qu'il revient."""

    def _citation(self) -> str:
        texte = build_text(DOSSIERS, total=3, reference=REFERENCE, action_address=ADRESSE)
        return "\n".join(f"> {ligne}" for ligne in texte.split("\n"))

    def test_une_croix_dans_la_citation_decide(self) -> None:
        cite = _cocher(self._citation(), 2, "B")
        lecture = read_reply("", cite, REFERENCE, mapping_size=3)
        self.assertEqual([(d.number, d.choice) for d in lecture.decisions], [(2, "B")])

    def test_une_citation_non_touchee_ne_decide_rien(self) -> None:
        lecture = read_reply("merci", self._citation(), REFERENCE, mapping_size=3)
        self.assertEqual(lecture.decisions, [])
        self.assertEqual(lecture.conflicts, [])


if __name__ == "__main__":
    unittest.main()
