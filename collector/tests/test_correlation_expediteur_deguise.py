"""Un expéditeur sans visage qui déguise ses mots ne se laisse pas lire en clair.

M-96852d (30 octobre 2026) : « L'assuranc e vous informe », un objet « Carte
A′̍meli », un corps Termius caché derrière un HTML qui ne rend que « 616 » et
un lien, depuis un domaine jetable authentifié (DKIM aligné) que personne ne
revendique, jamais vu. Livré à 0,92 : le juge a lu le texte brut. Aucun des
trois faits ne suffit seul (un inconnu sans répondant est un inconnu, un texte
caché peut être un gabarit), ensemble ils décrivent un montage.
"""

from __future__ import annotations

import unittest

from sentimail_v3.code.correlation import correlations


def _codes(observed: set[str]) -> dict[str, dict[str, object]]:
    return {value["clue_code"]: value for value in correlations(observed)}


SANS_VISAGE = {"SENDER_WITHOUT_PUBLIC_FOOTPRINT", "HISTORY_FIRST_OBSERVATION"}


class ExpediteurDeguiseTests(unittest.TestCase):
    def test_un_mot_coupe_depuis_un_inconnu_sans_repondant_converge(self) -> None:
        found = _codes({"CONTENT_INTRAWORD_NOISE", *SANS_VISAGE})
        self.assertIn("CORRELATION_DISGUISED_UNKNOWN_SENDER", found)
        clue = found["CORRELATION_DISGUISED_UNKNOWN_SENDER"]
        self.assertEqual(clue["direction"], "adverse")
        self.assertEqual(clue["article_code"], "CORR-020")
        self.assertEqual(clue["facts"]["attack_technique"], "TEXT_OBFUSCATION")

    def test_le_texte_cache_ou_les_ecritures_melees_valent_deguisement(self) -> None:
        for indice in ("CONTENT_HIDDEN_TEXT_SALTING", "CONTENT_MIXED_SCRIPT"):
            with self.subTest(indice=indice):
                self.assertIn(
                    "CORRELATION_DISGUISED_UNKNOWN_SENDER",
                    _codes({indice, *SANS_VISAGE}),
                )

    def test_sans_deguisement_un_inconnu_sans_repondant_ne_converge_pas(self) -> None:
        self.assertNotIn("CORRELATION_DISGUISED_UNKNOWN_SENDER", _codes(set(SANS_VISAGE)))

    def test_un_deguisement_venu_d_un_expediteur_qui_a_un_repondant_ne_converge_pas(
        self,
    ) -> None:
        self.assertNotIn(
            "CORRELATION_DISGUISED_UNKNOWN_SENDER",
            _codes({"CONTENT_INTRAWORD_NOISE", "HISTORY_FIRST_OBSERVATION"}),
        )

    def test_un_apex_deja_livre_localement_defait_le_faisceau(self) -> None:
        self.assertNotIn(
            "CORRELATION_DISGUISED_UNKNOWN_SENDER",
            _codes(
                {
                    "CONTENT_INTRAWORD_NOISE",
                    "HISTORY_APEX_ESTABLISHED_LOCALLY",
                    *SANS_VISAGE,
                }
            ),
        )


if __name__ == "__main__":
    unittest.main()
