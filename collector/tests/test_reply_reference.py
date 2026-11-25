"""Une réponse à MAIA sans bouton se rattache au message auquel elle répond."""

from __future__ import annotations

import unittest

from sentimail_v3.conversation.reply_reference import (
    MAX_REFERENCES,
    body_action_token,
    referenced_message_ids,
)

JETON_A = "a" * 43
JETON_B = "b" * 43


class IdentifiantsCitesTests(unittest.TestCase):
    def test_le_parent_passe_avant_le_fil(self) -> None:
        self.assertEqual(
            referenced_message_ids(
                ["<parent@exemple.fr>"],
                ["<racine@exemple.fr> <milieu@exemple.fr> <parent@exemple.fr>"],
            ),
            ["parent@exemple.fr", "milieu@exemple.fr", "racine@exemple.fr"],
        )

    def test_le_fil_se_lit_du_plus_recent_au_plus_ancien(self) -> None:
        self.assertEqual(
            referenced_message_ids([], ["<un@x.fr>", "<deux@x.fr>"]),
            ["deux@x.fr", "un@x.fr"],
        )

    def test_la_casse_et_les_chevrons_ne_comptent_pas(self) -> None:
        # En production, un tiers des en-têtes arrive sans chevrons.
        self.assertEqual(
            referenced_message_ids(["Parent@Exemple.FR"], []),
            ["parent@exemple.fr"],
        )

    def test_les_courriers_de_maia_gardent_leur_voie(self) -> None:
        self.assertEqual(
            referenced_message_ids(
                [f"<s3.{JETON_A}@sentinel.exemple.fr>"], ["<livre@x.example>"]
            ),
            ["livre@x.example"],
        )

    def test_un_fil_hostile_reste_borne(self) -> None:
        fil = " ".join(f"<m{rang}@x.fr>" for rang in range(500))
        self.assertEqual(len(referenced_message_ids([], [fil])), MAX_REFERENCES)

    def test_sans_en_tete_rien_n_est_cite(self) -> None:
        self.assertEqual(referenced_message_ids([], []), [])


class JetonDuCorpsTests(unittest.TestCase):
    def test_un_jeton_seul_est_lu(self) -> None:
        corps = f"Bonjour\n> S3-ACTION:{JETON_A}\n> S3-ACTION:{JETON_A}"
        self.assertEqual(body_action_token(corps), JETON_A)

    def test_plusieurs_jetons_ne_designent_aucun_dossier(self) -> None:
        # Le fil CPH citait trois pieds de page : chacun visait un autre message.
        corps = f"B\n\n> S3-ACTION:{JETON_A}\n>> S3-ACTION:{JETON_B}"
        self.assertIsNone(body_action_token(corps))

    def test_un_corps_sans_jeton(self) -> None:
        self.assertIsNone(body_action_token("C'est du spam."))


if __name__ == "__main__":
    unittest.main()
