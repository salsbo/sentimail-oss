from __future__ import annotations

import unittest
from urllib.parse import unquote, urlsplit

from sentimail_v3.conversation.directive_policy import evaluate_directive
from sentimail_v3.conversation.junk_notice import junk_choice_links
from sentimail_v3.conversation.review_notice import choice_links


def _corps_tel_que_lu(lien: str) -> str:
    """Le corps que le client de messagerie affiche.

    Un client mail ne decode PAS `+` en espace dans un mailto: - cette
    convention appartient aux formulaires web. Il n'applique que le
    pourcentage-encodage.
    """
    return unquote(urlsplit(lien).query.split("body=", 1)[1])


class EncodageMailtoTests(unittest.TestCase):
    """Les espaces encodes en `+` cassaient l'interpretation des reponses.

    Le bouton « C'est du spam » produisait « Ne+le+livre+pas », ou les regexes
    d'interpretation attendent des espaces. Non seulement la consigne n'etait
    plus reconnue, mais « livre » y etait lu comme une demande de LIVRAISON :
    le clic qui devait classer un indesirable demandait de le delivrer.
    Seule la detection de contradiction a empeche l'action.
    """

    def test_le_corps_ne_contient_aucun_plus_a_la_place_d_un_espace(self) -> None:
        for lettre in ("A", "B", "C"):
            with self.subTest(lettre=lettre):
                corps = _corps_tel_que_lu(choice_links("maia@mondomaine.example")[lettre])
                self.assertNotIn("+", corps)

    def test_l_avis_indesirable_est_encode_pareil(self) -> None:
        for lettre in ("A", "C"):
            with self.subTest(lettre=lettre):
                corps = _corps_tel_que_lu(junk_choice_links("maia@mondomaine.example")[lettre])
                self.assertNotIn("+", corps)

    def test_le_refus_est_lu_comme_un_refus_et_non_une_livraison(self) -> None:
        corps = _corps_tel_que_lu(choice_links("maia@mondomaine.example")["B"])
        verdict = evaluate_directive(corps, {"requested_action": "suppress_future"})
        self.assertEqual(verdict["explicit_action"], "suppress_future")
        self.assertEqual(verdict["conflicts"], [])

    def test_l_acceptation_reste_lue_comme_une_livraison(self) -> None:
        corps = _corps_tel_que_lu(choice_links("maia@mondomaine.example")["A"])
        verdict = evaluate_directive(corps, {"requested_action": "release_original"})
        self.assertEqual(verdict["explicit_action"], "release_original")
        self.assertEqual(verdict["conflicts"], [])

    def test_la_reprise_de_l_avis_indesirable_est_lue_correctement(self) -> None:
        corps = _corps_tel_que_lu(junk_choice_links("maia@mondomaine.example")["A"])
        verdict = evaluate_directive(corps, {"requested_action": "release_original"})
        self.assertEqual(verdict["explicit_action"], "release_original")

    def test_le_pied_de_page_de_signalement_est_encode_pareil(self) -> None:
        from types import SimpleNamespace

        from sentimail_v3.execution.delivery import _feedback_mailto

        lien = _feedback_mailto(
            SimpleNamespace(action_address="maia@mondomaine.example"), "JETON"
        )
        self.assertNotIn("+", _corps_tel_que_lu(lien))

    def test_les_accents_restent_lisibles(self) -> None:
        # Les corps sont des phrases rédigées : leurs accents doivent survivre
        # au pourcentage-encodage du mailto.
        corps = _corps_tel_que_lu(choice_links("maia@mondomaine.example")["C"])
        self.assertIn("à propos", corps)
        corps = _corps_tel_que_lu(choice_links("maia@mondomaine.example")["A"])
        self.assertIn("expéditeur", corps)


if __name__ == "__main__":
    unittest.main()
