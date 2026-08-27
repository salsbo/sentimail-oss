"""Le courrier technique ne s'adresse qu'à ceux qui exploitent le service.

Une lettre d'entretien parle d'analyses en échec, d'alertes étouffées et
d'erreurs de jugement : elle s'adresse à qui répare, pas à qui reçoit du
courrier. Trente-neuf sont pourtant parties vers un destinataire ordinaire
jusqu'au 25 août, parce qu'il figurait alors parmi les exploitants déclarés.

Retirer une adresse d'un réglage ne protège que jusqu'au prochain réglage :
ce test tient la règle elle-même - la liste des exploitants est la seule source
du destinataire, et rien d'autre ne peut le fournir.
"""

from __future__ import annotations

import inspect
import unittest

from sentimail_v3.supervision import caretaker, watchdog


class SourceDuDestinataireTests(unittest.TestCase):
    def test_l_entretien_ne_connait_que_les_exploitants(self) -> None:
        source = inspect.getsource(caretaker.report)
        self.assertIn("settings.operator_addresses", source)
        for interdit in ("participant_email FROM", "SELECT DISTINCT recipient"):
            self.assertNotIn(interdit, source)

    def test_l_alerte_technique_ne_connait_que_les_exploitants(self) -> None:
        source = inspect.getsource(watchdog)
        debut = source.index("destinataires = list(settings.operator_addresses)")
        fenetre = source[debut : debut + 600]
        self.assertNotIn("participant", fenetre)

    def test_sans_exploitant_declare_aucune_alerte_ne_part(self) -> None:
        # Un courrier sans destinataire serait refusé par le relais et
        # compterait pourtant pour une alerte émise.
        source = inspect.getsource(watchdog)
        debut = source.index("destinataires = list(settings.operator_addresses)")
        self.assertIn("if not destinataires:", source[debut : debut + 200])


class ListeDesExploitantsTests(unittest.TestCase):
    """La liste se lit dans un seul réglage, sans rien y ajouter d'implicite."""

    def test_la_liste_ne_retient_que_ce_qui_est_declare(self) -> None:
        from sentimail_v3.config import _operators

        reference, liste = _operators("Jean@exemple.test, jean@exemple.test ; autre@exemple.test")
        self.assertEqual(reference, "jean@exemple.test")
        self.assertEqual(liste, ("jean@exemple.test", "autre@exemple.test"))

    def test_un_reglage_vide_ne_designe_personne(self) -> None:
        from sentimail_v3.config import _operators

        self.assertEqual(_operators("  "), ("", ()))


if __name__ == "__main__":
    unittest.main()
