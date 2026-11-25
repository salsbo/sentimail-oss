"""Le courrier d'entretien ne part que pour une anomalie d'exploitation.

Règle du 13 septembre 2026 : un verdict humain s'applique, personne ne
repasse derrière. Un écart, même une vraie erreur, ne fait plus de courrier.

Les désaccords devenaient un courrier à chaque glissement de la fenêtre de
sept jours, y compris pour des prudences qui ne demandent rien. Ils vivent
désormais sur la page des écarts de la console ; la lettre ne part plus que
pour une vraie erreur encore ouverte ou un compteur d'anomalie levé.
"""

from __future__ import annotations

import unittest

from sentimail_v3.supervision.caretaker import (
    actionable_signals,
    disagreement_directions,
    mail_worthy,
)
from sentimail_v3.supervision.caretaker_letter import lettre
from sentimail_v3.supervision.discrepancies import (
    _DIRECTION_CASE,
    REAL_ERROR_DIRECTIONS,
)

_CALME = {
    "verdicts_en_erreur_24h": 0,
    "livraisons_differees": 0,
    "dossiers_coinces": 0,
    "retenues_sans_avis": 0,
    "alertes_amorties_24h": 0,
    "erreurs_de_verdict_24h": [],
    "desaccords_humain_modele_7j": [],
    "ecarts_non_traites": {
        "demande_au_lieu_de_classer": 0,
        "demande_au_lieu_de_livrer": 0,
        "erreur_de_qualification": 0,
        "laisse_passer": 0,
    },
}


def _etat(**changes: object) -> dict[str, object]:
    state = dict(_CALME)
    state["ecarts_non_traites"] = dict(_CALME["ecarts_non_traites"])  # type: ignore[arg-type]
    for key, value in changes.items():
        if key in state["ecarts_non_traites"]:  # type: ignore[operator]
            state["ecarts_non_traites"][key] = value  # type: ignore[index]
        else:
            state[key] = value
    return state


class CourrierTests(unittest.TestCase):
    """Ce qui justifie un courrier, et ce qui reste sur la page."""

    def test_un_etat_calme_ne_produit_pas_de_courrier(self) -> None:
        self.assertFalse(mail_worthy(_etat()))

    def test_les_prudences_seules_ne_produisent_pas_de_courrier(self) -> None:
        etat = _etat(demande_au_lieu_de_classer=3, demande_au_lieu_de_livrer=12)
        self.assertFalse(mail_worthy(etat))

    def test_une_vraie_erreur_ne_produit_pas_de_courrier(self) -> None:
        self.assertFalse(mail_worthy(_etat(laisse_passer=1)))
        self.assertFalse(mail_worthy(_etat(erreur_de_qualification=1)))

    def test_une_erreur_acquittee_ne_produit_plus_de_courrier(self) -> None:
        # L'écart existe toujours dans les mesures 7 j, mais il est traité :
        # ecarts_non_traites est à zéro, le courrier n'a plus de raison.
        etat = _etat(
            desaccords_humain_modele_7j=[
                {"humain": "spam", "modele": "legitimate", "count": 1}
            ],
        )
        self.assertFalse(mail_worthy(etat))

    def test_un_compteur_d_anomalie_produit_un_courrier(self) -> None:
        for compteur in (
            "retenues_sans_avis",
            "dossiers_coinces",
            "livraisons_differees",
        ):
            with self.subTest(compteur=compteur):
                self.assertTrue(mail_worthy(_etat(**{compteur: 1})))

    def test_des_alertes_regroupees_seules_ne_produisent_pas_de_courrier(self) -> None:
        self.assertFalse(mail_worthy(_etat(alertes_amorties_24h=9)))


class DiagnosticTests(unittest.TestCase):
    """Le diagnostic LLM ne tourne que quand un geste est envisageable."""

    def test_des_prudences_seules_ne_justifient_pas_de_diagnostic(self) -> None:
        etat = _etat(demande_au_lieu_de_livrer=12)
        self.assertFalse(actionable_signals(etat))

    def test_une_panne_reparable_justifie_le_diagnostic(self) -> None:
        etat = _etat(
            verdicts_en_erreur_24h=2,
            erreurs_de_verdict_24h=[
                {"error_type": "KeyError", "detail": "'clues'", "count": 2}
            ],
        )
        self.assertTrue(actionable_signals(etat))

    def test_un_refus_definitif_ne_justifie_pas_de_diagnostic(self) -> None:
        etat = _etat(
            verdicts_en_erreur_24h=1,
            erreurs_de_verdict_24h=[
                {"error_type": "SMTPRecipientsRefused",
                 "detail": "550 5.1.1 user unknown", "count": 1}
            ],
        )
        self.assertFalse(actionable_signals(etat))


class DirectionsSqlTests(unittest.TestCase):
    """Le classement SQL reproduit disagreement_directions, cas par cas."""

    def _direction_python(self, humain: str, modele: str) -> str | None:
        lecture = disagreement_directions(
            [{"humain": humain, "modele": modele, "count": 1}]
        )
        actifs = [sens for sens, compte in lecture.items() if compte]
        return actifs[0] if actifs else None

    def test_les_sens_sql_et_python_coincident(self) -> None:
        labels = ("legitimate", "spam", "dangerous", "suspect", "undetermined")
        for humain in labels:
            for modele in labels:
                if humain == modele:
                    continue
                attendu = self._direction_python(humain, modele)
                with self.subTest(humain=humain, modele=modele):
                    if attendu is None:
                        continue
                    self.assertIn(f"'{attendu}'", _DIRECTION_CASE)

    def test_les_vraies_erreurs_sont_les_deux_sens_tranches(self) -> None:
        self.assertEqual(
            set(REAL_ERROR_DIRECTIONS),
            {"laisse_passer", "erreur_de_qualification"},
        )


class LettreEcartsTests(unittest.TestCase):
    """La lettre grave pointe vers la page des écarts."""

    def test_le_lien_apparait_quand_l_url_est_connue(self) -> None:
        etat = _etat(laisse_passer=1, desaccords_humain_modele_7j=[
            {"humain": "spam", "modele": "legitimate", "count": 1}
        ], sens_des_desaccords_7j={"laisse_passer": 1})
        rendu = lettre(etat, {"diagnosis": ""}, {},
                       ecarts_url="https://console.example/ecarts")
        self.assertIn("https://console.example/ecarts", rendu.text)
        self.assertIn("https://console.example/ecarts", rendu.html)

    def test_une_vraie_erreur_ne_demande_ni_revue_ni_acquittement(self) -> None:
        etat = _etat(laisse_passer=1, sens_des_desaccords_7j={"laisse_passer": 1})
        rendu = lettre(etat, {"diagnosis": ""}, {},
                       ecarts_url="https://console.example/ecarts")
        for texte in (rendu.text, rendu.html, rendu.subject):
            self.assertNotIn("acquitte", texte)
            self.assertNotIn("examine", texte)
            self.assertNotIn("intervention requise", texte)
        self.assertIn("aucune action n’est requise", rendu.text + rendu.html)


class EnregistrementTests(unittest.TestCase):
    """L'écart naît clos par le verdict humain."""

    def test_l_ecart_est_clos_des_sa_creation(self) -> None:
        import inspect

        from sentimail_v3.supervision import discrepancies

        source = inspect.getsource(discrepancies.record)
        self.assertIn("acknowledged_at, acknowledged_by", source)
        self.assertIn("HUMAN_VERDICT", source)
        self.assertIn("WHERE acknowledged_at IS NULL", source)
        self.assertEqual("verdict_humain", discrepancies.HUMAN_VERDICT)

    def test_l_etat_ne_porte_plus_d_ecarts_a_traiter(self) -> None:
        import inspect

        from sentimail_v3.supervision import caretaker

        self.assertNotIn("ecarts_non_traites", inspect.getsource(caretaker))

    def test_sans_url_la_lettre_reste_muette_sur_la_console(self) -> None:
        rendu = lettre(_etat(), {"diagnosis": ""}, {})
        self.assertNotIn("acquittement", rendu.text)


if __name__ == "__main__":
    unittest.main()
