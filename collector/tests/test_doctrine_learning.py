from __future__ import annotations

import unittest

from sentimail_v3.code.doctrine_learning import recurring_profiles, render_note


def _label(
    signals: list[str], label: str = "spam", sender: str = "a@example.org",
    message_id: str = "1", observed_on: str = "2026-08-15",
) -> dict[str, object]:
    return {
        "label": label,
        "signals": signals,
        "sender_normalized": sender,
        "message_id": message_id,
        "observed_on": observed_on,
    }


class RecurringProfileTests(unittest.TestCase):
    def test_un_profil_repete_par_plusieurs_expediteurs_est_retenu(self) -> None:
        """Trois messages, trois expéditeurs, mêmes indices : c'est un motif."""
        profils = recurring_profiles(
            [
                _label(["IDENTITY_BRAND_MISMATCH", "AUTH_DMARC_FAIL", "CONTENT_URGENCY"],
                       sender="a@x.fr", message_id="1"),
                _label(["IDENTITY_BRAND_MISMATCH", "AUTH_DMARC_FAIL", "CONTENT_URGENCY"],
                       sender="b@y.fr", message_id="2"),
                _label(["IDENTITY_BRAND_MISMATCH", "AUTH_DMARC_FAIL", "URL_CROSS_APEX"],
                       sender="c@z.fr", message_id="3"),
            ]
        )
        self.assertEqual(len(profils), 1)
        profil = profils[0]
        self.assertEqual(profil.label, "spam")
        self.assertEqual(
            set(profil.signals), {"IDENTITY_BRAND_MISMATCH", "AUTH_DMARC_FAIL"}
        )
        self.assertEqual(profil.message_count, 3)

    def test_un_seul_expediteur_ne_fait_pas_doctrine(self) -> None:
        # Répété par un seul expéditeur, c'est une règle sur cette adresse,
        # pas un mécanisme d'attaque : l'écrire en doctrine généraliserait à
        # tort ce qui n'est qu'une habitude locale.
        self.assertEqual(
            recurring_profiles(
                [
                    _label(["IDENTITY_BRAND_MISMATCH", "AUTH_DMARC_FAIL"],
                           sender="seul@x.example", message_id=str(i))
                    for i in range(5)
                ]
            ),
            [],
        )

    def test_deux_messages_ne_suffisent_pas(self) -> None:
        self.assertEqual(
            recurring_profiles(
                [
                    _label(["A_UN", "A_DEUX"], sender="a@x.fr", message_id="1"),
                    _label(["A_UN", "A_DEUX"], sender="b@y.fr", message_id="2"),
                ]
            ),
            [],
        )

    def test_des_qualifications_contradictoires_ne_font_pas_doctrine(self) -> None:
        # Le même profil qualifié tantôt légitime tantôt indésirable ne
        # décrit rien : en tirer une fiche graverait une erreur.
        self.assertEqual(
            recurring_profiles(
                [
                    _label(["A_UN", "A_DEUX"], label="spam", sender="a@x.fr", message_id="1"),
                    _label(["A_UN", "A_DEUX"], label="spam", sender="b@y.fr", message_id="2"),
                    _label(["A_UN", "A_DEUX"], label="legitimate", sender="c@z.fr", message_id="3"),
                ]
            ),
            [],
        )

    def test_un_profil_trop_maigre_est_ecarte(self) -> None:
        # Un seul indice partagé ne caractérise pas un montage.
        self.assertEqual(
            recurring_profiles(
                [
                    _label(["AUTH_DMARC_FAIL", "AUTRE_UN"], sender="a@x.fr", message_id="1"),
                    _label(["AUTH_DMARC_FAIL", "AUTRE_DEUX"], sender="b@y.fr", message_id="2"),
                    _label(["AUTH_DMARC_FAIL", "AUTRE_TROIS"], sender="c@z.fr", message_id="3"),
                ]
            ),
            [],
        )


class RenderNoteTests(unittest.TestCase):
    def _profil(self):
        return recurring_profiles(
            [
                _label(["IDENTITY_BRAND_MISMATCH", "AUTH_DMARC_FAIL"],
                       sender="a@x.fr", message_id="1", observed_on="2026-08-14"),
                _label(["IDENTITY_BRAND_MISMATCH", "AUTH_DMARC_FAIL"],
                       sender="b@y.fr", message_id="2", observed_on="2026-08-15"),
                _label(["IDENTITY_BRAND_MISMATCH", "AUTH_DMARC_FAIL"],
                       sender="c@z.fr", message_id="3", observed_on="2026-08-16"),
            ]
        )[0]

    def test_la_fiche_est_sectionnee_et_cite_ses_sources(self) -> None:
        texte = render_note(self._profil())
        self.assertIn("1.", texte)
        self.assertIn("IDENTITY_BRAND_MISMATCH", texte)
        self.assertIn("3 message", texte)
        self.assertIn("2026-08-14", texte)

    def test_la_fiche_dit_qu_elle_ne_prouve_rien(self) -> None:
        """Une observation apprise reste une observation, pas une preuve."""
        texte = render_note(self._profil()).casefold()
        self.assertIn("ne prouve", texte)


if __name__ == "__main__":
    unittest.main()
