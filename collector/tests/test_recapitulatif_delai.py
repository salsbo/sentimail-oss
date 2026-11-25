"""Un dossier n'entre au récapitulatif qu'après avoir eu le temps d'être lu.

Le 9 septembre 2026, un récapitulatif est parti dix-sept minutes après l'avis
unitaire d'un des dossiers qu'il rappelait. Un avis envoyé il y a un quart
d'heure n'a pas été ignoré : il n'a simplement pas encore été ouvert.

Le compte annoncé dans l'objet et la liste de la lettre viennent de deux
requêtes différentes. Elles doivent porter la même condition, sinon l'objet
promet trois messages là où la lettre en montre deux.
"""

from __future__ import annotations

import unittest

import sentimail_v3.config
from sentimail_v3.conversation import digest


class DelaiAvantRappelTests(unittest.TestCase):
    def test_le_delai_par_defaut_laisse_une_demi_journee(self) -> None:
        """Une demi-journée : le récapitulatif tourne toutes les 24 heures, donc
        un avis du matin entre bien dans celui du soir - rien n'est retardé
        d'un cycle - mais un avis du quart d'heure passé attend le suivant."""
        from pathlib import Path

        config = Path(sentimail_v3.config.__file__).read_text(encoding="utf-8")
        self.assertIn('os.environ.get("DIGEST_QUIET_HOURS", "12")', config)

    def test_les_deux_requetes_portent_la_meme_condition(self) -> None:
        from pathlib import Path

        texte = Path(digest.__file__).read_text(encoding="utf-8")
        self.assertEqual(texte.count("AVIS_MUR.replace("), 2)

    def test_la_condition_exige_un_avis_envoye_et_reposé(self) -> None:
        self.assertIn("status='sent'", digest.AVIS_MUR)
        self.assertIn("interval '1 hour'", digest.AVIS_MUR)
