from __future__ import annotations

import unittest

from sentimail_v3.supervision import watchdog


class SeuilDInspectionTests(unittest.TestCase):
    """Une inspection lente doit se voir avant de devenir un retard d'analyse.

    Le 18 août, une fermeture TLS de trente secondes par URL a porté une
    analyse à dix-neuf minutes. Le superviseur ne l'a vu qu'au franchissement du
    seuil de dix minutes, et il a rapporté « retard d'analyse » - le symptôme,
    pas la cause. Une inspection d'URL anormalement lente est désormais un motif
    à part entière.
    """

    def test_le_compteur_est_un_motif_de_degradation(self) -> None:
        self.assertIn("slow_url_inspections", watchdog.DEGRADED_THRESHOLDS)

    def test_le_seuil_tolere_les_lenteurs_isolees(self) -> None:
        # Un domaine lent de temps en temps est la vie normale du réseau ; ce
        # qui doit alerter, c'est la répétition.
        self.assertGreaterEqual(watchdog.DEGRADED_THRESHOLDS["slow_url_inspections"], 3)

    def test_le_motif_apparait_au_dela_du_seuil(self) -> None:
        seuil = watchdog.DEGRADED_THRESHOLDS["slow_url_inspections"]
        motifs = watchdog._counter_reasons({"slow_url_inspections": seuil})
        self.assertIn("slow_url_inspections", motifs)

    def test_le_motif_est_absent_en_deca(self) -> None:
        seuil = watchdog.DEGRADED_THRESHOLDS["slow_url_inspections"]
        motifs = watchdog._counter_reasons({"slow_url_inspections": seuil - 1})
        self.assertNotIn("slow_url_inspections", motifs)

    def test_la_lenteur_est_une_defaillance_douce(self) -> None:
        # Elle ne fait pas tomber la chaîne : elle la ralentit. Elle appartient
        # donc aux compteurs suivis dans le temps, pas aux pannes franches.
        self.assertIn("slow_url_inspections", watchdog.SOFT_FAILURE_COUNTERS)


if __name__ == "__main__":
    unittest.main()
