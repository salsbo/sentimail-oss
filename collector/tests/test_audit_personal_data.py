"""Le détecteur qui garde la porte de la publication doit lui-même être gardé.

Il décide de ce qui sort du dépôt vers un dépôt public. Un détecteur qui se
dégrade laisse passer sans un mot - c'est exactement le défaut qu'il existe pour
empêcher. Ce test tient les deux versants : ce qu'il doit voir, et ce qu'il ne
doit pas signaler, sous peine de rendre chaque export impossible et donc de
faire désactiver le contrôle.
"""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest

CHEMIN = (
    pathlib.Path(__file__).resolve().parents[2] / "scripts" / "audit_personal_data.py"
)
_spec = importlib.util.spec_from_file_location("audit_personal_data", CHEMIN)
audit = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(audit)


def _examiner(contenu: str, nom: str = "cas.py") -> list[str]:
    with tempfile.TemporaryDirectory() as dossier:
        racine = pathlib.Path(dossier)
        (racine / nom).write_text(contenu, encoding="utf-8")
        return [str(t["nature"]) for t in audit.examiner(racine)]


class CeQuiDoitEtreVuTests(unittest.TestCase):
    def test_une_adresse_nominative_de_tiers(self) -> None:
        self.assertIn(  # audit-ok: cas d'épreuve du détecteur lui-même
            "adresse nominative", _examiner('FROM = "sarah@une-ecole.com.au"')  # audit-ok: cas d'épreuve du détecteur
        )

    def test_une_adresse_ip_publique(self) -> None:
        self.assertIn(  # audit-ok: cas d'épreuve
            # 192.0.3.1 : publique au sens du code, voisine de la plage de  # audit-ok: adresse d'épreuve, aucun message ne l'a portée
            # documentation, et relevée dans aucun message reçu.
            "adresse IP publique", _examiner('IP = "192.0.3.1"')  # audit-ok: adresse d'épreuve, aucun message ne l'a portée
        )

    def test_un_iban(self) -> None:
        self.assertIn(  # audit-ok: cas d'épreuve
            "IBAN", _examiner('IBAN = "FR7630006000011234567890189"')  # audit-ok: cas d'épreuve du détecteur
        )

    def test_un_numero_de_carte(self) -> None:
        self.assertIn(  # audit-ok: cas d'épreuve
            "numéro de carte", _examiner('CB = "4539 1488 0343 6467"')  # audit-ok: cas d'épreuve du détecteur
        )

    def test_un_numero_de_telephone(self) -> None:
        self.assertIn(  # audit-ok: cas d'épreuve
            "téléphone", _examiner('TEL = "06 42 71 83 95"')  # audit-ok: cas d'épreuve du détecteur
        )

    def test_un_nom_de_personne_en_expediteur(self) -> None:
        self.assertIn(
            "nom de personne en expéditeur",
            _examiner('MESSAGE = "From: Marc Lefevre <x@y.example>"'),  # audit-ok: cas d'épreuve
        )


class CeQuiNeDoitPasBloquerTests(unittest.TestCase):
    """Un contrôle qui crie sur tout finit désactivé."""

    def test_les_domaines_reserves(self) -> None:
        self.assertEqual(_examiner('A = "contact@ecole.example"'), [])

    def test_les_adresses_de_role(self) -> None:
        self.assertEqual(_examiner('A = "no-reply@boutique.fr"'), [])

    def test_les_reseaux_prives_et_documentaires(self) -> None:
        for ip in ("192.168.1.10", "10.0.0.4", "100.64.0.1", "192.0.2.7", "127.0.0.1"):
            with self.subTest(ip=ip):
                self.assertEqual(_examiner(f'IP = "{ip}"'), [])

    def test_les_empreintes_ne_sont_pas_des_telephones(self) -> None:
        ligne = "    --hash=sha256:29a0777c4ce1273acf90c87e4ae2fe0130182100d99bcd2ae5b"
        self.assertEqual(_examiner(ligne, nom="requirements.lock"), [])

    def test_un_numero_de_demonstration(self) -> None:
        self.assertEqual(_examiner('TEL = "0123456789"'), [])

    def test_un_collectif_n_est_pas_une_personne(self) -> None:
        self.assertEqual(_examiner('M = "From: Health News <x@y.example>"'), [])

    def test_les_adresses_de_role_numerotees_ou_au_pluriel(self) -> None:
        for adresse in ("noreply0@boutique.fr", "bounce-123@mg.boutique.fr", "bounces@em.boutique.fr"):
            with self.subTest(adresse=adresse):
                self.assertEqual(_examiner(f'A = "{adresse}"'), [])

    def test_un_uuid_n_est_pas_une_carte(self) -> None:
        self.assertEqual(_examiner('ID = "44444444-4444-4444-4444-444444444444"'), [])

    def test_une_exception_nommee_est_respectee(self) -> None:
        self.assertEqual(
            _examiner('IP = "100.128.0.1"  # audit-ok: frontière CGNAT éprouvée'), []
        )


class LeJournalNeRecopiePasTests(unittest.TestCase):
    def test_un_iban_trouve_est_masque(self) -> None:
        with tempfile.TemporaryDirectory() as dossier:
            racine = pathlib.Path(dossier)
            (racine / "cas.py").write_text(
                'IBAN = "FR7630006000011234567890189"', encoding="utf-8"  # audit-ok: cas d'épreuve
            )
            extraits = [str(t["extrait"]) for t in audit.examiner(racine)]
        self.assertEqual(len(extraits), 1)
        self.assertNotIn("30006000011234567890", extraits[0])  # audit-ok: cas d'épreuve


class LaPorteEstBrancheeTests(unittest.TestCase):
    def test_l_export_public_appelle_le_detecteur(self) -> None:
        export = (CHEMIN.parent / "export_public.sh").read_text(encoding="utf-8")
        self.assertIn("audit_personal_data.py", export)

    def test_les_mentions_legales_echappent_a_la_neutralisation(self) -> None:
        # Le titulaire des droits ne se remplace pas par un nom d'exemple.
        export = (CHEMIN.parent / "export_public.sh").read_text(encoding="utf-8")
        self.assertIn('legal = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md")', export)
        self.assertIn("ne nomme plus le titulaire des droits", export)

    def test_le_detecteur_ne_part_pas_dans_l_arbre_publie(self) -> None:
        # Il porte en clair les motifs qu'il cherche.
        export = (CHEMIN.parent / "export_public.sh").read_text(encoding="utf-8")
        self.assertIn('rm -f "$OUT/scripts/export_public.sh" "$OUT/scripts/audit_personal_data.py"', export)


if __name__ == "__main__":
    unittest.main()
