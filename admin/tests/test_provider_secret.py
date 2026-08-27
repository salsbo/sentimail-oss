from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sentimail_admin import pages, queries
from sentimail_admin.naming import normalize_preset
from sentimail_admin.presets import PRESETS
from sentimail_admin.secrets import write_named_secret

CLE = "sk-abcdef0123456789abcdef0123456789"


class EcritureDuSecretTests(unittest.TestCase):
    """La clé est un fichier, pas une ligne de base.

    Faire transiter un secret par la messagerie était la cause de tout : refus
    SMTP, rapport de non-remise emportant la clé, archive chiffrée que la
    chaîne comptait elle-même comme charge adverse. La console la pose
    directement, derrière Tailscale, sans qu'elle traverse aucune boîte.
    """

    def setUp(self) -> None:
        self.dossier = tempfile.mkdtemp(prefix="secrets-test-")

    def test_le_fichier_porte_le_nom_donne(self) -> None:
        write_named_secret(self.dossier, "deepseek_api_key", CLE)
        self.assertTrue((Path(self.dossier) / "deepseek_api_key").exists())

    def test_le_fichier_n_est_lisible_que_par_son_proprietaire(self) -> None:
        write_named_secret(self.dossier, "deepseek_api_key", CLE)
        mode = (Path(self.dossier) / "deepseek_api_key").stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_le_dossier_n_est_traversable_que_par_son_proprietaire(self) -> None:
        write_named_secret(self.dossier, "deepseek_api_key", CLE)
        self.assertEqual(Path(self.dossier).stat().st_mode & 0o777, 0o700)

    def test_la_cle_est_ecrite_telle_quelle(self) -> None:
        write_named_secret(self.dossier, "deepseek_api_key", CLE)
        contenu = (Path(self.dossier) / "deepseek_api_key").read_text(encoding="utf-8")
        self.assertEqual(contenu.strip(), CLE)

    def test_aucun_fichier_temporaire_ne_subsiste(self) -> None:
        # Un secret laissé dans un fichier temporaire serait lisible plus
        # longtemps que prévu, et invisible à la relecture du dossier.
        write_named_secret(self.dossier, "deepseek_api_key", CLE)
        restes = [n for n in os.listdir(self.dossier) if n.startswith(".")]
        self.assertEqual(restes, [])

    def test_une_seconde_ecriture_remplace_sans_trou(self) -> None:
        write_named_secret(self.dossier, "deepseek_api_key", CLE)
        write_named_secret(
            self.dossier, "deepseek_api_key", "sk-nouvelle-cle-000000000000"
        )
        contenu = (Path(self.dossier) / "deepseek_api_key").read_text(encoding="utf-8")
        self.assertIn("nouvelle", contenu)

    def test_un_nom_de_fichier_invalide_est_refuse(self) -> None:
        for mauvais in ("MAJUSCULES_api_key", "../../etc/passwd", "avec espace", ""):
            with self.subTest(mauvais=mauvais):
                with self.assertRaises(ValueError):
                    write_named_secret(self.dossier, mauvais, CLE)

    def test_une_cle_vide_est_refusee(self) -> None:
        with self.assertRaises(ValueError):
            write_named_secret(self.dossier, "deepseek_api_key", "   ")

    def test_une_cle_avec_saut_de_ligne_est_refusee(self) -> None:
        # Deux lignes dans le fichier feraient lire une clé tronquée.
        with self.assertRaises(ValueError):
            write_named_secret(self.dossier, "deepseek_api_key", "sk-abc\nsk-def")

    def test_les_cinq_presets_nommes_ont_leur_fichier_fixe(self) -> None:
        self.assertEqual(
            sorted(nom for nom, preset in PRESETS.items() if preset.secret_filename),
            ["anthropic", "deepseek", "mistral", "ollama", "openai"],
        )


class LaCleNeVaJamaisEnBaseTests(unittest.TestCase):
    """La base retient la configuration, jamais le secret."""

    def test_la_requete_de_configuration_ne_porte_pas_la_cle(self) -> None:
        requete = queries.set_role_provider(
            "verdict", "openai_compatible", "https://api.deepseek.com",
            "deepseek-v4-pro", "max_tokens", "deepseek_api_key", {}, "admin",
        )
        self.assertNotIn(CLE, requete.sql)
        for param in requete.params:
            self.assertNotIn(CLE, str(param))

    def test_la_requete_ecrit_le_nom_de_fichier_pas_le_contenu(self) -> None:
        requete = queries.set_role_provider(
            "verdict", "openai_compatible", "https://api.deepseek.com",
            "deepseek-v4-pro", "max_tokens", "deepseek_api_key", {}, "admin",
        )
        self.assertIn("deepseek_api_key", [str(p) for p in requete.params])
        self.assertIn("llm_role_providers", requete.sql)

    def test_un_preset_inconnu_est_refuse(self) -> None:
        from sentimail_admin.naming import SaisieInvalide

        with self.assertRaises(SaisieInvalide):
            normalize_preset("gemini")


class NormalisationTests(unittest.TestCase):
    def test_les_presets_courants_sont_acceptes(self) -> None:
        for saisie, attendu in (
            ("deepseek", "deepseek"),
            ("DeepSeek", "deepseek"),
            ("anthropic", "anthropic"),
            ("openai", "openai"),
        ):
            with self.subTest(saisie=saisie):
                self.assertEqual(normalize_preset(saisie), attendu)

    def test_une_saisie_inconnue_est_refusee(self) -> None:
        from sentimail_admin.naming import SaisieInvalide

        with self.assertRaises(SaisieInvalide):
            normalize_preset("gemini")


class PageSansFuiteTests(unittest.TestCase):
    """Une clé affichée est une clé perdue."""

    def test_le_formulaire_masque_la_saisie(self) -> None:
        page = pages.page_reglages_moteur(None)
        self.assertIn('type="password"', page)

    def test_le_formulaire_est_en_post(self) -> None:
        page = pages.page_reglages_moteur(None)
        self.assertIn('method="post"', page.casefold())

    def test_la_cle_n_est_jamais_reaffichee(self) -> None:
        # Même après enregistrement, la page ne montre que le fournisseur et
        # la date : le champ repart vide.
        page = pages.page_reglages_moteur(
            [
                {"role": "verdict", "provider": "openai_compatible",
                 "model_name": "deepseek-v4-pro",
                 "configured_by": "admin_console:100.64.0.1",
                 "validated_at": "2026-08-18T23:00:00+00:00"},
                {"role": "conversation", "provider": "openai_compatible",
                 "model_name": "deepseek-v4-pro",
                 "configured_by": "admin_console:100.64.0.1",
                 "validated_at": "2026-08-18T23:00:00+00:00"},
            ]
        )
        self.assertNotIn(CLE, page)
        self.assertIn("deepseek-v4-pro", page)

    def test_la_page_dit_qui_a_configure_et_quand(self) -> None:
        page = pages.page_reglages_moteur(
            [
                # base_url présente : c'est ce qui distingue une vraie ligne
                # de llm_role_providers (colonne NOT NULL) du repère
                # synthétique {"role", "secret_pose"} posé par /reglages
                # quand aucune configuration n'existe pour ce rôle.
                {"role": "verdict", "provider": "openai_compatible",
                 "base_url": "https://api.deepseek.com",
                 "model_name": "deepseek-v4-pro",
                 "configured_by": "admin_console:100.64.0.1",
                 "validated_at": "2026-08-18T23:00:00+00:00"},
            ]
        )
        self.assertIn("100.64.0.1", page)

    def test_sans_configuration_la_page_le_dit(self) -> None:
        self.assertIn("aucun", pages.page_reglages_moteur(None).casefold())
        self.assertIn("aucun", pages.page_reglages_moteur([]).casefold())


class AucuneRelectureTests(unittest.TestCase):
    """Une capacite de lecture non utilisee finit par l'etre.

    La console recoit le droit d'ecrire dans le volume des secrets. Rien dans
    son code ne doit pouvoir les relire : ni ouverture en lecture, ni listage
    du dossier, ni requete qui remonterait un contenu de fichier.
    """

    def test_le_module_des_secrets_n_a_aucun_chemin_de_lecture(self) -> None:
        import inspect

        from sentimail_admin import secrets

        source = inspect.getsource(secrets)
        for interdit in ("read_text(", "read_bytes(", "listdir(", "iterdir(", '"r"'):
            with self.subTest(appel=interdit):
                self.assertNotIn(interdit, source)

    def test_seul_le_module_des_secrets_touche_au_dossier(self) -> None:
        # Si un autre module lisait provider_secrets_dir, il pourrait relire
        # ce que la console vient d'ecrire.
        import pathlib

        racine = pathlib.Path(__file__).resolve().parents[1] / "src" / "sentimail_admin"
        porteurs = [
            f.name
            for f in racine.glob("*.py")
            if "provider_secrets_dir" in f.read_text(encoding="utf-8")
        ]
        self.assertEqual(sorted(porteurs), ["app.py", "config.py"])

    def test_la_cle_n_est_jamais_journalisee(self) -> None:
        import inspect

        from sentimail_admin import app

        source = inspect.getsource(app)
        # Le champ « cle » ne doit apparaitre que pour etre lu du formulaire
        # et transmis a l'ecriture, jamais dans un log ni un audit.
        for ligne in source.splitlines():
            if "logger" in ligne or "details=" in ligne:
                with self.subTest(ligne=ligne.strip()[:50]):
                    self.assertNotIn('champs.get("cle")', ligne)

    def test_la_route_d_enregistrement_est_en_post(self) -> None:
        from sentimail_admin import app

        routes = {r.path: getattr(r, "methods", None) for r in app.routes}
        self.assertIn("/reglages/moteur", routes)
        self.assertIn("POST", routes["/reglages/moteur"] or [])


if __name__ == "__main__":
    unittest.main()
