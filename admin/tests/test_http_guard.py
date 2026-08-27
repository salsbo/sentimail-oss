from __future__ import annotations

import unittest

from sentimail_admin.config import (
    ConfigurationInvalide,
    is_tailscale_address,
    resolve_bind_host,
)
from sentimail_admin.http_guard import (
    OrigineRefusee,
    check_same_origin,
    client_ip,
    expected_origins,
    parse_form,
)

CONSOLE = {"host": "sentinel-admin:8093"}


class OrigineTests(unittest.TestCase):
    def test_l_origine_de_la_console_est_acceptee(self) -> None:
        check_same_origin({**CONSOLE, "origin": "http://sentinel-admin:8093"})

    def test_la_casse_de_l_origine_est_indifferente(self) -> None:
        check_same_origin({**CONSOLE, "Origin": "HTTP://Sentinel-Admin:8093"})

    def test_une_origine_etrangere_est_refusee(self) -> None:
        with self.assertRaises(OrigineRefusee):
            check_same_origin({**CONSOLE, "origin": "https://attaquant.example"})

    def test_une_origine_absente_est_refusee(self) -> None:
        with self.assertRaises(OrigineRefusee):
            check_same_origin(dict(CONSOLE))

    def test_une_origine_opaque_retombe_sur_le_referent(self) -> None:
        with self.assertRaises(OrigineRefusee):
            check_same_origin({**CONSOLE, "origin": "null"})

    def test_un_referent_de_la_console_suffit(self) -> None:
        check_same_origin({**CONSOLE, "referer": "http://sentinel-admin:8093/domaines"})

    def test_un_referent_etranger_est_refuse(self) -> None:
        with self.assertRaises(OrigineRefusee):
            check_same_origin({**CONSOLE, "referer": "https://attaquant.example/x"})

    def test_un_hote_absent_est_refuse(self) -> None:
        with self.assertRaises(OrigineRefusee):
            check_same_origin({"origin": "http://sentinel-admin:8093"})

    def test_un_sous_domaine_voisin_ne_passe_pas(self) -> None:
        with self.assertRaises(OrigineRefusee):
            check_same_origin(
                {"host": "admin.mondomaine.example", "origin": "http://admin.mondomaine.example.evil.tld"}
            )

    def test_les_origines_configurees_remplacent_l_hote(self) -> None:
        configurees = ("https://sentinel.mondomaine.example",)
        check_same_origin(
            {"host": "10.0.0.5", "origin": "https://sentinel.mondomaine.example"}, configurees
        )
        with self.assertRaises(OrigineRefusee):
            check_same_origin(
                {"host": "10.0.0.5", "origin": "http://10.0.0.5"}, configurees
            )

    def test_les_origines_attendues_couvrent_les_deux_schemas(self) -> None:
        self.assertEqual(
            expected_origins("sentinel-admin:8093", ()),
            {"http://sentinel-admin:8093", "https://sentinel-admin:8093"},
        )


class FormulaireTests(unittest.TestCase):
    def test_un_formulaire_urlencode_est_lu(self) -> None:
        champs = parse_form(
            "application/x-www-form-urlencoded; charset=utf-8",
            b"fqdn=mondomaine.example&admin_email=operateur%40mondomaine.example",
        )
        self.assertEqual(
            champs, {"fqdn": "mondomaine.example", "admin_email": "operateur@mondomaine.example"}
        )

    def test_un_champ_vide_est_conserve(self) -> None:
        champs = parse_form("application/x-www-form-urlencoded", b"admin_email=")
        self.assertEqual(champs, {"admin_email": ""})

    def test_les_autres_types_sont_refuses(self) -> None:
        for type_media in (
            "text/plain",
            "multipart/form-data",
            "application/json",
            None,
        ):
            with self.subTest(type_media=type_media), self.assertRaises(OrigineRefusee):
                parse_form(type_media, b"fqdn=mondomaine.example")


class AdresseAppelanteTests(unittest.TestCase):
    def test_l_adresse_du_pair_est_retenue(self) -> None:
        self.assertEqual(client_ip("100.64.0.7", {}), "100.64.0.7")

    def test_un_en_tete_transfere_est_ignore_sans_relais_declare(self) -> None:
        self.assertEqual(
            client_ip("100.64.0.7", {"x-forwarded-for": "1.2.3.4"}), "100.64.0.7"
        )

    def test_un_relais_declare_est_cru(self) -> None:
        self.assertEqual(
            client_ip(
                "172.20.0.1",
                {"X-Forwarded-For": "100.64.0.7, 172.20.0.1"},
                frozenset({"172.20.0.1"}),
            ),
            "100.64.0.7",
        )

    def test_un_en_tete_transfere_illisible_retombe_sur_le_pair(self) -> None:
        self.assertEqual(
            client_ip(
                "172.20.0.1",
                {"x-forwarded-for": "pas-une-ip"},
                frozenset({"172.20.0.1"}),
            ),
            "172.20.0.1",
        )

    def test_une_adresse_absente_reste_tracee(self) -> None:
        self.assertEqual(client_ip(None, {}), "inconnue")
        self.assertEqual(client_ip("socket-unix", {}), "inconnue")


class AdresseEcouteTests(unittest.TestCase):
    def test_la_plage_tailscale_est_reconnue(self) -> None:
        self.assertTrue(is_tailscale_address("100.64.0.1"))
        self.assertTrue(is_tailscale_address("100.127.255.254"))
        # Juste au-delà de la plage CGNAT, pour éprouver la frontière.
        self.assertFalse(is_tailscale_address("100.128.0.1"))  # audit-ok: hors plage, aucun abonné
        self.assertFalse(is_tailscale_address("192.168.50.73"))
        self.assertFalse(is_tailscale_address("pas-une-ip"))

    def test_une_adresse_explicite_est_respectee(self) -> None:
        self.assertEqual(
            resolve_bind_host({"ADMIN_BIND_HOST": " 100.64.0.7 "}), "100.64.0.7"
        )

    def test_ecouter_partout_est_refuse_par_defaut(self) -> None:
        for valeur in ("0.0.0.0", "::", "*"):
            with self.subTest(valeur=valeur), self.assertRaises(ConfigurationInvalide):
                resolve_bind_host({"ADMIN_BIND_HOST": valeur})

    def test_ecouter_partout_exige_un_choix_explicite(self) -> None:
        self.assertEqual(
            resolve_bind_host(
                {"ADMIN_BIND_HOST": "0.0.0.0", "ADMIN_BIND_UNRESTRICTED": "true"}
            ),
            "0.0.0.0",
        )

    def test_sans_tailnet_le_service_refuse_de_deviner(self) -> None:
        from sentimail_admin import config

        original = config.discover_tailscale_address
        config.discover_tailscale_address = lambda *args, **kwargs: None
        try:
            with self.assertRaises(ConfigurationInvalide):
                resolve_bind_host({})
        finally:
            config.discover_tailscale_address = original

    def test_l_adresse_tailscale_sert_de_defaut(self) -> None:
        from sentimail_admin import config

        original = config.discover_tailscale_address
        config.discover_tailscale_address = lambda *args, **kwargs: "100.64.0.7"
        try:
            self.assertEqual(resolve_bind_host({}), "100.64.0.7")
        finally:
            config.discover_tailscale_address = original


if __name__ == "__main__":
    unittest.main()
