from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

from sentimail_admin.app import SECURITY_HEADERS, create_app
from sentimail_admin.config import (
    ConfigurationInvalide,
    Settings,
    is_tailscale_address,
    resolve_bind_host,
)
from sentimail_admin.http_guard import (
    CorpsTropGrand,
    MAX_FORM_BODY_BYTES,
    OrigineRefusee,
    check_content_length,
    check_same_origin,
    check_trusted_host,
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


class HoteDeConfianceTests(unittest.TestCase):
    def test_sans_origines_configurees_tout_hote_passe(self) -> None:
        check_trusted_host({"host": "testserver"}, (), path="/domaines", peer="127.0.0.1")
        check_trusted_host({"host": "admin:8093"}, (), path="/domaines", peer="172.21.0.5")

    def test_en_production_un_hote_autorise_passe(self) -> None:
        configurees = ("https://sentinel.mondomaine.example", "http://100.64.0.10:8093")
        check_trusted_host(
            {"host": "sentinel.mondomaine.example"},
            configurees,
            path="/domaines",
            peer="100.64.0.7",
        )
        check_trusted_host(
            {"Host": "100.64.0.10:8093"},
            configurees,
            path="/domaines",
            peer="100.64.0.7",
        )

    def test_en_production_un_hote_interne_data_net_est_refuse(self) -> None:
        configurees = ("https://sentinel.mondomaine.example",)
        for hote in ("admin:8093", "sentimail-v3-admin:8093", "172.21.0.2:8093", ""):
            with self.subTest(hote=hote), self.assertRaises(OrigineRefusee):
                check_trusted_host(
                    {"host": hote} if hote else {},
                    configurees,
                    path="/domaines",
                    peer="172.21.0.5",
                )

    def test_sante_depuis_boucle_locale_passe_meme_avec_hote_local(self) -> None:
        configurees = ("https://sentinel.mondomaine.example",)
        check_trusted_host(
            {"host": "127.0.0.1:8093"},
            configurees,
            path="/sante",
            peer="127.0.0.1",
        )

    def test_sante_depuis_un_autre_conteneur_reste_refuse(self) -> None:
        configurees = ("https://sentinel.mondomaine.example",)
        with self.assertRaises(OrigineRefusee):
            check_trusted_host(
                {"host": "admin:8093"},
                configurees,
                path="/sante",
                peer="172.21.0.5",
            )

    def test_autre_route_depuis_boucle_locale_avec_mauvais_hote_est_refusee(self) -> None:
        configurees = ("https://sentinel.mondomaine.example",)
        with self.assertRaises(OrigineRefusee):
            check_trusted_host(
                {"host": "127.0.0.1:8093"},
                configurees,
                path="/domaines",
                peer="127.0.0.1",
            )


class TailleFormulaireTests(unittest.TestCase):
    def test_content_length_dans_la_limite_passe(self) -> None:
        check_content_length({"content-length": str(MAX_FORM_BODY_BYTES)})

    def test_content_length_trop_grand_est_refuse(self) -> None:
        with self.assertRaises(CorpsTropGrand):
            check_content_length({"Content-Length": str(MAX_FORM_BODY_BYTES + 1)})

    def test_parse_form_refuse_un_corps_trop_grand(self) -> None:
        with self.assertRaises(CorpsTropGrand):
            parse_form(
                "application/x-www-form-urlencoded",
                b"a=" + b"x" * MAX_FORM_BODY_BYTES,
            )


async def _asgi_request(
    app: Any,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    client: tuple[str, int] = ("100.64.0.7", 12345),
) -> tuple[int, dict[str, str], bytes]:
    raw_headers = [
        (k.lower().encode("latin-1"), v.encode("latin-1"))
        for k, v in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": b"",
        "headers": raw_headers,
        "client": client,
        "server": ("testserver", 80),
    }
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    status = 0
    resp_headers: dict[str, str] = {}
    chunks: list[bytes] = []

    async def send(message: dict[str, Any]) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
            for k, v in message.get("headers", []):
                resp_headers[k.decode("latin-1").lower()] = v.decode("latin-1")
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    await app(scope, receive, send)
    return status, resp_headers, b"".join(chunks)


def _settings(trusted_origins: tuple[str, ...] = ()) -> Settings:
    return Settings(
        database_url="postgresql://unused/unused",
        bind_host="127.0.0.1",
        bind_port=8093,
        trusted_origins=trusted_origins,
        trusted_proxies=frozenset(),
        messages_limit=100,
        events_limit=50,
        provider_secrets_dir="/tmp",
    )


class MiddlewareSecuriteTests(unittest.IsolatedAsyncioTestCase):
    def _assert_security_headers(self, headers: dict[str, str]) -> None:
        for name, expected in SECURITY_HEADERS:
            self.assertEqual(headers.get(name.lower()), expected)

    async def test_les_en_tetes_de_securite_sont_presents_sur_get(self) -> None:
        app = create_app(_settings())
        app.state.pool = SimpleNamespace(fetchval=AsyncMock(return_value=1))
        status, headers, _ = await _asgi_request(
            app, "GET", "/sante", headers={"host": "testserver"}
        )
        self.assertEqual(status, 200)
        self._assert_security_headers(headers)

    async def test_hote_non_autorise_renvoie_403_avec_en_tetes_de_securite(self) -> None:
        app = create_app(_settings(("https://sentinel.mondomaine.example",)))
        app.state.pool = SimpleNamespace(fetchval=AsyncMock(return_value=1))
        status, headers, _ = await _asgi_request(
            app,
            "GET",
            "/sante",
            headers={"host": "admin:8093"},
            client=("172.21.0.5", 44444),
        )
        self.assertEqual(status, 403)
        self._assert_security_headers(headers)

    async def test_sante_boucle_locale_renvoie_200_meme_en_production(self) -> None:
        app = create_app(_settings(("https://sentinel.mondomaine.example",)))
        app.state.pool = SimpleNamespace(fetchval=AsyncMock(return_value=1))
        status, headers, _ = await _asgi_request(
            app,
            "GET",
            "/sante",
            headers={"host": "127.0.0.1:8093"},
            client=("127.0.0.1", 44444),
        )
        self.assertEqual(status, 200)
        self._assert_security_headers(headers)

    async def test_post_trop_volumineux_par_content_length_renvoie_413(self) -> None:
        app = create_app(_settings())
        status, headers, _ = await _asgi_request(
            app,
            "POST",
            "/domaines/ajouter",
            headers={
                "host": "testserver",
                "origin": "http://testserver",
                "content-type": "application/x-www-form-urlencoded",
                "content-length": str(MAX_FORM_BODY_BYTES + 10),
            },
            body=b"fqdn=exemple.fr",
        )
        self.assertEqual(status, 413)
        self._assert_security_headers(headers)

    async def test_post_trop_volumineux_sans_content_length_renvoie_413(self) -> None:
        app = create_app(_settings())
        status, headers, _ = await _asgi_request(
            app,
            "POST",
            "/domaines/ajouter",
            headers={
                "host": "testserver",
                "origin": "http://testserver",
                "content-type": "application/x-www-form-urlencoded",
            },
            body=b"fqdn=" + b"a" * (MAX_FORM_BODY_BYTES + 1),
        )
        self.assertEqual(status, 413)
        self._assert_security_headers(headers)


if __name__ == "__main__":
    unittest.main()
