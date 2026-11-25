from __future__ import annotations

import pinned_http
import pytest
import server
from pinned_http import HopResponse
from pydantic import ValidationError
from url_policy import ValidatedTarget
from url_policy import resolve_global_addresses as real_resolve


def _hop(
    status: int = 200,
    *,
    location: str | None = None,
    peer_ip: str = "93.184.216.34",
) -> HopResponse:
    headers = {"location": location} if location is not None else {}
    return HopResponse(status, headers, b"ok", "text/plain", 2, False, peer_ip)


async def test_direct_private_url_is_blocked_without_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connected = False

    async def forbidden_connect(*_args: object, **_kwargs: object) -> HopResponse:
        nonlocal connected
        connected = True
        return _hop()

    monkeypatch.setattr(server, "request_pinned", forbidden_connect)
    result = await server.fetch(server.FetchIn(url="http://127.0.0.1/admin"))
    assert result["error"] == "blocked_url:non_global_address"
    assert result["hops"] == 0
    assert connected is False


@pytest.mark.parametrize(
    "private_location",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/admin",
    ],
)
async def test_redirect_to_private_url_is_revalidated(
    monkeypatch: pytest.MonkeyPatch,
    private_location: str,
) -> None:
    async def fake_resolve(target: ValidatedTarget) -> tuple[str, ...]:
        if target.host == "public.example":
            return ("93.184.216.34",)
        return await real_resolve(target)

    async def fake_request(*_args: object, **_kwargs: object) -> HopResponse:
        return _hop(302, location=private_location)

    monkeypatch.setattr(server, "resolve_global_addresses", fake_resolve)
    monkeypatch.setattr(server, "request_pinned", fake_request)
    result = await server.fetch(server.FetchIn(url="https://public.example/start"))
    assert result["error"] == "blocked_url:non_global_address"
    assert result["hops"] == 1


async def test_network_timeout_is_reported_fail_soft(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(_target: ValidatedTarget) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def timeout(*_args: object, **_kwargs: object) -> HopResponse:
        raise TimeoutError

    monkeypatch.setattr(server, "resolve_global_addresses", fake_resolve)
    monkeypatch.setattr(server, "request_pinned", timeout)
    result = await server.fetch(server.FetchIn(url="https://timeout.example/"))
    assert result["error"] == "hop_timeout"
    assert result["hops"] == 0


async def test_dns_is_resolved_once_then_the_validated_ip_is_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolutions = 0
    connected: list[tuple[str, tuple[str, ...]]] = []

    async def fake_resolve(target: ValidatedTarget) -> tuple[str, ...]:
        nonlocal resolutions
        resolutions += 1
        return ("93.184.216.34",)

    async def fake_request(
        target: ValidatedTarget,
        addresses: tuple[str, ...],
        **_kwargs: object,
    ) -> HopResponse:
        connected.append((target.host, addresses))
        return _hop()

    monkeypatch.setattr(server, "resolve_global_addresses", fake_resolve)
    monkeypatch.setattr(server, "request_pinned", fake_request)
    result = await server.fetch(server.FetchIn(url="https://rebind.example/path"))
    assert result["error"] is None
    assert resolutions == 1
    assert connected == [("rebind.example", ("93.184.216.34",))]
    assert result["chain"][0]["connected_ip"] == "93.184.216.34"


async def test_credentials_are_rejected_and_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    async def forbidden(*_args: object, **_kwargs: object) -> tuple[str, ...]:
        raise AssertionError("DNS must not run")

    monkeypatch.setattr(server, "resolve_global_addresses", forbidden)
    result = await server.fetch(server.FetchIn(url="https://user:secret@example.com/path"))
    assert result["error"] == "blocked_url:credentials_forbidden"
    assert "secret" not in result["initial_url"]


async def test_redirects_are_manually_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(_target: ValidatedTarget) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def fake_request(*_args: object, **_kwargs: object) -> HopResponse:
        return _hop(302, location="/again")

    monkeypatch.setattr(server, "resolve_global_addresses", fake_resolve)
    monkeypatch.setattr(server, "request_pinned", fake_request)
    result = await server.fetch(server.FetchIn(url="https://loop.example/start"))
    assert result["error"] == "too_many_redirects"
    assert result["hops"] == server.MAX_REDIRECTS + 1


def test_qr_decode_failure_does_not_invalidate_the_url_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys
    from types import ModuleType, SimpleNamespace

    def broken_image(*_args: object, **_kwargs: object) -> object:
        raise ValueError("not an image")

    pil = ModuleType("PIL")
    pil.Image = SimpleNamespace(  # type: ignore[attr-defined]
        DecompressionBombWarning=Warning,
        open=broken_image,
    )
    pyzbar = ModuleType("pyzbar")
    pyzbar_decode = ModuleType("pyzbar.pyzbar")
    pyzbar_decode.decode = lambda _image: []  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "PIL", pil)
    monkeypatch.setitem(sys.modules, "pyzbar", pyzbar)
    monkeypatch.setitem(sys.modules, "pyzbar.pyzbar", pyzbar_decode)
    result = server.FetchResult(initial_url="https://example.com/image")
    server._decode_qr(b"not-an-image", result)
    assert result.error is None
    assert result.qr_error is not None
    assert result.qr_error.startswith("qr_decode:")
    assert result.as_dict()["qr_error"] == result.qr_error


class TestProfilsDAcces:
    """Deux profils, pour voir si un site sert deux pages differentes.

    Quarante pour cent des URL de phishing pratiquent le cloaking : elles
    montrent une page anodine au scanner et la vraie page au visiteur. Un seul
    profil ne peut pas voir la difference - il faut demander deux fois, sous
    deux identites, et comparer.

    Le profil est nomme, jamais compose par l'appelant : laisser passer des
    en-tetes arbitraires ferait du bac a sable un relais d'injection.
    """

    def test_le_profil_par_defaut_reste_le_scanner(self) -> None:
        payload = server.FetchIn(url="https://exemple.test/")
        assert payload.profile == "scanner"

    def test_le_profil_navigateur_est_accepte(self) -> None:
        payload = server.FetchIn(url="https://exemple.test/", profile="browser")
        assert payload.profile == "browser"

    def test_un_profil_inconnu_est_refuse(self) -> None:
        with pytest.raises(ValidationError):
            server.FetchIn(url="https://exemple.test/", profile="curl/8")

    def test_aucun_entete_arbitraire_ne_passe(self) -> None:
        # extra="forbid" : un appelant ne compose pas sa propre identite.
        with pytest.raises(ValidationError):
            server.FetchIn(url="https://exemple.test/", headers={"X-Injecte": "1"})

    def test_les_deux_profils_annoncent_des_identites_differentes(self) -> None:
        scanner = pinned_http.profile_headers("scanner")
        navigateur = pinned_http.profile_headers("browser")
        assert scanner["User-Agent"] != navigateur["User-Agent"]
        assert scanner["User-Agent"] == "Mozilla/5.0 (compatible)"
        assert "mozilla" in navigateur["User-Agent"].casefold()
        for profile in (scanner, navigateur):
            assert not any(word in str(profile).casefold() for word in (
                "sentimail", "referer", "from"))

    def test_le_profil_navigateur_demande_du_html_et_une_langue(self) -> None:
        # Un site qui filtre sur l'entete Accept ou la langue doit voir un
        # visiteur credible, sinon la seconde requete ne prouve rien.
        navigateur = pinned_http.profile_headers("browser")
        assert "text/html" in navigateur["Accept"]
        assert navigateur.get("Accept-Language")

    def test_aucun_entete_ne_contient_de_saut_de_ligne(self) -> None:
        # Un en-tete injectable romprait la requete HTTP.
        for nom in ("scanner", "browser"):
            for cle, valeur in pinned_http.profile_headers(nom).items():
                assert "\r" not in cle + valeur
                assert "\n" not in cle + valeur


class TestEmpreinteDeContenu:
    """Comparer deux pages demande une empreinte stable."""

    def test_deux_rendus_identiques_donnent_la_meme_empreinte(self) -> None:
        a = server.content_digest("<html><body><p>Bonjour  le   monde</p></body></html>")
        b = server.content_digest("<html><body>\n<p>Bonjour le monde</p>\n</body></html>")
        assert a == b

    def test_deux_pages_differentes_donnent_des_empreintes_differentes(self) -> None:
        a = server.content_digest("<html><body><p>Connectez-vous</p></body></html>")
        b = server.content_digest("<html><body><p>Page introuvable</p></body></html>")
        assert a != b

    def test_une_page_vide_ne_casse_pas_l_empreinte(self) -> None:
        assert server.content_digest("") == server.content_digest("   ")

    async def test_la_reponse_fetch_normalise_le_texte_et_ignore_scripts(self, monkeypatch):
        async def resolve(_target):
            return ("93.184.216.34",)

        contents = iter((b"<p>Bonjour  le   monde</p><script>bruit</script>",
                         b"<p>Bonjour le monde</p><style>bruit</style>"))

        async def request(*_args, **_kwargs):
            body = next(contents)
            return HopResponse(200, {}, body, "text/html", len(body), False, "93.184.216.34")

        monkeypatch.setattr(server, "resolve_global_addresses", resolve)
        monkeypatch.setattr(server, "request_pinned", request)
        a = await server.fetch(server.FetchIn(url="https://exemple.test/a"))
        b = await server.fetch(server.FetchIn(url="https://exemple.test/a"))
        assert a["content_digest"] == b["content_digest"]
        assert a["content_digest"] == server.content_digest("<p>Bonjour le monde</p>")
