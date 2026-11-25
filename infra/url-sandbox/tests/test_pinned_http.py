from __future__ import annotations

import asyncio
from typing import Any

import pinned_http
import pytest
from url_policy import validate_url


class FakeWriter:
    def __init__(self, peer_ip: str) -> None:
        self.peer_ip = peer_ip
        self.written = bytearray()

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        return None

    def get_extra_info(self, name: str) -> object:
        return (self.peer_ip, 443) if name == "peername" else None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


async def test_connects_to_pinned_ip_with_original_host_and_sni(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK")
    reader.feed_eof()
    writer = FakeWriter("93.184.216.34")
    captured: dict[str, Any] = {}

    async def fake_open_connection(**kwargs: Any) -> tuple[asyncio.StreamReader, FakeWriter]:
        captured.update(kwargs)
        return reader, writer

    monkeypatch.setattr(pinned_http.asyncio, "open_connection", fake_open_connection)
    target = validate_url("https://example.com/login")
    response = await pinned_http.request_pinned(
        target,
        ("93.184.216.34",),
        body_limit=1024,
        image_limit=1024,
        decode_qr=False,
    )

    assert captured["host"] == "93.184.216.34"
    assert captured["server_hostname"] == "example.com"
    assert b"Host: example.com\r\n" in writer.written
    assert response.peer_ip == "93.184.216.34"
    assert response.body == b"OK"


async def test_stops_reading_at_body_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789")
    reader.feed_eof()
    writer = FakeWriter("93.184.216.34")

    async def fake_open_connection(**_kwargs: Any) -> tuple[asyncio.StreamReader, FakeWriter]:
        return reader, writer

    monkeypatch.setattr(pinned_http.asyncio, "open_connection", fake_open_connection)
    response = await pinned_http.request_pinned(
        validate_url("http://93.184.216.34/"),
        ("93.184.216.34",),
        body_limit=4,
        image_limit=4,
        decode_qr=False,
    )
    assert response.body == b"0123"
    assert response.truncated is True


class MuteWriter(FakeWriter):
    """Un pair qui n'envoie jamais son close_notify.

    C'est le comportement observe en production sur les destinations de
    redirection publicitaire : la connexion TLS est acceptee, puis plus rien.
    asyncio attend alors son propre plafond de fermeture SSL - trente secondes -
    et cette attente a lieu APRES l'annulation du saut, donc hors de tout
    plafond. Le plafond de cinq secondes par saut devenait trente-cinq.
    """

    def __init__(self, peer_ip: str) -> None:
        super().__init__(peer_ip)
        self.fermeture_demandee = False

    def close(self) -> None:
        self.fermeture_demandee = True

    async def wait_closed(self) -> None:
        await asyncio.sleep(30)


async def test_la_fermeture_dun_pair_muet_est_bornee(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK")
    reader.feed_eof()
    writer = MuteWriter("93.184.216.34")

    async def fake_open_connection(**kwargs: Any) -> tuple[Any, Any]:
        return reader, writer

    monkeypatch.setattr(pinned_http.asyncio, "open_connection", fake_open_connection)

    target = validate_url("https://exemple.test/")
    debut = asyncio.get_running_loop().time()
    await pinned_http.request_pinned(
        target,
        ("93.184.216.34",),
        body_limit=1024,
        image_limit=1024,
        decode_qr=False,
    )
    ecoule = asyncio.get_running_loop().time() - debut

    assert writer.fermeture_demandee, "la connexion doit etre fermee"
    assert ecoule < pinned_http.CLOSE_TIMEOUT + 1, (
        f"la fermeture n'est pas bornee : {ecoule:.1f}s"
    )


async def test_le_plafond_du_saut_reste_tenu_malgre_un_pair_muet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Le vrai symptome : un plafond de saut qui ne tient plus.

    Le pair accepte la connexion puis ne repond jamais. Le saut doit rendre la
    main au plafond demande, pas trente secondes plus tard.
    """
    reader = asyncio.StreamReader()  # jamais alimente : le pair reste muet
    writer = MuteWriter("93.184.216.34")

    async def fake_open_connection(**kwargs: Any) -> tuple[Any, Any]:
        return reader, writer

    monkeypatch.setattr(pinned_http.asyncio, "open_connection", fake_open_connection)

    target = validate_url("https://exemple.test/")
    debut = asyncio.get_running_loop().time()
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.2):
            await pinned_http.request_pinned(
                target,
                ("93.184.216.34",),
                body_limit=1024,
                image_limit=1024,
                decode_qr=False,
            )
    ecoule = asyncio.get_running_loop().time() - debut
    assert ecoule < 0.2 + pinned_http.CLOSE_TIMEOUT + 1, (
        f"le plafond du saut n'est pas tenu : {ecoule:.1f}s"
    )


async def test_l_identite_du_profil_part_reellement_sur_le_fil(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preuve au niveau de l'octet : ce que le site distant recevra.

    Le reste - profils nommes, comparaison structurelle - ne vaut rien si les
    deux requetes partent avec la meme identite. C'est la seule verification qui
    regarde les octets ecrits sur la socket.
    """
    envois: dict[str, bytes] = {}
    for profil in ("scanner", "browser"):
        reader = asyncio.StreamReader()
        reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nOK")
        reader.feed_eof()
        writer = FakeWriter("93.184.216.34")

        async def fake_open_connection(**kwargs: Any) -> tuple[Any, Any]:
            return reader, writer

        monkeypatch.setattr(pinned_http.asyncio, "open_connection", fake_open_connection)
        await pinned_http.request_pinned(
            validate_url("https://exemple.test/"),
            ("93.184.216.34",),
            body_limit=1024,
            image_limit=1024,
            decode_qr=False,
            profile=profil,
        )
        envois[profil] = bytes(writer.written)

    scanner = envois["scanner"].decode("ascii")
    navigateur = envois["browser"].decode("ascii")

    assert "User-Agent: Mozilla/5.0 (compatible)" in scanner
    assert "Mozilla/5.0" in navigateur
    assert "sentimail-sandbox" not in navigateur
    assert "Accept-Language: fr-FR" in navigateur
    assert "Accept-Language" not in scanner
    # Une seule ligne User-Agent : deux rendraient la requete ambigue.
    assert navigateur.count("User-Agent:") == 1
    # Le Host reste celui du nom d'origine, quel que soit le profil.
    assert "Host: exemple.test" in scanner
    assert "Host: exemple.test" in navigateur


async def test_la_fermeture_abandonnee_ne_pollue_pas_les_journaux(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Une fermeture qui echoue en arriere-plan ne doit rien journaliser.

    Borner l'attente laisse une tache courir seule. Si personne ne recupere son
    exception, asyncio journalise une trace complete a chaque pair muet - et du
    bruit dans les journaux est precisement ce qui masque les vrais problemes.
    """
    reader = asyncio.StreamReader()
    reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK")
    reader.feed_eof()

    class WriterQuiEchoueALaFermeture(FakeWriter):
        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            await asyncio.sleep(0.05)
            raise TimeoutError("SSL shutdown timed out")

    writer = WriterQuiEchoueALaFermeture("93.184.216.34")

    async def fake_open_connection(**kwargs: Any) -> tuple[Any, Any]:
        return reader, writer

    monkeypatch.setattr(pinned_http.asyncio, "open_connection", fake_open_connection)
    monkeypatch.setattr(pinned_http, "CLOSE_TIMEOUT", 0.01)

    await pinned_http.request_pinned(
        validate_url("https://exemple.test/"),
        ("93.184.216.34",),
        body_limit=1024,
        image_limit=1024,
        decode_qr=False,
    )
    # On laisse la tache abandonnee finir puis etre ramassee.
    await asyncio.sleep(0.2)
    import gc

    gc.collect()
    await asyncio.sleep(0)

    bruit = [
        enregistrement.getMessage()
        for enregistrement in caplog.records
        if "never retrieved" in enregistrement.getMessage()
    ]
    assert not bruit, f"exception non recuperee journalisee : {bruit}"


async def test_un_point_est_legal_dans_un_nom_d_en_tete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Netflix renvoie « X-Netflix.nfstatus », et la norme l'autorise.

    Un nom d'en-tete est un « token » (RFC 9110 5.6.2) : lettres, chiffres et
    les signes ! # $ % & ' * + - . ^ _ ` | ~ . N'accepter que l'alphanumerique
    et le tiret faisait rejeter la reponse entiere de netflix.com - donc
    echouer l'analyse du message, donc retenir des courriers authentifies dont
    les codes de connexion, qui n'arrivaient jamais.
    """
    reader = asyncio.StreamReader()
    reader.feed_data(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"X-Netflix.nfstatus: 1_1\r\n"
        b"x-netflix.proxy.execution-time: 640\r\n"
        b"Content-Length: 2\r\n\r\nOK"
    )
    reader.feed_eof()
    writer = FakeWriter("93.184.216.34")

    async def fake_open_connection(**kwargs: Any) -> tuple[asyncio.StreamReader, FakeWriter]:
        return reader, writer

    monkeypatch.setattr(pinned_http.asyncio, "open_connection", fake_open_connection)
    response = await pinned_http.request_pinned(
        validate_url("https://example.com/browse"),
        ("93.184.216.34",),
        body_limit=1024,
        image_limit=1024,
        decode_qr=False,
    )
    assert response.status == 200
    assert response.headers["x-netflix.nfstatus"] == "1_1"


async def test_un_nom_d_en_tete_reellement_invalide_reste_refuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Elargir le jeu de caracteres ne doit pas ouvrir la porte a tout."""
    reader = asyncio.StreamReader()
    reader.feed_data(b"HTTP/1.1 200 OK\r\nBad Header: x\r\nContent-Length: 2\r\n\r\nOK")
    reader.feed_eof()
    writer = FakeWriter("93.184.216.34")

    async def fake_open_connection(**kwargs: Any) -> tuple[asyncio.StreamReader, FakeWriter]:
        return reader, writer

    monkeypatch.setattr(pinned_http.asyncio, "open_connection", fake_open_connection)
    with pytest.raises(pinned_http.HttpProtocolError):
        await pinned_http.request_pinned(
            validate_url("https://example.com/x"),
            ("93.184.216.34",),
            body_limit=1024,
            image_limit=1024,
            decode_qr=False,
        )


async def test_l_erreur_rendue_est_celle_qui_explique(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Une panne de reseau ne doit pas masquer un refus applicatif.

    Les adresses sont essayees dans l'ordre rendu par le resolveur, IPv6
    comprises alors que l'hote n'a pas d'IPv6. En rendant la DERNIERE erreur,
    la sandbox rapportait « Network is unreachable » quand la vraie cause etait
    un en-tete refuse sur l'IPv4 : le diagnostic partait sur le reseau pendant
    que le defaut etait ailleurs.
    """
    essais: list[str] = []

    async def fake_open_connection(**kwargs: Any) -> tuple[asyncio.StreamReader, FakeWriter]:
        adresse = str(kwargs.get("host"))
        essais.append(adresse)
        if ":" in adresse:
            raise OSError(101, "Network is unreachable")
        reader = asyncio.StreamReader()
        reader.feed_data(b"HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n")
        reader.feed_eof()
        return reader, FakeWriter(adresse)

    monkeypatch.setattr(pinned_http.asyncio, "open_connection", fake_open_connection)
    with pytest.raises(pinned_http.HttpProtocolError):
        await pinned_http.request_pinned(
            validate_url("https://example.com/x"),
            ("93.184.216.34", "2a00:86c0:2042::1"),
            body_limit=1024,
            image_limit=1024,
            decode_qr=False,
        )
