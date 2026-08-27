"""Client HTTP/1.1 minimal connecte a une IP deja validee.

Le hostname original ne repasse jamais dans une resolution implicite : il est
utilise uniquement pour Host, SNI et la verification du certificat TLS.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import ssl
from dataclasses import dataclass
from typing import Final

from url_policy import ValidatedTarget

HEADER_LIMIT_BYTES: Final = 64 * 1024
HEADER_LINE_LIMIT_BYTES: Final = 8 * 1024
HEADER_COUNT_LIMIT: Final = 200
REDIRECT_STATUSES: Final = frozenset({301, 302, 303, 307, 308})
# Fermer une connexion TLS demande au pair un close_notify. Une destination de
# redirection publicitaire accepte la connexion puis se tait : asyncio applique
# alors son propre plafond de fermeture SSL, trente secondes. Cette attente a
# lieu dans le nettoyage, donc APRES l'annulation du saut - elle echappait a
# tout plafond et portait un saut borne a cinq secondes jusqu'a trente-cinq.
# Vingt URL de ce type ont deja fait passer une analyse a dix-neuf minutes.
# Une fermeture propre est un confort, pas un resultat : on lui laisse une
# seconde, puis on passe.
CLOSE_TIMEOUT: Final = 1.0

# Deux identites, et deux seulement. Un site qui pratique le cloaking sert une
# page anodine au scanner et la vraie page au visiteur : le voir demande de
# demander deux fois, sous deux identites, puis de comparer.
#
# Les profils sont nommes et fixes ici. Laisser un appelant composer ses propres
# en-tetes ferait du bac a sable un relais : un contenu d'email pourrait dicter
# ce que la requete sortante contient.
_PROFILES: Final[dict[str, dict[str, str]]] = {
    "scanner": {
        "User-Agent": "sentimail-sandbox/2.0",
        "Accept": "*/*",
    },
    "browser": {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
    },
}


def profile_headers(profile: str) -> dict[str, str]:
    """Les en-tetes d'une identite nommee, jamais composee par l'appelant."""
    entetes = _PROFILES.get(profile)
    if entetes is None:
        raise ValueError(f"profil inconnu : {profile!r}")
    return dict(entetes)


class HttpProtocolError(RuntimeError):
    """Reponse distante non sure ou non prise en charge."""


# Ce qu'un nom d'en-tete a le droit de contenir, en plus de l'alphanumerique :
# la RFC 9110 (5.6.2) en fait un « token ». Le point en fait partie, et
# netflix.com s'en sert - « X-Netflix.nfstatus ». N'accepter que le tiret
# faisait rejeter toute la reponse d'un site parfaitement conforme, donc
# echouer l'analyse du message qui pointait vers lui.
_CARACTERES_DE_JETON = frozenset("!#$%&'*+-.^_`|~")


@dataclass(frozen=True, slots=True)
class HopResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    content_type: str
    size: int
    truncated: bool
    peer_ip: str


async def request_pinned(
    target: ValidatedTarget,
    addresses: tuple[str, ...],
    *,
    body_limit: int,
    image_limit: int,
    decode_qr: bool,
    profile: str = "scanner",
) -> HopResponse:
    """Essaie les IP validees sans jamais redonner le hostname au connecteur."""
    reseau: Exception | None = None
    applicative: Exception | None = None
    for address in addresses:
        try:
            return await _request_address(
                target,
                address,
                body_limit=body_limit,
                image_limit=image_limit,
                decode_qr=decode_qr,
                profile=profile,
            )
        except (OSError, ssl.SSLError, asyncio.IncompleteReadError, HttpProtocolError) as exc:
            if isinstance(exc, HttpProtocolError):
                applicative = applicative or exc
            else:
                reseau = exc
    # L'hote sans IPv6 échoue sur chaque adresse IPv6 que le resolveur propose.
    # Rendre la derniere erreur faisait donc remonter « Network is
    # unreachable » quand l'IPv4, elle, avait bel et bien repondu - et que son
    # refus etait la seule chose a comprendre. Une erreur qui dit ce que le
    # serveur a repondu explique toujours mieux qu'une route manquante.
    if applicative is not None:
        raise applicative
    if reseau is None:
        raise HttpProtocolError("no_validated_address")
    raise reseau


async def _request_address(
    target: ValidatedTarget,
    address: str,
    *,
    body_limit: int,
    image_limit: int,
    decode_qr: bool,
    profile: str = "scanner",
) -> HopResponse:
    ssl_context = ssl.create_default_context() if target.use_tls else None
    reader, writer = await asyncio.open_connection(
        host=address,
        port=target.port,
        ssl=ssl_context,
        server_hostname=target.host if target.use_tls else None,
        limit=HEADER_LIMIT_BYTES + 1,
    )
    try:
        peer_ip = _verified_peer_ip(writer, address)
        identite = "".join(
            f"{cle}: {valeur}\r\n" for cle, valeur in profile_headers(profile).items()
        )
        request = (
            f"GET {target.request_target} HTTP/1.1\r\n"
            f"Host: {target.host_header}\r\n"
            f"{identite}"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(request)
        await writer.drain()

        status, headers = await _read_headers(reader)
        content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if status in REDIRECT_STATUSES or status in {204, 304} or 100 <= status < 200:
            return HopResponse(status, headers, b"", content_type, 0, False, peer_ip)

        limit = image_limit if decode_qr and content_type.startswith("image/") else body_limit
        body, truncated = await _read_body(reader, headers, limit)
        return HopResponse(
            status=status,
            headers=headers,
            body=body,
            content_type=content_type,
            size=len(body),
            truncated=truncated,
            peer_ip=peer_ip,
        )
    finally:
        writer.close()
        # shield : la fermeture doit pouvoir s'achever en arriere-plan sans que
        # notre attente, elle, soit illimitee. Sans lui, wait_for propagerait
        # l'annulation dans une tache deja en cours d'annulation.
        fermeture = asyncio.ensure_future(writer.wait_closed())
        # Passe le plafond, plus personne n'attend ce resultat. Le consommer
        # evite qu'asyncio journalise une trace complete a chaque pair muet :
        # du bruit dans les journaux masque les vrais problemes, et c'est
        # exactement ce qui avait laisse passer trente secondes par URL.
        fermeture.add_done_callback(
            lambda tache: tache.cancelled() or tache.exception()
        )
        with contextlib.suppress(Exception):
            await asyncio.wait_for(asyncio.shield(fermeture), CLOSE_TIMEOUT)


def _verified_peer_ip(writer: asyncio.StreamWriter, expected: str) -> str:
    peer = writer.get_extra_info("peername")
    if not isinstance(peer, tuple) or not peer:
        raise HttpProtocolError("missing_peer_address")
    try:
        actual_ip = ipaddress.ip_address(str(peer[0]).split("%", 1)[0])
        expected_ip = ipaddress.ip_address(expected)
    except ValueError as exc:
        raise HttpProtocolError("invalid_peer_address") from exc
    if actual_ip != expected_ip:
        raise HttpProtocolError("peer_address_mismatch")
    return actual_ip.compressed


async def _read_headers(reader: asyncio.StreamReader) -> tuple[int, dict[str, str]]:
    try:
        raw = await reader.readuntil(b"\r\n\r\n")
    except asyncio.LimitOverrunError as exc:
        raise HttpProtocolError("headers_too_large") from exc
    if len(raw) > HEADER_LIMIT_BYTES:
        raise HttpProtocolError("headers_too_large")
    lines = raw[:-4].split(b"\r\n")
    if not lines or len(lines) - 1 > HEADER_COUNT_LIMIT:
        raise HttpProtocolError("invalid_header_count")
    if len(lines[0]) > HEADER_LINE_LIMIT_BYTES:
        raise HttpProtocolError("status_line_too_large")
    try:
        protocol, raw_status, _reason = lines[0].decode("ascii").split(" ", 2)
        status = int(raw_status)
    except (UnicodeDecodeError, ValueError) as exc:
        raise HttpProtocolError("invalid_status_line") from exc
    if protocol not in {"HTTP/1.0", "HTTP/1.1"} or not 100 <= status <= 599:
        raise HttpProtocolError("invalid_status_line")

    values: dict[str, list[str]] = {}
    for line in lines[1:]:
        if len(line) > HEADER_LINE_LIMIT_BYTES or b":" not in line:
            raise HttpProtocolError("invalid_header")
        raw_name, raw_value = line.split(b":", 1)
        try:
            name = raw_name.decode("ascii").strip().lower()
            value = raw_value.decode("iso-8859-1").strip()
        except UnicodeDecodeError as exc:
            raise HttpProtocolError("invalid_header") from exc
        if not name or not all(
            char.isascii() and (char.isalnum() or char in _CARACTERES_DE_JETON)
            for char in name
        ):
            raise HttpProtocolError("invalid_header_name")
        if any(ord(char) < 32 and char != "\t" for char in value):
            raise HttpProtocolError("invalid_header_value")
        values.setdefault(name, []).append(value)

    content_lengths = values.get("content-length", [])
    if len(set(content_lengths)) > 1:
        raise HttpProtocolError("conflicting_content_length")
    return status, {name: ", ".join(items) for name, items in values.items()}


async def _read_body(
    reader: asyncio.StreamReader,
    headers: dict[str, str],
    limit: int,
) -> tuple[bytes, bool]:
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if transfer_encoding:
        if transfer_encoding != "chunked":
            raise HttpProtocolError("unsupported_transfer_encoding")
        return await _read_chunked(reader, limit)

    content_length = _content_length(headers)
    if content_length is not None:
        wanted = min(content_length, limit + 1)
        payload = await reader.readexactly(wanted) if wanted else b""
        truncated = content_length > limit
        return payload[:limit], truncated
    return await _read_until_eof(reader, limit)


def _content_length(headers: dict[str, str]) -> int | None:
    raw = headers.get("content-length")
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise HttpProtocolError("invalid_content_length") from exc
    if value < 0:
        raise HttpProtocolError("invalid_content_length")
    return value


async def _read_until_eof(reader: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
    output = bytearray()
    while len(output) <= limit:
        chunk = await reader.read(min(64 * 1024, limit + 1 - len(output)))
        if not chunk:
            return bytes(output), False
        output.extend(chunk)
    return bytes(output[:limit]), True


async def _read_chunked(reader: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
    output = bytearray()
    truncated = False
    while True:
        line = await reader.readline()
        if not line or len(line) > 128 or not line.endswith(b"\r\n"):
            raise HttpProtocolError("invalid_chunk_header")
        try:
            size = int(line[:-2].split(b";", 1)[0], 16)
        except ValueError as exc:
            raise HttpProtocolError("invalid_chunk_size") from exc
        if size < 0:
            raise HttpProtocolError("invalid_chunk_size")
        if size == 0:
            await _read_trailers(reader)
            return bytes(output), truncated

        remaining = max(0, limit - len(output))
        keep = min(size, remaining)
        if keep:
            output.extend(await reader.readexactly(keep))
        if size > keep:
            # Fermer la connexion suffit : ne jamais consommer un corps au-dela
            # de la limite, meme sans l'allouer en memoire.
            return bytes(output), True
        if await reader.readexactly(2) != b"\r\n":
            raise HttpProtocolError("invalid_chunk_terminator")


async def _read_trailers(reader: asyncio.StreamReader) -> None:
    consumed = 0
    count = 0
    while True:
        line = await reader.readline()
        consumed += len(line)
        if consumed > HEADER_LIMIT_BYTES or count > HEADER_COUNT_LIMIT:
            raise HttpProtocolError("trailers_too_large")
        if line == b"\r\n":
            return
        if not line or not line.endswith(b"\r\n") or b":" not in line:
            raise HttpProtocolError("invalid_trailer")
        count += 1
