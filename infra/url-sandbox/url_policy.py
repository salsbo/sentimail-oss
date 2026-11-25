"""Validation SSRF stricte et resolution DNS des destinations HTTP."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import quote, urlsplit, urlunsplit

MAX_URL_LENGTH = 4096
_REQUEST_PATH_SAFE = "/%:@!$&'()*+,;=-._~"
_REQUEST_QUERY_SAFE = "/?%:@!$&'()*+,;=-._~"
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")


class BlockedUrlError(ValueError):
    """Destination refusee avant toute ouverture de socket."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    url: str
    scheme: str
    host: str
    port: int
    host_header: str
    request_target: str

    @property
    def use_tls(self) -> bool:
        return self.scheme == "https"


def validate_url(raw_url: str) -> ValidatedTarget:
    """Accepte uniquement une URL HTTP(S) absolue sans userinfo."""
    if not raw_url or len(raw_url) > MAX_URL_LENGTH:
        raise BlockedUrlError("invalid_length")
    # Un espace dans le chemin ou la requête est une URL HTML courante et se
    # normalise sans ambiguïté en %20. En revanche, aucun espace n'est toléré
    # autour de l'URL, dans le schéma ou dans l'autorité ; les contrôles et les
    # antislashs restent interdits partout pour éviter les divergences de parse.
    if raw_url != raw_url.strip() or "\\" in raw_url or any(
        ord(char) < 32 or ord(char) == 127 for char in raw_url
    ):
        raise BlockedUrlError("invalid_characters")
    try:
        parsed = urlsplit(raw_url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise BlockedUrlError("invalid_url") from exc
    if scheme not in {"http", "https"}:
        raise BlockedUrlError("unsupported_scheme")
    if any(char.isspace() for char in parsed.scheme + parsed.netloc):
        raise BlockedUrlError("invalid_characters")
    if not parsed.netloc or hostname is None:
        raise BlockedUrlError("missing_hostname")
    if parsed.username is not None or parsed.password is not None:
        raise BlockedUrlError("credentials_forbidden")
    if "%" in hostname:
        # Refuse les zone IDs IPv6 et les hostnames encodes ambigus.
        raise BlockedUrlError("invalid_hostname")

    host = _normalize_host(hostname)
    resolved_port = port if port is not None else (443 if scheme == "https" else 80)
    if not 1 <= resolved_port <= 65535:
        raise BlockedUrlError("invalid_port")

    default_port = 443 if scheme == "https" else 80
    host_literal = f"[{host}]" if _is_ipv6_literal(host) else host
    host_header = (
        host_literal if resolved_port == default_port else f"{host_literal}:{resolved_port}"
    )
    path = quote(parsed.path or "/", safe=_REQUEST_PATH_SAFE)
    query = quote(parsed.query, safe=_REQUEST_QUERY_SAFE)
    request_target = f"{path}?{query}" if query else path
    normalized_url = urlunsplit(
        (
            scheme,
            host_header,
            path,
            query,
            "",  # Un fragment n'est jamais transmis au serveur distant.
        )
    )
    return ValidatedTarget(
        url=normalized_url,
        scheme=scheme,
        host=host,
        port=resolved_port,
        host_header=host_header,
        request_target=request_target,
    )


async def resolve_global_addresses(target: ValidatedTarget) -> tuple[str, ...]:
    """Resout une fois le host et refuse le hop si une reponse n'est pas globale."""
    literal = _parse_ip(target.host)
    if literal is not None:
        _require_global(literal)
        return (literal.compressed,)

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(
            target.host,
            target.port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except OSError as exc:
        raise BlockedUrlError("dns_resolution_failed") from exc

    addresses: list[str] = []
    for _family, _type, _proto, _canonical, sockaddr in infos:
        address = _parse_ip(str(sockaddr[0]).split("%", 1)[0])
        if address is None:
            raise BlockedUrlError("dns_invalid_address")
        _require_global(address)
        compressed = address.compressed
        if compressed not in addresses:
            addresses.append(compressed)
    if not addresses:
        raise BlockedUrlError("dns_no_addresses")
    return tuple(addresses)


def _normalize_host(hostname: str) -> str:
    host = hostname.rstrip(".").lower()
    if not host or len(host) > 253:
        raise BlockedUrlError("invalid_hostname")
    literal = _parse_ip(host)
    if literal is not None:
        return literal.compressed
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise BlockedUrlError("invalid_hostname") from exc
    labels = ascii_host.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise BlockedUrlError("invalid_hostname")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        raise BlockedUrlError("invalid_hostname")
    if any(not all(char.isalnum() or char == "-" for char in label) for label in labels):
        raise BlockedUrlError("invalid_hostname")
    return ascii_host


def _require_global(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    # ``ipaddress.is_global`` classe encore certains multicast et l'ancien
    # espace IPv6 site-local comme globaux. Ce ne sont pas des destinations
    # unicast Internet acceptables pour un fetcher anti-SSRF.
    if (
        not address.is_global
        or address.is_multicast
        or (isinstance(address, ipaddress.IPv6Address) and address.is_site_local)
    ):
        raise BlockedUrlError("non_global_address")
    if isinstance(address, ipaddress.IPv4Address):
        return

    embedded: list[ipaddress.IPv4Address] = []
    if address.ipv4_mapped is not None:
        embedded.append(address.ipv4_mapped)
    if address.sixtofour is not None:
        embedded.append(address.sixtofour)
    if address.teredo is not None:
        embedded.extend(address.teredo)
    if address in _NAT64_WELL_KNOWN or address in _NAT64_LOCAL:
        embedded.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
    if any(not value.is_global or value.is_multicast for value in embedded):
        raise BlockedUrlError("embedded_non_global_address")


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_ipv6_literal(value: str) -> bool:
    parsed = _parse_ip(value)
    return isinstance(parsed, ipaddress.IPv6Address)
