from __future__ import annotations

import socket

import pytest
from url_policy import BlockedUrlError, resolve_global_addresses, validate_url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/admin",
        "http://10.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
        "http://224.0.0.1/",
        "http://[ff0e::1]/",
        "http://[fec0::1]/",
        "http://[2002:7f00:1::1]/",
        "http://[64:ff9b::7f00:1]/",
        "http://[64:ff9b::e000:1]/",
    ],
)
async def test_rejects_non_global_ipv4_ipv6_and_embedded_addresses(url: str) -> None:
    with pytest.raises(BlockedUrlError):
        await resolve_global_addresses(validate_url(url))


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://93.184.216.34/", "93.184.216.34"),
        ("https://[2001:4860:4860::8888]/", "2001:4860:4860::8888"),
    ],
)
async def test_accepts_global_ipv4_and_ipv6_literals(url: str, expected: str) -> None:
    assert await resolve_global_addresses(validate_url(url)) == (expected,)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/file",
        "file:///etc/passwd",
        "http://user:secret@example.com/",
        "https://user@example.com/",
        "http://example.com\\@127.0.0.1/",
        "http://[fe80::1%25eth0]/",
        " http://example.com/",
    ],
)
def test_rejects_schemes_credentials_and_ambiguous_hosts(url: str) -> None:
    with pytest.raises(BlockedUrlError):
        validate_url(url)


def test_spaces_in_path_and_query_are_percent_encoded() -> None:
    target = validate_url(
        "https://example.com/Home Improvement?SearchText=Home Improvement"
    )
    assert target.url == (
        "https://example.com/Home%20Improvement?SearchText=Home%20Improvement"
    )
    assert target.request_target == (
        "/Home%20Improvement?SearchText=Home%20Improvement"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://exa mple.com/path",
        "https://example.com\t/path",
        "https://example.com/path\r\nHost:internal",
    ],
)
def test_authority_and_control_characters_remain_rejected(url: str) -> None:
    with pytest.raises(BlockedUrlError, match="invalid_characters"):
        validate_url(url)


async def test_rejects_mixed_public_private_dns_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = validate_url("https://mixed.example/path")
    loop = __import__("asyncio").get_running_loop()

    async def fake_getaddrinfo(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443)),
        ]

    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(BlockedUrlError, match="non_global_address"):
        await resolve_global_addresses(target)
