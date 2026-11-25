"""Sandbox HTTP anti-SSRF pour l'analyse reproductible des URLs d'email."""

from __future__ import annotations

import asyncio
import hashlib
import io
import os
import re
import warnings
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup
from domain_name import registrable_domain
from fastapi import FastAPI
from pinned_http import REDIRECT_STATUSES, HopResponse, request_pinned
from pydantic import BaseModel, ConfigDict, Field
from url_policy import BlockedUrlError, resolve_global_addresses, validate_url

MAX_REDIRECTS = 8
PER_HOP_TIMEOUT = 5.0
TOTAL_TIMEOUT = 40.0
BODY_LIMIT_BYTES = 256 * 1024
IMG_LIMIT_BYTES = 2 * 1024 * 1024
MAX_IMAGE_PIXELS = 20_000_000


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


_fetch_slots = asyncio.Semaphore(_positive_int_env("URL_FETCH_CONCURRENCY", 8))

app = FastAPI(title="sentimail url-sandbox", version="0.2.1")


class FetchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=4096)
    decode_qr: bool = False
    # Nomme, jamais compose : voir pinned_http._PROFILES.
    profile: Literal["scanner", "browser"] = "scanner"


@dataclass(slots=True)
class FetchResult:
    initial_url: str
    initial_host: str = ""
    final_host: str = ""
    final_status: int | None = None
    chain: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    body_excerpt: str = ""
    visible_links: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    qr_codes: list[str] = field(default_factory=list)
    qr_error: str | None = None
    profile: str = "scanner"
    content_digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        initial_apex = registrable_domain(self.initial_host)
        final_apex = registrable_domain(self.final_host)
        return {
            "initial_url": self.initial_url,
            "initial_host": self.initial_host,
            "final_host": self.final_host,
            "initial_apex": initial_apex,
            "final_apex": final_apex,
            "final_status": self.final_status,
            "hops": len(self.chain),
            "chain": self.chain,
            "cloaking": bool(initial_apex and final_apex and initial_apex != final_apex),
            "same_apex_redirect": bool(
                self.initial_host
                and self.final_host
                and self.initial_host != self.final_host
                and initial_apex == final_apex
            ),
            "error": self.error,
            "profile": self.profile,
            "content_digest": self.content_digest,
            "body_excerpt": self.body_excerpt,
            "visible_links": self.visible_links[:30],
            "forms": self.forms[:5],
            "qr_codes": self.qr_codes,
            # Le QR est un enrichissement facultatif. Son décodeur peut ne pas
            # reconnaître une image parfaitement inspectée : cela ne transforme
            # jamais le fetch HTTP réussi en analyse incomplète.
            "qr_error": self.qr_error,
        }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/fetch")
async def fetch(payload: FetchIn) -> dict[str, Any]:
    """Suit manuellement chaque hop, toujours resolu puis connecte sur IP."""
    result = FetchResult(
        initial_url=_redact_url(payload.url), profile=payload.profile
    )
    try:
        async with asyncio.timeout(TOTAL_TIMEOUT):
            async with _fetch_slots:
                await _fetch_chain(payload, result)
    except TimeoutError:
        result.error = "sandbox_total_timeout"
    except Exception as exc:  # fail-soft : le pipeline recoit une preuve d'indisponibilite
        result.error = f"unexpected:{type(exc).__name__}"
    return result.as_dict()


async def _fetch_chain(payload: FetchIn, result: FetchResult) -> None:
    current = payload.url
    for hop_index in range(MAX_REDIRECTS + 1):
        try:
            target = validate_url(current)
        except BlockedUrlError as exc:
            result.error = f"blocked_url:{exc.code}"
            return
        if hop_index == 0:
            result.initial_url = target.url
            result.initial_host = target.host

        try:
            async with asyncio.timeout(PER_HOP_TIMEOUT):
                addresses = await resolve_global_addresses(target)
                response = await request_pinned(
                    target,
                    addresses,
                    body_limit=BODY_LIMIT_BYTES,
                    image_limit=IMG_LIMIT_BYTES,
                    decode_qr=payload.decode_qr,
                    profile=payload.profile,
                )
        except BlockedUrlError as exc:
            result.error = f"blocked_url:{exc.code}"
            return
        except TimeoutError:
            result.error = "hop_timeout"
            return
        except Exception as exc:
            result.error = f"fetch_error:{type(exc).__name__}"
            return

        _record_hop(result, target.url, target.host, response)
        if response.status not in REDIRECT_STATUSES:
            _analyze_final(response, payload.decode_qr, result)
            return

        location = response.headers.get("location")
        if not location:
            result.error = "redirect_without_location"
            return
        if hop_index >= MAX_REDIRECTS:
            result.error = "too_many_redirects"
            return
        current = urljoin(target.url, location)


def _record_hop(
    result: FetchResult,
    url: str,
    host: str,
    response: HopResponse,
) -> None:
    result.chain.append(
        {
            "url": url,
            "status": response.status,
            "host": host,
            "connected_ip": response.peer_ip,
            "content_type": response.content_type,
            "size": response.size,
            "truncated": response.truncated,
        }
    )
    result.final_status = response.status
    result.final_host = host


def _analyze_final(response: HopResponse, decode_qr: bool, result: FetchResult) -> None:
    if response.content_type.startswith("text/html"):
        _analyze_html(response.body, result)
    elif response.content_type.startswith("image/") and decode_qr and not response.truncated:
        _decode_qr(response.body, result)


def content_digest(html: str) -> str:
    """Empreinte stable du texte visible d'une page.

    Elle sert a comparer deux rendus du meme lien sous deux identites. La mise
    en forme, les espaces et la casse ne comptent pas : sans cette
    normalisation, deux rendus identiques donneraient deux empreintes
    differentes et tout site paraitrait pratiquer le cloaking.

    Une empreinte differente ne prouve rien a elle seule : une page datee ou
    personnalisee change a chaque appel. C'est un contexte ; la preuve, c'est
    la divergence structurelle.
    """
    texte = BeautifulSoup(html or "", "lxml").get_text(" ", strip=True)
    return _text_digest(texte)


def _text_digest(texte: str) -> str:
    """Même normalisation pour le helper public et la réponse HTTP réelle."""
    normalise = re.sub(r"\s+", " ", texte).strip().casefold()
    return hashlib.sha256(normalise.encode("utf-8")).hexdigest()


def _analyze_html(content: bytes, result: FetchResult) -> None:
    try:
        soup = BeautifulSoup(content, "lxml")
        for node in soup(["script", "style"]):
            node.decompose()
        texte = soup.get_text(" ", strip=True)
        result.body_excerpt = texte[:5000]
        result.content_digest = _text_digest(texte)
        result.visible_links = [str(node["href"]) for node in soup.find_all("a", href=True)[:30]]
        result.forms = [
            {
                "action": str(form.get("action", "")),
                "method": str(form.get("method", "GET")).upper(),
                "inputs": [str(node.get("name", "")) for node in form.find_all("input")[:20]],
            }
            for form in soup.find_all("form")[:5]
        ]
    except Exception as exc:
        result.error = f"html_parse:{type(exc).__name__}"


def _decode_qr(content: bytes, result: FetchResult) -> None:
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as zbar_decode

        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            image = Image.open(io.BytesIO(content))
            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise ValueError("image_pixel_limit")
            image.load()  # type: ignore[no-untyped-call]  # Pillow n'expose pas ce type
        for obj in zbar_decode(image):
            result.qr_codes.append(obj.data.decode("utf-8", errors="replace"))
    except Exception as exc:
        result.qr_error = f"qr_decode:{type(exc).__name__}"


def _redact_url(raw_url: str) -> str:
    """Ne renvoie jamais le userinfo d'une URL interdite dans les preuves."""
    try:
        parsed = urlsplit(raw_url)
        host = parsed.hostname or ""
        port = parsed.port
        host_literal = f"[{host}]" if ":" in host else host
        netloc = f"{host_literal}:{port}" if port is not None else host_literal
        return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, ""))
    except (TypeError, ValueError):
        return ""


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8090)
