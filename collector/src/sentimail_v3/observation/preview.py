from __future__ import annotations

import base64
import html
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

import httpx

MAX_RENDER_HTML_CHARS = 1_000_000
MAX_INLINE_IMAGE_BYTES = 5 * 1024 * 1024
MAX_SCREENSHOT_BYTES = 10 * 1024 * 1024
_CID_SOURCE = re.compile(
    r"(?P<prefix>\bsrc\s*=\s*['\"]?)cid:(?P<cid>[^'\"\s>]+)", re.IGNORECASE
)


def render_source(raw: bytes) -> str | None:
    try:
        parsed: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
        body = parsed.get_body(preferencelist=("html",))
        content = body.get_content() if body is not None else None
        if not isinstance(content, str) or not content.strip():
            plain = parsed.get_body(preferencelist=("plain",))
            text = plain.get_content() if plain is not None else ""
            if not isinstance(text, str) or not text.strip():
                return None
            return (
                "<!doctype html><html><body><pre>"
                + html.escape(text[:200_000])
                + "</pre></body></html>"
            )
        inline: dict[str, str] = {}
        total = 0
        for part in parsed.walk():
            cid = str(part.get("Content-ID") or "").strip().strip("<>").casefold()
            if not cid or not part.get_content_type().startswith("image/"):
                continue
            payload = part.get_payload(decode=True)
            if not isinstance(payload, bytes) or total + len(payload) > MAX_INLINE_IMAGE_BYTES:
                continue
            total += len(payload)
            encoded = base64.b64encode(payload).decode("ascii")
            inline[cid] = f"data:{part.get_content_type()};base64,{encoded}"

        def replace(match: re.Match[str]) -> str:
            source = inline.get(match.group("cid").casefold())
            return f"{match.group('prefix')}{source}" if source else match.group(0)

        return _CID_SOURCE.sub(replace, content)[:MAX_RENDER_HTML_CHARS]
    except Exception:  # noqa: BLE001 - la notification texte reste disponible
        return None


async def screenshot(raw: bytes, renderer_url: str) -> bytes | None:
    source = render_source(raw)
    if source is None:
        return None
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15, connect=3)) as client:
            response = await client.post(
                f"{renderer_url.rstrip('/')}/render",
                json={"html": source, "width": 900},
            )
        content_type = response.headers.get("content-type", "").split(";", 1)[0]
        if response.status_code != 200 or content_type != "image/png":
            return None
        if not response.content or len(response.content) > MAX_SCREENSHOT_BYTES:
            return None
        return response.content
    except (httpx.HTTPError, ValueError):
        return None


# La largeur d'affichage de l'avis. Au-delà, les pixels sont perdus par le
# client de messagerie : ils ne coûtent que du poids sur un téléphone.
THUMBNAIL_WIDTH = 640
MAX_THUMBNAIL_BYTES = 2 * 1024 * 1024


async def thumbnail(
    png: bytes, renderer_url: str, width: int = THUMBNAIL_WIDTH
) -> tuple[bytes, str] | None:
    """La capture réduite à ce que l'avis affiche, avec son type MIME.

    C'est elle que l'avis montre, et rien ne part en plus : au-delà de la
    largeur d'affichage, les pixels ne coûtent que du poids sur un téléphone.
    Le bac à sable de rendu la produit parce qu'il est le seul à disposer d'une
    bibliothèque d'images ; l'introduire dans le collector ajouterait une
    dépendance pour un service qui l'a déjà.

    Un échec n'est jamais bloquant : l'avis part alors avec l'original affiché.
    """
    if not png:
        return None
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15, connect=3)) as client:
            response = await client.post(
                f"{renderer_url.rstrip('/')}/thumbnail",
                params={"width": width},
                content=png,
                headers={"content-type": "image/png"},
            )
    except (httpx.HTTPError, ValueError):
        return None
    content_type = response.headers.get("content-type", "").split(";", 1)[0]
    if response.status_code != 200 or content_type not in {"image/png", "image/jpeg"}:
        return None
    reduite = response.content
    # Le bac à sable rend l'original quand il ne sait pas faire mieux : une
    # miniature qui ne gagne rien n'a pas lieu d'être expédiée en plus.
    if not reduite or len(reduite) >= len(png) or len(reduite) > MAX_THUMBNAIL_BYTES:
        return None
    return reduite, content_type
