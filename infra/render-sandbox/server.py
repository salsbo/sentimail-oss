"""Rendu PNG isolé d'un corps HTML d'email, sans aucune requête réseau."""

from __future__ import annotations

import asyncio
import io
import re
from contextlib import asynccontextmanager
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Query, Request, Response
from PIL import Image, ImageDraw
from playwright.async_api import Browser, async_playwright
from pydantic import BaseModel, Field
from pyzbar.pyzbar import decode as decode_barcodes

MAX_HTML_CHARS = 1_000_000
# Hauteur maximale de la capture. Le `max-height` CSS borne le peint mais pas
# `scrollHeight` : le rectangle est borné avant la capture, pour éviter de
# peindre et encoder une longue image dont le bas serait immédiatement jeté.
MAX_CAPTURE_HEIGHT = 1_200
MAX_IMAGE_PIXELS = 20_000_000
RENDER_TIMEOUT_SECONDS = 20.0
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
_DANGEROUS_CSS = re.compile(
    r"url\s*\([^)]*\)|@import[^;]*;?|expression\s*\([^)]*\)|javascript\s*:",
    re.IGNORECASE,
)
_REMOVE_TAGS = {
    "applet",
    "audio",
    "base",
    "button",
    "embed",
    "form",
    "frame",
    "frameset",
    "iframe",
    "input",
    "link",
    "meta",
    "noscript",
    "object",
    "script",
    "select",
    "source",
    "textarea",
    "video",
}
_DROP_ATTRIBUTES = {
    "action",
    "background",
    "formaction",
    "href",
    "ping",
    "poster",
    "srcset",
}


class RenderIn(BaseModel):
    html: str = Field(min_length=1, max_length=MAX_HTML_CHARS)
    width: int = Field(default=900, ge=480, le=1_200)


class State:
    browser: Browser | None = None


state = State()
_render_slots = asyncio.Semaphore(2)


def _sanitized_html(source: str) -> str:
    soup = BeautifulSoup(source, "html.parser")
    for tag in soup.find_all(_REMOVE_TAGS):
        tag.decompose()
    for tag in soup.find_all(True):
        for attribute in list(tag.attrs):
            folded = attribute.casefold()
            if folded.startswith("on") or folded in _DROP_ATTRIBUTES:
                del tag.attrs[attribute]
        style = tag.attrs.get("style")
        if isinstance(style, str):
            tag.attrs["style"] = _DANGEROUS_CSS.sub("", style)[:4_000]
        if tag.name == "img":
            src = tag.attrs.get("src")
            if not isinstance(src, str) or not src.casefold().startswith(
                ("data:image/png;base64,", "data:image/jpeg;base64,", "data:image/gif;base64,", "data:image/webp;base64,")
            ):
                alt = str(tag.attrs.get("alt") or "Image distante non chargée")[:160]
                replacement = soup.new_tag("span")
                replacement.string = f"[{alt}]"
                replacement.attrs["style"] = "display:inline-block;padding:8px;color:#64748b;background:#f1f5f9;border:1px solid #cbd5e1"
                tag.replace_with(replacement)
    for style_tag in soup.find_all("style"):
        css = style_tag.string or style_tag.get_text()
        style_tag.string = _DANGEROUS_CSS.sub("", css)[:100_000]
    head = soup.head
    if head is None:
        head = soup.new_tag("head")
        if soup.html is None:
            wrapper = soup.new_tag("html")
            wrapper.extend(list(soup.contents))
            soup.append(wrapper)
        soup.html.insert(0, head)
    policy = soup.new_tag("meta")
    policy.attrs["http-equiv"] = "Content-Security-Policy"
    policy.attrs["content"] = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src 'none'; form-action 'none'; base-uri 'none'"
    head.insert(0, policy)
    base_style = soup.new_tag("style")
    base_style.string = "html,body{margin:0!important;min-height:100%;max-height:6000px;background:#fff;color:#111827;overflow-wrap:anywhere}html{overflow:hidden!important}body{padding:24px;box-sizing:border-box;overflow:hidden!important}a{pointer-events:none!important}"
    head.append(base_style)
    return str(soup)


def _mask_qr_codes(png: bytes) -> bytes:
    image = Image.open(io.BytesIO(png)).convert("RGB")
    draw = ImageDraw.Draw(image)
    changed = False
    for symbol in decode_barcodes(image):
        if symbol.type != "QRCODE":
            continue
        left, top, width, height = symbol.rect
        draw.rectangle((left, top, left + width, top + height), fill="#e2e8f0", outline="#475569", width=3)
        draw.text((left + 8, top + 8), "QR code masque", fill="#0f172a")
        changed = True
    if not changed:
        return png
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    return output.getvalue()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    manager = async_playwright()
    playwright = await manager.start()
    state.browser = await playwright.chromium.launch(
        headless=True,
        args=["--disable-dev-shm-usage", "--disable-gpu", "--no-sandbox"],
    )
    try:
        yield
    finally:
        if state.browser is not None:
            await state.browser.close()
        await playwright.stop()


app = FastAPI(title="sentimail render sandbox", version="0.3.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok" if state.browser is not None else "starting"}


@app.post("/render")
async def render(payload: RenderIn) -> Response:
    if state.browser is None:
        raise HTTPException(status_code=503, detail="renderer unavailable")
    try:
        async with asyncio.timeout(RENDER_TIMEOUT_SECONDS):
            async with _render_slots:
                sanitized = await asyncio.to_thread(_sanitized_html, payload.html)
                context = await state.browser.new_context(
                    viewport={"width": payload.width, "height": 900},
                    device_scale_factor=1,
                    java_script_enabled=False,
                )
                try:
                    page = await context.new_page()
                    await page.route("**/*", lambda route: route.abort())
                    await page.set_content(sanitized, wait_until="domcontentloaded", timeout=5_000)
                    # full_page permet au clip de dépasser le viewport sans le changer
                    # (vh et media queries restent identiques). Chromium ne capture que
                    # ce rectangle, pas une pleine page à découper après encodage.
                    png = await page.screenshot(
                        type="png",
                        full_page=True,
                        clip={"x": 0, "y": 0, "width": payload.width, "height": MAX_CAPTURE_HEIGHT},
                    )
                except Exception as exc:
                    raise HTTPException(status_code=422, detail=f"render failed: {type(exc).__name__}") from exc
                finally:
                    await context.close()
            masked = await asyncio.to_thread(_mask_qr_codes, png)
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail="render timeout") from exc
    return Response(content=masked, media_type="image/png")


MAX_THUMBNAIL_SOURCE_BYTES = 10 * 1024 * 1024


def _downscale(png: bytes, width: int) -> tuple[bytes, str]:
    """Réduit la capture à ce que l'avis affiche réellement.

    Ce service est le seul du parc à disposer d'une bibliothèque d'images : la
    réduction se fait ici plutôt que d'ajouter la dépendance au collector pour
    une opération faite une fois par avis.

    Le JPEG est choisi à dessein. Cette copie ne sert qu'à être regardée -
    l'original PNG part en pièce jointe et reste la preuve, intacte. Réencoder
    en PNG ne gagnait que 29 % sur la capture la plus lourde, et rien du tout
    sur une capture médiane : le codeur de Chromium fait déjà mieux que le
    nôtre. La perte visuelle du JPEG est invisible à 640 pixels de large, le
    gain ne l'est pas.

    Aucune coupe : un message long reste lisible en entier, seuls les pixels
    au-delà de la largeur d'affichage disparaissent.
    """
    image = Image.open(io.BytesIO(png))
    cible = min(width, image.width)
    hauteur = max(1, round(image.height * cible / image.width))
    reduite = image.convert("RGB")
    if cible != image.width:
        reduite = reduite.resize((cible, hauteur), Image.LANCZOS)
    sortie = io.BytesIO()
    reduite.save(sortie, format="JPEG", quality=78, optimize=True, progressive=True)
    jpeg = sortie.getvalue()
    # Un gain négatif n'existe pas : sur une capture minuscule, l'original
    # reste le meilleur des deux.
    if len(jpeg) >= len(png):
        return png, "image/png"
    return jpeg, "image/jpeg"


@app.post("/thumbnail")
async def thumbnail(request: Request, width: int = Query(default=640, ge=240, le=1_200)) -> Response:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_size = int(content_length)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="en-tete Content-Length invalide") from exc
        if declared_size <= 0 or declared_size > MAX_THUMBNAIL_SOURCE_BYTES:
            raise HTTPException(status_code=413, detail="image absente ou trop lourde")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_THUMBNAIL_SOURCE_BYTES:
            raise HTTPException(status_code=413, detail="image absente ou trop lourde")
        chunks.append(chunk)
    png = b"".join(chunks)
    if not png:
        raise HTTPException(status_code=413, detail="image absente ou trop lourde")
    try:
        reduite, media_type = await asyncio.to_thread(_downscale, png, width)
    except Exception as exc:  # noqa: BLE001 - une miniature absente n'est pas une panne
        raise HTTPException(
            status_code=422, detail=f"thumbnail failed: {type(exc).__name__}"
        ) from exc
    return Response(content=reduite, media_type=media_type)
