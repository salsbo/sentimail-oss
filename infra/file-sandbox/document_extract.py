"""Extraction documentaire bornée, pure et testable sans dépendance runtime."""

from __future__ import annotations

import io
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import BinaryIO

_URL_RE = re.compile(r"https?://[^\s<>'\"\)]+", re.IGNORECASE)


@dataclass(frozen=True)
class TextExtraction:
    text: str
    text_total_chars: int
    text_truncated: bool
    urls: tuple[str, ...]
    urls_total: int
    urls_truncated: bool
    complete: bool
    error: str | None = None
    pages_total_observed: int = 0
    pages_analyzed: int = 0
    pages_skipped: int = 0
    pages_truncated: bool = False


def _ordered_urls(text: str) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;:!?")
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def bound_text(
    text: str,
    *,
    max_chars: int,
    max_urls: int,
) -> TextExtraction:
    """Borne explicitement texte et URLs; toute perte rend le résultat incomplet."""
    urls = _ordered_urls(text)
    text_truncated = len(text) > max_chars
    urls_truncated = len(urls) > max_urls
    return TextExtraction(
        text=text[:max_chars],
        text_total_chars=len(text),
        text_truncated=text_truncated,
        urls=tuple(urls[:max_urls]),
        urls_total=len(urls),
        urls_truncated=urls_truncated,
        complete=not text_truncated and not urls_truncated,
    )


def extract_pdf_text(
    data: bytes,
    *,
    extractor: Callable[[BinaryIO], object],
    max_chars: int,
    max_urls: int,
) -> TextExtraction:
    """Adapte pdfminer (injecté) en résultat déterministe borné et fail-soft."""
    try:
        text = extractor(io.BytesIO(data))
    except Exception as exc:
        return TextExtraction(
            text="",
            text_total_chars=0,
            text_truncated=False,
            urls=(),
            urls_total=0,
            urls_truncated=False,
            complete=False,
            error=type(exc).__name__,
        )
    if not isinstance(text, str):
        return TextExtraction(
            text="",
            text_total_chars=0,
            text_truncated=False,
            urls=(),
            urls_total=0,
            urls_truncated=False,
            complete=False,
            error="invalid_extractor_output",
        )
    return bound_text(text, max_chars=max_chars, max_urls=max_urls)


def extract_pdf_pages(
    data: bytes,
    *,
    page_extractor: Callable[[BinaryIO], Iterable[object]],
    max_pages: int,
    max_chars: int,
    max_urls: int,
) -> TextExtraction:
    """Consomme un PDF page par page et s'arrête dès le premier budget atteint."""
    if max_pages <= 0 or max_chars <= 0 or max_urls <= 0:
        return TextExtraction(
            text="",
            text_total_chars=0,
            text_truncated=False,
            urls=(),
            urls_total=0,
            urls_truncated=False,
            complete=False,
            error="invalid_extraction_budget",
            pages_truncated=True,
        )
    chunks: list[str] = []
    observed_chars = 0
    pages_total_observed = 0
    pages_analyzed = 0
    pages_truncated = False
    error: str | None = None
    try:
        pages = page_extractor(io.BytesIO(data))
        for page in pages:
            pages_total_observed += 1
            if pages_total_observed > max_pages:
                pages_truncated = True
                break
            if not isinstance(page, str):
                error = "invalid_page_extractor_output"
                pages_truncated = True
                break
            separator = "\n" if chunks else ""
            remaining = max_chars + 1 - observed_chars
            candidate = f"{separator}{page}"
            chunks.append(candidate[: max(0, remaining)])
            observed_chars += min(len(candidate), max(0, remaining))
            if len(candidate) > remaining or observed_chars > max_chars:
                pages_truncated = True
                break
            pages_analyzed += 1
    except Exception as exc:
        error = type(exc).__name__
        pages_truncated = True
        pages_total_observed += 1

    bounded = bound_text("".join(chunks), max_chars=max_chars, max_urls=max_urls)
    pages_skipped = max(0, pages_total_observed - pages_analyzed)
    return TextExtraction(
        text=bounded.text,
        text_total_chars=bounded.text_total_chars,
        text_truncated=bounded.text_truncated,
        urls=bounded.urls,
        urls_total=bounded.urls_total,
        urls_truncated=bounded.urls_truncated,
        complete=bounded.complete and not pages_truncated and error is None,
        error=error,
        pages_total_observed=pages_total_observed,
        pages_analyzed=pages_analyzed,
        pages_skipped=pages_skipped,
        pages_truncated=pages_truncated,
    )
