"""Sandbox HTTP : analyse pièce jointe (oletools / pdfminer / YARA).

Container isolé. Communique avec ingest via HTTP. Reçoit le binaire en multipart,
applique YARA + détection oletools/pdfminer selon mime, retourne JSON verdict.
"""

from __future__ import annotations

import base64
import hashlib
import math
import os
import re
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path
from typing import Any, BinaryIO

import yara  # type: ignore[import-not-found]
from archive_scan import ArchiveLimits, archive_kind, inspect_archive
from document_extract import TextExtraction, bound_text, extract_pdf_pages
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

YARA_RULES_PATH = Path("/app/rules/sentimail_basic.yar")
MAX_BYTES = 25 * 1024 * 1024


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _positive_float_env(name: str, default: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if math.isfinite(value) and value > 0 else default


OCR_MAX_BYTES = _positive_int_env("OCR_MAX_BYTES", 10 * 1024 * 1024)
OCR_MAX_CHARS = _positive_int_env("OCR_MAX_CHARS", 2500)
OCR_TIMEOUT_SECONDS = _positive_float_env("OCR_TIMEOUT_SECONDS", 15.0)
OCR_LANGUAGES = os.environ.get("OCR_LANGUAGES", "eng+fra")
PDF_TEXT_MAX_CHARS = _positive_int_env("PDF_TEXT_MAX_CHARS", 100_000)
PDF_URL_MAX_COUNT = _positive_int_env("PDF_URL_MAX_COUNT", 1_000)
PDF_MAX_PAGES = _positive_int_env("PDF_MAX_PAGES", 200)
ARCHIVE_TEXT_MAX_CHARS = _positive_int_env("ARCHIVE_TEXT_MAX_CHARS", 100_000)
ARCHIVE_URL_MAX_COUNT = _positive_int_env("ARCHIVE_URL_MAX_COUNT", 1_000)
ARCHIVE_MAX_OCR_MEMBERS = _positive_int_env("ARCHIVE_MAX_OCR_MEMBERS", 3)
ARCHIVE_LIMITS = ArchiveLimits(
    max_depth=_positive_int_env("ARCHIVE_MAX_DEPTH", 3),
    max_entries=_positive_int_env("ARCHIVE_MAX_ENTRIES", 100),
    max_member_bytes=_positive_int_env("ARCHIVE_MAX_MEMBER_BYTES", 10 * 1024 * 1024),
    max_total_uncompressed_bytes=_positive_int_env("ARCHIVE_MAX_TOTAL_BYTES", 50 * 1024 * 1024),
    max_compression_ratio=_positive_float_env("ARCHIVE_MAX_COMPRESSION_RATIO", 200.0),
)
OCR_MIME_TYPES = frozenset(
    {
        "image/bmp",
        "image/jpeg",
        "image/png",
        "image/tiff",
        "image/webp",
    }
)
_BASE64_EXPECTED_MIME_PREFIXES = (
    "application/pdf",
    "application/zip",
    "application/x-zip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/x-tar",
    "application/gzip",
    "application/vnd.openxmlformats-officedocument.",
    "application/vnd.ms-",
    "application/pkcs7-",
    "application/x-pkcs7-",
    "application/pkcs8-",
    "image/",
    "font/",
    "application/font-",
    "application/x-font-",
)
_DANGEROUS_MEMBER_SUFFIXES = (
    ".bat",
    ".cmd",
    ".com",
    ".cpl",
    ".dll",
    ".exe",
    ".hta",
    ".jar",
    ".js",
    ".lnk",
    ".msi",
    ".pif",
    ".ps1",
    ".reg",
    ".scr",
    ".vbs",
    ".wsf",
    ".wsh",
)
_TEXT_MEMBER_SUFFIXES = (
    ".csv",
    ".eml",
    ".htm",
    ".html",
    ".ics",
    ".json",
    ".md",
    ".txt",
    ".xml",
)
_OFFICE_MEMBER_SUFFIXES = (
    ".doc",
    ".docm",
    ".docx",
    ".ppt",
    ".pptm",
    ".pptx",
    ".xls",
    ".xlsm",
    ".xlsx",
)
_OFFICE_MIME_TYPES = frozenset(
    {
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }
)

app = FastAPI(title="sentimail file-sandbox", version="0.2.1")
_compiled_rules: yara.Rules | None = None


def _normalize_ocr_text(value: str) -> tuple[str, bool]:
    """Nettoie la sortie OCR sans fusionner les lignes d'un document."""
    lines = [re.sub(r"\s+", " ", line).strip() for line in value.splitlines()]
    normalized = "\n".join(line for line in lines if line)
    return normalized[:OCR_MAX_CHARS], len(normalized) > OCR_MAX_CHARS


def _extract_image_text(data: bytes, mime: str) -> tuple[str, str | None, bool, bool]:
    """OCR raster borné: texte, erreur, troncature et complétude."""
    if mime.lower() not in OCR_MIME_TYPES:
        return "", None, False, True
    if len(data) > OCR_MAX_BYTES:
        return "", "ocr_input_too_large", False, False
    try:
        result = subprocess.run(
            [
                "tesseract",
                "stdin",
                "stdout",
                "--dpi",
                "200",
                "-l",
                OCR_LANGUAGES,
            ],
            input=data,
            capture_output=True,
            check=False,
            timeout=OCR_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", type(exc).__name__, False, False
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        return "", f"tesseract_exit_{result.returncode}: {error[:120]}", False, False
    text, truncated = _normalize_ocr_text(result.stdout.decode("utf-8", errors="replace"))
    return text, None, truncated, not truncated


def _rules() -> yara.Rules:
    global _compiled_rules
    if _compiled_rules is None:
        _compiled_rules = yara.compile(filepath=str(YARA_RULES_PATH))
    return _compiled_rules


def _detect_mime(data: bytes) -> str:
    try:
        import magic

        return str(magic.from_buffer(data, mime=True) or "application/octet-stream").lower()
    except Exception:
        return "application/octet-stream"


def _scan_yara(
    data: bytes,
    *,
    mime: str,
    context: str | None = None,
) -> tuple[list[dict[str, Any]], float, bool]:
    """Applique YARA à un blob et expose explicitement toute indisponibilité."""
    findings: list[dict[str, Any]] = []
    score = 0.0
    base64_is_expected = any(
        mime.lower().startswith(prefix) for prefix in _BASE64_EXPECTED_MIME_PREFIXES
    )
    try:
        matches = _rules().match(data=data)
    except yara.Error as exc:
        return (
            [
                {
                    "code": "YARA_ERROR",
                    "severity": "high",
                    "description": (f"{context}: " if context else "")
                    + f"YARA indisponible: {type(exc).__name__}",
                }
            ],
            0.0,
            False,
        )

    for match in matches:
        rule_name = match.rule
        severity = match.meta.get("severity", "medium") if hasattr(match, "meta") else "medium"
        description = str(match.meta.get("description", rule_name))
        if context:
            description = f"{context}: {description}"
        if rule_name == "SENTIMAIL_BASE64_PAYLOAD" and base64_is_expected:
            findings.append(
                {
                    "code": f"YARA_{rule_name}",
                    "severity": "info",
                    "description": (f"{context}: " if context else "")
                    + f"Long blob base64 attendu pour le type {mime}; ignore",
                }
            )
            continue
        findings.append(
            {
                "code": f"YARA_{rule_name}",
                "severity": severity,
                "description": description,
            }
        )
        if severity == "critical":
            score = max(score, 0.9)
        elif severity == "high":
            score = max(score, 0.7)
        elif severity == "medium":
            score = max(score, 0.4)
    return findings, score, True


def _member_ref(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8", errors="replace")).hexdigest()[:16]


def _decode_text_member(data: bytes) -> tuple[str, bool]:
    try:
        return data.decode("utf-8"), True
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), False


def _is_office(filename: str, mime: str) -> bool:
    lower = filename.lower()
    return mime.lower() in _OFFICE_MIME_TYPES or lower.endswith(_OFFICE_MEMBER_SUFFIXES)


def _scan_office(
    data: bytes,
    *,
    filename: str,
    context: str | None = None,
) -> tuple[list[dict[str, Any]], float, bool]:
    """Analyse les macros sans tronquer silencieusement leur contenu."""
    findings: list[dict[str, Any]] = []
    score = 0.0
    parser: Any | None = None
    prefix = f"{context}: " if context else ""
    try:
        from oletools.olevba import VBA_Parser

        with tempfile.NamedTemporaryFile(
            delete=True,
            suffix=Path(filename).suffix or ".bin",
        ) as temporary:
            temporary.write(data)
            temporary.flush()
            parser = VBA_Parser(temporary.name)
            if not parser.detect_vba_macros():
                return findings, score, True

            findings.append(
                {
                    "code": "OFFICE_HAS_MACROS",
                    "severity": "high",
                    "description": f"{prefix}macros VBA détectées",
                }
            )
            score = max(score, 0.7)
            auto_exec = False
            shell_exec = False
            try:
                for _source, _stream, _vba_filename, vba_code in parser.extract_macros():
                    if isinstance(vba_code, bytes):
                        code = vba_code.decode("utf-8", errors="replace")
                    else:
                        code = str(vba_code)
                    auto_exec = auto_exec or bool(
                        re.search(
                            r"AutoOpen|Auto_Open|Document_Open|Workbook_Open",
                            code,
                            re.IGNORECASE,
                        )
                    )
                    shell_exec = shell_exec or bool(
                        re.search(
                            r"Shell|WScript|Environ|CreateObject|cmd\.exe|powershell",
                            code,
                            re.IGNORECASE,
                        )
                    )
            except Exception as exc:
                findings.append(
                    {
                        "code": "OFFICE_MACRO_EXTRACTION_ERROR",
                        "severity": "high",
                        "description": (f"{prefix}extraction VBA incomplète: {type(exc).__name__}"),
                    }
                )
                return findings, score, False

            if auto_exec:
                findings.append(
                    {
                        "code": "OFFICE_AUTO_EXEC",
                        "severity": "critical",
                        "description": f"{prefix}macro VBA auto-exécutée à l'ouverture",
                    }
                )
                score = max(score, 0.95)
            if shell_exec:
                findings.append(
                    {
                        "code": "OFFICE_SHELL_EXEC",
                        "severity": "critical",
                        "description": f"{prefix}macro lance un shell / process externe",
                    }
                )
                score = max(score, 0.95)
            return findings, score, True
    except Exception as exc:
        return (
            [
                {
                    "code": "OFFICE_PARSE_ERROR",
                    "severity": "high",
                    "description": f"{prefix}oletools indisponible: {type(exc).__name__}",
                }
            ],
            score,
            False,
        )
    finally:
        if parser is not None:
            with suppress(Exception):
                parser.close()


def _extract_pdf(data: bytes) -> TextExtraction:
    """Extrait le texte PDF avec budgets explicites et dépendance locale."""
    try:
        from pdfminer.high_level import extract_pages
        from pdfminer.layout import LTTextContainer
    except Exception as exc:
        return TextExtraction(
            text="",
            text_total_chars=0,
            text_truncated=False,
            urls=(),
            urls_total=0,
            urls_truncated=False,
            complete=False,
            error=f"dependency_{type(exc).__name__}",
        )

    def page_texts(stream: BinaryIO) -> Iterator[str]:
        for layout in extract_pages(stream):
            yield "\n".join(
                element.get_text() for element in layout if isinstance(element, LTTextContainer)
            )

    return extract_pdf_pages(
        data,
        page_extractor=page_texts,
        max_pages=PDF_MAX_PAGES,
        max_chars=PDF_TEXT_MAX_CHARS,
        max_urls=PDF_URL_MAX_COUNT,
    )


def _pdf_findings(
    extraction: TextExtraction,
    *,
    context: str | None = None,
) -> tuple[list[dict[str, Any]], float]:
    findings: list[dict[str, Any]] = []
    score = 0.0
    prefix = f"{context}: " if context else ""
    if extraction.error:
        findings.append(
            {
                "code": "PDF_PARSE_ERROR",
                "severity": "high",
                "description": f"{prefix}pdfminer indisponible: {extraction.error}",
            }
        )
    if extraction.text_truncated or extraction.urls_truncated or extraction.pages_truncated:
        findings.append(
            {
                "code": "PDF_EXTRACTION_BUDGET_EXCEEDED",
                "severity": "high",
                "description": (
                    f"{prefix}extraction PDF incomplète "
                    f"(texte={extraction.text_total_chars}/{PDF_TEXT_MAX_CHARS}, "
                    f"urls={extraction.urls_total}/{PDF_URL_MAX_COUNT}, "
                    f"pages={extraction.pages_analyzed}/{PDF_MAX_PAGES})"
                ),
            }
        )
    if re.search(r"/JavaScript|/JS|\bJavaScript\b", extraction.text, re.IGNORECASE):
        findings.append(
            {
                "code": "PDF_JAVASCRIPT",
                "severity": "high",
                "description": f"{prefix}PDF contient du JavaScript",
            }
        )
        score = max(score, 0.6)
    if re.search(r"/Launch|/EmbeddedFile|/OpenAction", extraction.text, re.IGNORECASE):
        findings.append(
            {
                "code": "PDF_LAUNCH_ACTION",
                "severity": "high",
                "description": f"{prefix}PDF avec OpenAction / Launch / fichier embarqué",
            }
        )
        score = max(score, 0.7)
    return findings, score


class AnalyzeIn(BaseModel):
    filename: str = Field(min_length=1, max_length=512)
    content_b64: str = Field(min_length=1)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(payload: AnalyzeIn) -> dict[str, Any]:
    try:
        data = base64.b64decode(payload.content_b64, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"base64 invalide: {exc}") from exc
    if len(data) > MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"fichier > {MAX_BYTES} bytes")

    findings: list[dict[str, Any]] = []
    score = 0.0
    analysis_incomplete = False
    name = payload.filename
    sha256 = hashlib.sha256(data).hexdigest()
    mime = _detect_mime(data)
    mime_low = mime.lower()

    extracted_text = ""
    extracted_text_source: str | None = None
    extracted_text_provenance: dict[str, Any] | None = None
    extracted_text_total_chars = 0
    extracted_text_truncated = False
    extracted_text_complete = True
    extracted_urls: list[str] = []
    extracted_urls_total = 0
    extracted_urls_truncated = False
    archive_analysis: dict[str, Any] | None = None

    # OCR des images avant l'analyse sémantique du pipeline. Le sandbox ne
    # décide pas si le texte est légitime : il l'expose comme contenu non fiable.
    ocr_text, ocr_error, ocr_truncated, ocr_complete = _extract_image_text(data, mime_low)
    if mime_low in OCR_MIME_TYPES:
        ocr_extraction = bound_text(
            ocr_text,
            max_chars=OCR_MAX_CHARS,
            max_urls=PDF_URL_MAX_COUNT,
        )
        extracted_text = ocr_extraction.text
        extracted_text_source = "ocr"
        extracted_text_provenance = {
            "kind": "image_ocr",
            "origin": "attachment",
        }
        extracted_text_total_chars = ocr_extraction.text_total_chars
        extracted_text_truncated = ocr_truncated or ocr_extraction.text_truncated
        extracted_urls = list(ocr_extraction.urls)
        extracted_urls_total = ocr_extraction.urls_total
        extracted_urls_truncated = ocr_extraction.urls_truncated
        extracted_text_complete = ocr_complete and ocr_extraction.complete
        analysis_incomplete = analysis_incomplete or not extracted_text_complete
        if extracted_text:
            findings.append(
                {
                    "code": "IMAGE_OCR_TEXT",
                    "severity": "info",
                    "description": (
                        "Texte OCR non fiable extrait de l'image "
                        f"({len(extracted_text)} caractères)"
                    ),
                }
            )
        if ocr_error:
            findings.append(
                {
                    "code": "IMAGE_OCR_ERROR",
                    "severity": "high",
                    "description": f"OCR image indisponible : {ocr_error}",
                }
            )

    yara_findings, yara_score, yara_complete = _scan_yara(data, mime=mime_low)
    findings.extend(yara_findings)
    score = max(score, yara_score)
    analysis_incomplete = analysis_incomplete or not yara_complete

    # oletools si Office. Les documents OOXML sont volontairement exclus du
    # chemin archive générique : leur scan macros natif reste l'autorité.
    is_office = _is_office(name, mime_low)
    if is_office:
        office_findings, office_score, office_complete = _scan_office(
            data,
            filename=name,
        )
        findings.extend(office_findings)
        score = max(score, office_score)
        analysis_incomplete = analysis_incomplete or not office_complete

    # pdfminer si PDF
    is_pdf = mime_low == "application/pdf" or name.lower().endswith(".pdf")
    if is_pdf:
        pdf_extraction = _extract_pdf(data)
        pdf_findings, pdf_score = _pdf_findings(pdf_extraction)
        findings.extend(pdf_findings)
        score = max(score, pdf_score)
        extracted_text = pdf_extraction.text
        extracted_text_source = "pdf"
        extracted_text_provenance = {
            "kind": "pdf_text",
            "origin": "attachment",
            "pages_total_observed": pdf_extraction.pages_total_observed,
            "pages_analyzed": pdf_extraction.pages_analyzed,
            "pages_skipped": pdf_extraction.pages_skipped,
        }
        extracted_text_total_chars = pdf_extraction.text_total_chars
        extracted_text_truncated = pdf_extraction.text_truncated
        extracted_urls = list(pdf_extraction.urls)
        extracted_urls_total = pdf_extraction.urls_total
        extracted_urls_truncated = pdf_extraction.urls_truncated
        extracted_text_complete = pdf_extraction.complete
        analysis_incomplete = analysis_incomplete or not pdf_extraction.complete

    # Archives récursives. Les chemins membres ne sortent jamais du sandbox :
    # seule une référence SHA-256 courte est exposée pour la provenance.
    if not is_office:
        archive_result = inspect_archive(data, name, limits=ARCHIVE_LIMITS)
        if archive_result.detected:
            archive_chunks: list[str] = []
            archive_sources: list[dict[str, Any]] = []
            archive_members: list[dict[str, Any]] = []
            archive_complete = archive_result.complete
            archive_ocr_count = 0

            for issue in archive_result.issues:
                findings.append(
                    {
                        "code": issue.code,
                        "severity": "high",
                        "description": f"Inspection archive incomplète: {issue.detail}",
                    }
                )

            for member in archive_result.members:
                ref = _member_ref(member.path)
                member_mime = _detect_mime(member.data)
                lower_path = member.path.lower()
                nested_kind = archive_kind(member.data, member.path)
                member_complete = True
                extraction_kind: str | None = None
                member_text = ""
                member_urls_total = 0

                member_yara, member_score, member_yara_complete = _scan_yara(
                    member.data,
                    mime=member_mime,
                    context=f"membre archive {ref}",
                )
                findings.extend(member_yara)
                score = max(score, member_score)
                member_complete = member_complete and member_yara_complete

                if lower_path.endswith(_DANGEROUS_MEMBER_SUFFIXES):
                    findings.append(
                        {
                            "code": "ARCHIVE_DANGEROUS_MEMBER_EXTENSION",
                            "severity": "critical",
                            "description": (f"Membre archive exécutable détecté (référence {ref})"),
                        }
                    )
                    score = max(score, 0.95)

                if _is_office(member.path, member_mime):
                    office_findings, office_score, office_complete = _scan_office(
                        member.data,
                        filename=member.path,
                        context=f"membre archive {ref}",
                    )
                    findings.extend(office_findings)
                    score = max(score, office_score)
                    member_complete = member_complete and office_complete

                if member_mime == "application/pdf" or lower_path.endswith(".pdf"):
                    extraction_kind = "pdf_text"
                    member_pdf = _extract_pdf(member.data)
                    member_pdf_findings, member_pdf_score = _pdf_findings(
                        member_pdf,
                        context=f"membre archive {ref}",
                    )
                    findings.extend(member_pdf_findings)
                    score = max(score, member_pdf_score)
                    member_complete = member_complete and member_pdf.complete
                    member_text = member_pdf.text
                    member_urls_total = member_pdf.urls_total
                elif member_mime in OCR_MIME_TYPES:
                    extraction_kind = "image_ocr"
                    archive_ocr_count += 1
                    if archive_ocr_count > ARCHIVE_MAX_OCR_MEMBERS:
                        member_complete = False
                        findings.append(
                            {
                                "code": "ARCHIVE_OCR_BUDGET_EXCEEDED",
                                "severity": "high",
                                "description": (
                                    "Budget OCR archive dépassé "
                                    f"(référence {ref}, budget={ARCHIVE_MAX_OCR_MEMBERS})"
                                ),
                            }
                        )
                    else:
                        member_ocr, member_ocr_error, member_ocr_truncated, member_ocr_complete = (
                            _extract_image_text(member.data, member_mime)
                        )
                        bounded_ocr = bound_text(
                            member_ocr,
                            max_chars=OCR_MAX_CHARS,
                            max_urls=ARCHIVE_URL_MAX_COUNT,
                        )
                        member_text = bounded_ocr.text
                        member_urls_total = bounded_ocr.urls_total
                        member_complete = (
                            member_complete
                            and member_ocr_complete
                            and not member_ocr_truncated
                            and bounded_ocr.complete
                        )
                        if member_ocr_error:
                            findings.append(
                                {
                                    "code": "ARCHIVE_OCR_ERROR",
                                    "severity": "high",
                                    "description": (
                                        f"OCR membre archive indisponible (référence {ref}): "
                                        f"{member_ocr_error}"
                                    ),
                                }
                            )
                elif nested_kind is None and (
                    member_mime.startswith("text/") or lower_path.endswith(_TEXT_MEMBER_SUFFIXES)
                ):
                    extraction_kind = "text"
                    decoded, decoded_complete = _decode_text_member(member.data)
                    member_text = decoded
                    member_complete = member_complete and decoded_complete
                    if not decoded_complete:
                        findings.append(
                            {
                                "code": "ARCHIVE_TEXT_DECODE_INCOMPLETE",
                                "severity": "high",
                                "description": (
                                    f"Décodage texte archive avec remplacement (référence {ref})"
                                ),
                            }
                        )

                if member_text:
                    archive_chunks.append(
                        f"[archive-member {ref}; source={extraction_kind}]\n{member_text}"
                    )
                    archive_sources.append(
                        {
                            "member_ref": ref,
                            "kind": extraction_kind,
                            "depth": member.depth,
                            "text_chars": len(member_text),
                            "urls_total": member_urls_total,
                            "pages_total_observed": (
                                member_pdf.pages_total_observed
                                if extraction_kind == "pdf_text"
                                else 0
                            ),
                            "pages_analyzed": (
                                member_pdf.pages_analyzed if extraction_kind == "pdf_text" else 0
                            ),
                            "pages_skipped": (
                                member_pdf.pages_skipped if extraction_kind == "pdf_text" else 0
                            ),
                        }
                    )
                archive_members.append(
                    {
                        "member_ref": ref,
                        "depth": member.depth,
                        "size_bytes": len(member.data),
                        "sha256": member.sha256,
                        "mime": member_mime,
                        "analysis_complete": member_complete,
                        "text_source": extraction_kind,
                    }
                )
                archive_complete = archive_complete and member_complete

            archive_extraction = bound_text(
                "\n\n".join(archive_chunks),
                max_chars=ARCHIVE_TEXT_MAX_CHARS,
                max_urls=ARCHIVE_URL_MAX_COUNT,
            )
            if not archive_extraction.complete:
                findings.append(
                    {
                        "code": "ARCHIVE_TEXT_BUDGET_EXCEEDED",
                        "severity": "high",
                        "description": (
                            "Contenu dérivé archive incomplet "
                            f"(texte={archive_extraction.text_total_chars}/"
                            f"{ARCHIVE_TEXT_MAX_CHARS}, urls={archive_extraction.urls_total}/"
                            f"{ARCHIVE_URL_MAX_COUNT})"
                        ),
                    }
                )
            archive_complete = archive_complete and archive_extraction.complete
            analysis_incomplete = analysis_incomplete or not archive_complete
            extracted_text = archive_extraction.text
            extracted_text_source = "archive"
            extracted_text_provenance = {
                "kind": "archive_members",
                "origin": "attachment",
                "archive_kind": archive_result.kind,
                "sources": archive_sources,
            }
            extracted_text_total_chars = archive_extraction.text_total_chars
            extracted_text_truncated = archive_extraction.text_truncated
            extracted_urls = list(archive_extraction.urls)
            extracted_urls_total = archive_extraction.urls_total
            extracted_urls_truncated = archive_extraction.urls_truncated
            extracted_text_complete = archive_complete
            archive_analysis = {
                "detected": True,
                "kind": archive_result.kind,
                "complete": archive_complete,
                "entries_total_observed": archive_result.entries_total,
                "entries_analyzed": archive_result.entries_analyzed,
                "entries_skipped": archive_result.entries_skipped,
                "total_uncompressed_bytes": archive_result.total_uncompressed_bytes,
                "max_depth_seen": archive_result.max_depth_seen,
                "limits": {
                    "max_depth": ARCHIVE_LIMITS.max_depth,
                    "max_entries": ARCHIVE_LIMITS.max_entries,
                    "max_member_bytes": ARCHIVE_LIMITS.max_member_bytes,
                    "max_total_uncompressed_bytes": (ARCHIVE_LIMITS.max_total_uncompressed_bytes),
                    "max_compression_ratio": ARCHIVE_LIMITS.max_compression_ratio,
                    "max_ocr_members": ARCHIVE_MAX_OCR_MEMBERS,
                    "max_pdf_pages_per_member": PDF_MAX_PAGES,
                },
                "issues": [
                    {"code": issue.code, "detail": issue.detail} for issue in archive_result.issues
                ],
                "members": archive_members,
            }

    return {
        "filename": name,
        "size_bytes": len(data),
        "sha256": sha256,
        "mime": mime,
        "score": min(1.0, score),
        "extracted_text": extracted_text,
        "extracted_text_source": extracted_text_source,
        "extracted_text_provenance": extracted_text_provenance,
        "extracted_text_total_chars": extracted_text_total_chars,
        "extracted_text_truncated": extracted_text_truncated,
        "extracted_text_incomplete": not extracted_text_complete,
        "extracted_urls": extracted_urls,
        "extracted_urls_total": extracted_urls_total,
        "extracted_urls_truncated": extracted_urls_truncated,
        "analysis_incomplete": analysis_incomplete,
        "archive_analysis": archive_analysis,
        "findings": findings,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8091)
