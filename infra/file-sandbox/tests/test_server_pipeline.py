"""Tests purs du branchement HTTP, avec dépendances système simulées."""

from __future__ import annotations

import base64
import importlib
import io
import sys
import types
import zipfile
from collections.abc import Callable
from typing import Any

import pytest
from document_extract import TextExtraction


class _FakeFastAPI:
    def __init__(self, **_kwargs: object) -> None:
        pass

    def get(self, *_args: object, **_kwargs: object) -> Callable[[Any], Any]:
        return lambda function: function

    def post(self, *_args: object, **_kwargs: object) -> Callable[[Any], Any]:
        return lambda function: function


class _FakeHTTPError(Exception):
    def __init__(self, *, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class _FakeYaraError(Exception):
    pass


class _FakeYaraRules:
    def match(self, *, data: bytes) -> list[object]:
        del data
        return []


def _install_dependency_stubs() -> None:
    fastapi = types.ModuleType("fastapi")
    fastapi.FastAPI = _FakeFastAPI  # type: ignore[attr-defined]
    fastapi.HTTPException = _FakeHTTPError  # type: ignore[attr-defined]
    sys.modules.setdefault("fastapi", fastapi)

    yara = types.ModuleType("yara")
    yara.Error = _FakeYaraError  # type: ignore[attr-defined]
    yara.Rules = _FakeYaraRules  # type: ignore[attr-defined]
    yara.compile = lambda **_kwargs: _FakeYaraRules()  # type: ignore[attr-defined]
    sys.modules.setdefault("yara", yara)


_install_dependency_stubs()
server = importlib.import_module("server")


def _zip(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


def _payload(filename: str, content: bytes) -> Any:
    return server.AnalyzeIn(
        filename=filename,
        content_b64=base64.b64encode(content).decode("ascii"),
    )


def test_invalid_or_nonfinite_limits_cannot_disable_budgets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_ARCHIVE_LIMIT", "nan")
    assert server._positive_float_env("TEST_ARCHIVE_LIMIT", 200.0) == 200.0
    monkeypatch.setenv("TEST_ARCHIVE_LIMIT", "-1")
    assert server._positive_float_env("TEST_ARCHIVE_LIMIT", 200.0) == 200.0
    monkeypatch.setenv("TEST_ARCHIVE_LIMIT", "0")
    assert server._positive_int_env("TEST_ARCHIVE_LIMIT", 100) == 100


@pytest.mark.asyncio
async def test_archive_pipeline_is_recursive_material_and_privacy_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        server,
        "_detect_mime",
        lambda content: (
            "application/zip"
            if zipfile.is_zipfile(io.BytesIO(content))
            else "text/plain"
            if content.startswith(b"Read")
            else "application/octet-stream"
        ),
    )
    inner = _zip({"payload.exe": b"MZ synthetic"})
    outer = _zip(
        {
            "readme.txt": b"Read https://archive.example/path",
            "nested.zip": inner,
        }
    )

    result = server.analyze_content(_payload("outer.zip", outer))

    assert result["analysis_incomplete"] is False
    assert result["score"] == 0.95
    assert result["extracted_text_source"] == "archive"
    assert result["extracted_urls"] == ["https://archive.example/path"]
    assert result["extracted_text_provenance"]["kind"] == "archive_members"
    assert result["archive_analysis"]["entries_total_observed"] == 3
    assert result["archive_analysis"]["entries_analyzed"] == 3
    assert any(
        finding["code"] == "ARCHIVE_DANGEROUS_MEMBER_EXTENSION" for finding in result["findings"]
    )
    assert "payload.exe" not in str(result["archive_analysis"])
    assert "payload.exe" not in str(result["findings"])


@pytest.mark.asyncio
async def test_pdf_pipeline_exposes_bounded_text_urls_and_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "_detect_mime", lambda _content: "application/pdf")
    monkeypatch.setattr(
        server,
        "_extract_pdf",
        lambda *_args, **_kwargs: TextExtraction(
            text="Invoice https://billing.example/pay",
            text_total_chars=35,
            text_truncated=False,
            urls=("https://billing.example/pay",),
            urls_total=1,
            urls_truncated=False,
            complete=True,
        ),
    )

    result = server.analyze_content(
        _payload("invoice.pdf", b"%PDF-1.7\n1 0 obj << /JavaScript (alert(1)) >> endobj")
    )

    assert result["analysis_incomplete"] is False
    assert result["extracted_text_source"] == "pdf"
    assert result["extracted_text_provenance"] == {
        "kind": "pdf_text",
        "origin": "attachment",
        "pages_total_observed": 0,
        "pages_analyzed": 0,
        "pages_skipped": 0,
    }
    assert result["extracted_urls"] == ["https://billing.example/pay"]
    assert result["extracted_urls_total"] == 1
    assert any(finding["code"] == "PDF_JAVASCRIPT" for finding in result["findings"])


def test_pdf_findings_ignores_benign_javascript_text_and_checks_raw_bytes() -> None:
    extraction = TextExtraction(
        text="Guide de developpement JavaScript et /OpenAction dans un tutoriel",
        text_total_chars=64,
        text_truncated=False,
        urls=(),
        urls_total=0,
        urls_truncated=False,
        complete=True,
    )
    benign_findings, benign_score = server._pdf_findings(extraction, b"%PDF-1.7\n% benign")
    assert benign_findings == []
    assert benign_score == 0.0

    threat_findings, threat_score = server._pdf_findings(
        extraction, b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JS (x) >> endobj"
    )
    codes = {finding["code"] for finding in threat_findings}
    assert codes == {"PDF_JAVASCRIPT", "PDF_LAUNCH_ACTION"}
    assert threat_score == 0.7


def test_analyze_in_bounds_content_b64_length() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        server.AnalyzeIn(
            filename="oversized.bin",
            content_b64="A" * (server.MAX_CONTENT_B64_CHARS + 1),
        )


@pytest.mark.asyncio
async def test_unsupported_archive_pipeline_can_never_pass_silently() -> None:
    result = server.analyze_content(_payload("opaque.rar", b"Rar!\x1a\x07\x01\x00synthetic"))

    assert result["analysis_incomplete"] is True
    assert result["archive_analysis"]["kind"] == "unsupported"
    assert result["archive_analysis"]["complete"] is False
    assert any(finding["code"] == "ARCHIVE_FORMAT_UNSUPPORTED" for finding in result["findings"])
