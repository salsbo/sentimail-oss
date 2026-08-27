"""Tests purs de l'extraction documentaire bornée."""

from __future__ import annotations

from collections.abc import Iterator
from typing import BinaryIO

from document_extract import bound_text, extract_pdf_pages, extract_pdf_text


def test_bound_text_exposes_ordered_unique_urls_and_all_counters() -> None:
    result = bound_text(
        "start https://one.example/a https://two.example/b https://one.example/a end",
        max_chars=1_000,
        max_urls=1,
    )

    assert result.text_total_chars == 75
    assert result.text_truncated is False
    assert result.urls == ("https://one.example/a",)
    assert result.urls_total == 2
    assert result.urls_truncated is True
    assert result.complete is False


def test_pdf_adapter_exposes_text_and_urls_without_runtime_dependency() -> None:
    def extractor(stream: BinaryIO) -> str:
        assert stream.read() == b"%PDF synthetic"
        return "Invoice: https://billing.example/pay"

    result = extract_pdf_text(
        b"%PDF synthetic",
        extractor=extractor,
        max_chars=1_000,
        max_urls=10,
    )

    assert result.text == "Invoice: https://billing.example/pay"
    assert result.urls == ("https://billing.example/pay",)
    assert result.complete is True
    assert result.error is None


def test_pdf_text_cap_is_visible_and_invalid_output_is_fail_closed() -> None:
    truncated = extract_pdf_text(
        b"%PDF",
        extractor=lambda _stream: "X" * 11,
        max_chars=10,
        max_urls=10,
    )
    invalid = extract_pdf_text(
        b"%PDF",
        extractor=lambda _stream: None,
        max_chars=10,
        max_urls=10,
    )

    assert truncated.text == "X" * 10
    assert truncated.text_total_chars == 11
    assert truncated.text_truncated is True
    assert truncated.complete is False
    assert invalid.complete is False
    assert invalid.error == "invalid_extractor_output"


def test_pdf_extractor_failure_is_structured() -> None:
    def raises(_stream: BinaryIO) -> str:
        raise ValueError("private parser detail")

    result = extract_pdf_text(
        b"%PDF",
        extractor=raises,
        max_chars=10,
        max_urls=10,
    )

    assert result.complete is False
    assert result.error == "ValueError"
    assert result.text == ""


def test_pdf_page_and_character_budgets_stop_iteration_explicitly() -> None:
    consumed: list[str] = []

    def pages(_stream: BinaryIO) -> Iterator[str]:
        values = ["page one", "page two", "page three"]
        for value in values:
            consumed.append(value)
            yield value

    page_limited = extract_pdf_pages(
        b"%PDF",
        page_extractor=pages,
        max_pages=2,
        max_chars=1_000,
        max_urls=10,
    )
    char_limited = extract_pdf_pages(
        b"%PDF",
        page_extractor=lambda _stream: ["0123456789ABC"],
        max_pages=10,
        max_chars=10,
        max_urls=10,
    )

    assert consumed == ["page one", "page two", "page three"]
    assert page_limited.pages_total_observed == 3
    assert page_limited.pages_analyzed == 2
    assert page_limited.pages_skipped == 1
    assert page_limited.pages_truncated is True
    assert page_limited.complete is False
    assert char_limited.text == "0123456789"
    assert char_limited.text_truncated is True
    assert char_limited.pages_analyzed == 0
    assert char_limited.pages_skipped == 1
    assert char_limited.complete is False


def test_pdf_page_iterator_failure_and_invalid_budget_are_fail_closed() -> None:
    def raises(_stream: BinaryIO) -> list[str]:
        raise TimeoutError

    failed = extract_pdf_pages(
        b"%PDF",
        page_extractor=raises,
        max_pages=10,
        max_chars=100,
        max_urls=10,
    )
    invalid = extract_pdf_pages(
        b"%PDF",
        page_extractor=lambda _stream: [],
        max_pages=0,
        max_chars=100,
        max_urls=10,
    )

    assert failed.error == "TimeoutError"
    assert failed.pages_total_observed == 1
    assert failed.pages_skipped == 1
    assert failed.complete is False
    assert invalid.error == "invalid_extraction_budget"
    assert invalid.complete is False
