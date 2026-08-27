"""Tests purs des budgets et de la récursion archive."""

from __future__ import annotations

import io
import tarfile
import zipfile

import archive_scan
import pytest
from archive_scan import ArchiveLimits, inspect_archive


def _zip(entries: dict[str, bytes], *, compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=compression) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


def _tar(entries: dict[str, bytes], *, mode: str = "w") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode=mode) as archive:
        for name, content in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def _mark_first_zip_entry_encrypted(data: bytes) -> bytes:
    """Positionne le bit ZIP encrypted dans les en-têtes local et central."""
    output = bytearray(data)
    local = output.find(b"PK\x03\x04")
    central = output.find(b"PK\x01\x02")
    assert local >= 0 and central >= 0
    local_flags = int.from_bytes(output[local + 6 : local + 8], "little") | 0x1
    central_flags = int.from_bytes(output[central + 8 : central + 10], "little") | 0x1
    output[local + 6 : local + 8] = local_flags.to_bytes(2, "little")
    output[central + 8 : central + 10] = central_flags.to_bytes(2, "little")
    return bytes(output)


def test_nested_zip_inventories_every_member_with_depth_and_hash() -> None:
    inner = _zip({"payload.exe": b"MZ synthetic executable"})
    outer = _zip({"readme.txt": b"hello", "bundle.zip": inner})

    result = inspect_archive(outer, "outer.zip")

    assert result.detected is True
    assert result.complete is True
    assert result.entries_total == 3
    assert result.entries_analyzed == 3
    assert result.entries_skipped == 0
    assert result.max_depth_seen == 2
    assert [member.path for member in result.members] == [
        "outer.zip/readme.txt",
        "outer.zip/bundle.zip",
        "outer.zip/bundle.zip/payload.exe",
    ]
    assert all(len(member.sha256) == 64 for member in result.members)


def test_entry_budget_is_explicit_and_never_reports_complete() -> None:
    result = inspect_archive(
        _zip({"one.txt": b"1", "two.txt": b"2"}),
        "many.zip",
        limits=ArchiveLimits(max_entries=1),
    )

    assert result.complete is False
    assert result.entries_total == 2
    assert result.entries_analyzed == 1
    assert result.entries_skipped == 1
    assert {issue.code for issue in result.issues} == {"ARCHIVE_ENTRY_LIMIT_EXCEEDED"}


def test_member_size_and_compression_ratio_budgets_are_fail_closed() -> None:
    oversized = inspect_archive(
        _zip({"large.txt": b"A" * 64}, compression=zipfile.ZIP_STORED),
        "oversized.zip",
        limits=ArchiveLimits(max_member_bytes=32),
    )
    compressed = inspect_archive(
        _zip({"bomb.txt": b"A" * 100_000}),
        "ratio.zip",
        limits=ArchiveLimits(max_compression_ratio=2.0),
    )

    assert oversized.complete is False
    assert oversized.entries_skipped == 1
    assert any(issue.code == "ARCHIVE_MEMBER_SIZE_LIMIT_EXCEEDED" for issue in oversized.issues)
    assert compressed.complete is False
    assert compressed.entries_skipped == 1
    assert any(issue.code == "ARCHIVE_COMPRESSION_RATIO_EXCEEDED" for issue in compressed.issues)


def test_unsafe_path_and_encrypted_entry_are_never_silently_accepted() -> None:
    unsafe = inspect_archive(_zip({"../escape.txt": b"secret"}), "unsafe.zip")
    encrypted = inspect_archive(
        _mark_first_zip_entry_encrypted(_zip({"secret.txt": b"encrypted?"})),
        "encrypted.zip",
    )

    assert unsafe.complete is False
    assert unsafe.members == ()
    assert any(issue.code == "ARCHIVE_UNSAFE_PATH" for issue in unsafe.issues)
    assert encrypted.complete is False
    assert encrypted.members == ()
    assert any(issue.code == "ARCHIVE_ENCRYPTED_ENTRY" for issue in encrypted.issues)


@pytest.mark.parametrize(
    ("filename", "payload"),
    [
        ("sample.7z", b"7z\xbc\xaf'\x1c\x00synthetic"),
        ("sample.rar", b"Rar!\x1a\x07\x01\x00synthetic"),
        ("sample.bz2", b"BZh9synthetic"),
        ("sample.xz", b"\xfd7zXZ\x00synthetic"),
    ],
)
def test_recognized_unsupported_formats_are_explicit_unknown(
    filename: str,
    payload: bytes,
) -> None:
    result = inspect_archive(payload, filename)

    assert result.detected is True
    assert result.kind == "unsupported"
    assert result.complete is False
    assert any(issue.code == "ARCHIVE_FORMAT_UNSUPPORTED" for issue in result.issues)


def test_corrupt_supported_archive_is_explicitly_incomplete() -> None:
    result = inspect_archive(b"not a real zip", "claimed.zip")

    assert result.detected is True
    assert result.kind == "zip"
    assert result.complete is False
    assert any(issue.code == "ARCHIVE_PARSE_ERROR" for issue in result.issues)


@pytest.mark.parametrize(("mode", "filename"), [("w:bz2", "safe.tar.bz2"), ("w:xz", "safe.tar.xz")])
def test_bounded_tar_bzip2_and_xz_are_supported(mode: str, filename: str) -> None:
    result = inspect_archive(_tar({"safe.txt": b"hello"}, mode=mode), filename)

    assert result.detected is True
    assert result.kind == "tar"
    assert result.complete is True
    assert result.entries_analyzed == 1


def test_nested_depth_limit_is_explicit() -> None:
    deepest = _zip({"payload.txt": b"hello"})
    middle = _zip({"deep.zip": deepest})
    outer = _zip({"middle.zip": middle})

    result = inspect_archive(outer, "outer.zip", limits=ArchiveLimits(max_depth=2))

    assert result.complete is False
    assert any(issue.code == "ARCHIVE_DEPTH_LIMIT_EXCEEDED" for issue in result.issues)


def test_unexpected_inspector_failure_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def raises(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("private parser failure")

    monkeypatch.setattr(archive_scan, "_visit_zip", raises)

    result = inspect_archive(_zip({"safe.txt": b"hello"}), "safe.zip")

    assert result.complete is False
    assert any(issue.code == "ARCHIVE_INSPECTION_ERROR" for issue in result.issues)
    assert all("private parser failure" not in issue.detail for issue in result.issues)


def test_nonfinite_or_zero_limit_configuration_is_fail_closed() -> None:
    invalid = inspect_archive(
        _zip({"safe.txt": b"hello"}),
        "safe.zip",
        limits=ArchiveLimits(max_entries=0, max_compression_ratio=float("nan")),
    )

    assert invalid.complete is False
    assert invalid.entries_analyzed == 0
    assert any(issue.code == "ARCHIVE_LIMIT_CONFIG_INVALID" for issue in invalid.issues)
