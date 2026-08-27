"""Inspection d'archives en mémoire avec budgets anti-décompression explosive."""

from __future__ import annotations

import gzip
import hashlib
import io
import math
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Literal, Protocol

ArchiveKind = Literal["zip", "tar", "gzip", "unsupported"]


class _BinaryReader(Protocol):
    def read(self, size: int = -1) -> bytes: ...


_UNSUPPORTED_SUFFIXES = (
    ".7z",
    ".ace",
    ".bz2",
    ".img",
    ".iso",
    ".rar",
    ".xz",
)
_TAR_SUFFIXES = (".tar", ".tar.bz2", ".tar.xz")
_GZIP_SUFFIXES = (".gz", ".gzip", ".tgz", ".tar.gz")
_ZIP_SUFFIXES = (".apk", ".epub", ".jar", ".zip", ".zipx")


@dataclass(frozen=True)
class ArchiveLimits:
    max_depth: int = 3
    max_entries: int = 100
    max_member_bytes: int = 10 * 1024 * 1024
    max_total_uncompressed_bytes: int = 50 * 1024 * 1024
    max_compression_ratio: float = 200.0


@dataclass(frozen=True)
class ArchiveMember:
    path: str
    depth: int
    data: bytes
    sha256: str


@dataclass(frozen=True)
class ArchiveIssue:
    code: str
    detail: str


@dataclass(frozen=True)
class ArchiveScanResult:
    detected: bool
    kind: ArchiveKind | None
    complete: bool
    entries_total: int
    entries_analyzed: int
    entries_skipped: int
    total_uncompressed_bytes: int
    max_depth_seen: int
    members: tuple[ArchiveMember, ...]
    issues: tuple[ArchiveIssue, ...]


@dataclass
class _State:
    limits: ArchiveLimits
    entries_total: int = 0
    entries_skipped: int = 0
    total_uncompressed_bytes: int = 0
    max_depth_seen: int = 0
    incomplete: bool = False
    members: list[ArchiveMember] = field(default_factory=list)
    issues: list[ArchiveIssue] = field(default_factory=list)
    issue_keys: set[tuple[str, str]] = field(default_factory=set)

    def issue(self, code: str, detail: str, *, incomplete: bool = True) -> None:
        key = (code, detail)
        if key not in self.issue_keys:
            self.issue_keys.add(key)
            self.issues.append(ArchiveIssue(code=code, detail=detail))
        self.incomplete = self.incomplete or incomplete


def _path_ref(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8", errors="replace")).hexdigest()[:16]


def _safe_member_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    if not normalized or normalized.startswith(("/", "//")):
        return False
    if re.match(r"^[a-zA-Z]:", normalized):
        return False
    return ".." not in PurePosixPath(normalized).parts


def _read_bounded(stream: _BinaryReader, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    read_total = 0
    while True:
        chunk = stream.read(min(64 * 1024, max(1, limit + 1 - read_total)))
        if not chunk:
            return b"".join(chunks), False
        chunks.append(chunk)
        read_total += len(chunk)
        if read_total > limit:
            return b"".join(chunks), True


def _compression_ratio_exceeded(
    *, uncompressed: int, compressed: int, limits: ArchiveLimits
) -> bool:
    if uncompressed <= 0:
        return False
    return uncompressed / max(1, compressed) > limits.max_compression_ratio


def archive_kind(data: bytes, filename: str) -> ArchiveKind | None:
    """Détecte les formats stdlib supportés et les formats à tenir en unknown."""
    lower = filename.lower()
    try:
        if zipfile.is_zipfile(io.BytesIO(data)):
            return "zip"
    except (OSError, ValueError, zipfile.BadZipFile):
        pass
    if lower.endswith(_ZIP_SUFFIXES):
        return "zip"
    if data.startswith(b"\x1f\x8b") or lower.endswith(_GZIP_SUFFIXES):
        return "gzip"
    if (len(data) >= 262 and data[257:262] == b"ustar") or lower.endswith(_TAR_SUFFIXES):
        return "tar"
    unsupported_magic = (
        data.startswith((b"7z\xbc\xaf'\x1c", b"Rar!\x1a\x07", b"BZh", b"\xfd7zXZ\x00"))
        or b"**ACE**" in data[:32]
        or (len(data) >= 0x8006 and data[0x8001:0x8006] == b"CD001")
    )
    if unsupported_magic or lower.endswith(_UNSUPPORTED_SUFFIXES):
        return "unsupported"
    return None


def _reserve_entry(state: _State, *, depth: int) -> bool:
    state.max_depth_seen = max(state.max_depth_seen, depth)
    if state.entries_total >= state.limits.max_entries:
        state.entries_total += 1
        state.entries_skipped += 1
        state.issue(
            "ARCHIVE_ENTRY_LIMIT_EXCEEDED",
            f"budget={state.limits.max_entries}",
        )
        return False
    state.entries_total += 1
    return True


def _accept_member(state: _State, *, path: str, depth: int, data: bytes) -> None:
    state.total_uncompressed_bytes += len(data)
    state.members.append(
        ArchiveMember(
            path=path,
            depth=depth,
            data=data,
            sha256=hashlib.sha256(data).hexdigest(),
        )
    )


def _remaining_bytes(state: _State) -> int:
    return max(0, state.limits.max_total_uncompressed_bytes - state.total_uncompressed_bytes)


def _validate_declared_member(
    state: _State,
    *,
    path: str,
    declared_size: int,
    compressed_size: int | None,
) -> bool:
    ref = _path_ref(path)
    if not _safe_member_path(path):
        state.entries_skipped += 1
        state.issue("ARCHIVE_UNSAFE_PATH", f"member={ref}")
        return False
    if declared_size > state.limits.max_member_bytes:
        state.entries_skipped += 1
        state.issue(
            "ARCHIVE_MEMBER_SIZE_LIMIT_EXCEEDED",
            f"member={ref};size={declared_size};budget={state.limits.max_member_bytes}",
        )
        return False
    if declared_size > _remaining_bytes(state):
        state.entries_skipped += 1
        state.issue(
            "ARCHIVE_TOTAL_SIZE_LIMIT_EXCEEDED",
            f"member={ref};budget={state.limits.max_total_uncompressed_bytes}",
        )
        return False
    if compressed_size is not None and _compression_ratio_exceeded(
        uncompressed=declared_size,
        compressed=compressed_size,
        limits=state.limits,
    ):
        state.entries_skipped += 1
        state.issue(
            "ARCHIVE_COMPRESSION_RATIO_EXCEEDED",
            f"member={ref};budget={state.limits.max_compression_ratio:g}",
        )
        return False
    return True


def _visit_zip(state: _State, data: bytes, *, prefix: str, depth: int) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                member_depth = depth + 1
                if not _reserve_entry(state, depth=member_depth):
                    return
                path = f"{prefix}/{info.filename}" if prefix else info.filename
                ref = _path_ref(path)
                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode == stat.S_IFLNK:
                    state.entries_skipped += 1
                    state.issue("ARCHIVE_LINK_SKIPPED", f"member={ref}")
                    continue
                if info.flag_bits & 0x1:
                    state.entries_skipped += 1
                    state.issue("ARCHIVE_ENCRYPTED_ENTRY", f"member={ref}")
                    continue
                if not _validate_declared_member(
                    state,
                    path=path,
                    declared_size=max(0, info.file_size),
                    compressed_size=max(0, info.compress_size),
                ):
                    continue
                limit = min(state.limits.max_member_bytes, _remaining_bytes(state))
                try:
                    with archive.open(info, "r") as stream:
                        member_data, exceeded = _read_bounded(stream, limit)
                except (
                    NotImplementedError,
                    OSError,
                    RuntimeError,
                    zipfile.BadZipFile,
                    zipfile.LargeZipFile,
                ) as exc:
                    state.entries_skipped += 1
                    state.issue(
                        "ARCHIVE_ENTRY_READ_ERROR",
                        f"member={ref};error={type(exc).__name__}",
                    )
                    continue
                if exceeded:
                    state.entries_skipped += 1
                    state.issue("ARCHIVE_MEMBER_SIZE_LIMIT_EXCEEDED", f"member={ref}")
                    continue
                _accept_member(state, path=path, depth=member_depth, data=member_data)
                _visit_nested(state, member_data, filename=path, depth=member_depth)
    except (OSError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        state.issue("ARCHIVE_PARSE_ERROR", f"kind=zip;error={type(exc).__name__}")


def _visit_tar(state: _State, data: bytes, *, prefix: str, depth: int) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for info in archive:
                if info.isdir():
                    continue
                member_depth = depth + 1
                if not _reserve_entry(state, depth=member_depth):
                    return
                path = f"{prefix}/{info.name}" if prefix else info.name
                ref = _path_ref(path)
                if info.issym() or info.islnk():
                    state.entries_skipped += 1
                    state.issue("ARCHIVE_LINK_SKIPPED", f"member={ref}")
                    continue
                if not info.isfile():
                    state.entries_skipped += 1
                    state.issue("ARCHIVE_SPECIAL_ENTRY_SKIPPED", f"member={ref}")
                    continue
                if not _validate_declared_member(
                    state,
                    path=path,
                    declared_size=max(0, info.size),
                    compressed_size=None,
                ):
                    continue
                stream = archive.extractfile(info)
                if stream is None:
                    state.entries_skipped += 1
                    state.issue("ARCHIVE_ENTRY_READ_ERROR", f"member={ref};error=no_stream")
                    continue
                with stream:
                    member_data, exceeded = _read_bounded(
                        stream,
                        min(state.limits.max_member_bytes, _remaining_bytes(state)),
                    )
                if exceeded:
                    state.entries_skipped += 1
                    state.issue("ARCHIVE_MEMBER_SIZE_LIMIT_EXCEEDED", f"member={ref}")
                    continue
                _accept_member(state, path=path, depth=member_depth, data=member_data)
                _visit_nested(state, member_data, filename=path, depth=member_depth)
    except (OSError, ValueError, tarfile.TarError) as exc:
        state.issue("ARCHIVE_PARSE_ERROR", f"kind=tar;error={type(exc).__name__}")


def _gzip_member_name(filename: str) -> str:
    lower = filename.lower()
    for suffix in sorted(_GZIP_SUFFIXES, key=len, reverse=True):
        if lower.endswith(suffix):
            stripped = filename[: -len(suffix)]
            return f"{stripped}.tar" if suffix == ".tgz" else stripped or "gzip-payload"
    return f"{filename}.payload"


def _visit_gzip(state: _State, data: bytes, *, prefix: str, depth: int) -> None:
    member_depth = depth + 1
    if not _reserve_entry(state, depth=member_depth):
        return
    path = _gzip_member_name(prefix or "archive.gz")
    ref = _path_ref(path)
    ratio_limit = int(max(1, len(data)) * state.limits.max_compression_ratio)
    limit = min(
        state.limits.max_member_bytes,
        _remaining_bytes(state),
        ratio_limit,
    )
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
            member_data, exceeded = _read_bounded(stream, limit)
    except (EOFError, OSError, gzip.BadGzipFile) as exc:
        state.entries_skipped += 1
        state.issue(
            "ARCHIVE_ENTRY_READ_ERROR",
            f"member={ref};error={type(exc).__name__}",
        )
        return
    if exceeded:
        state.entries_skipped += 1
        code = (
            "ARCHIVE_COMPRESSION_RATIO_EXCEEDED"
            if limit == ratio_limit
            else "ARCHIVE_MEMBER_SIZE_LIMIT_EXCEEDED"
        )
        state.issue(code, f"member={ref}")
        return
    _accept_member(state, path=path, depth=member_depth, data=member_data)
    _visit_nested(state, member_data, filename=path, depth=member_depth)


def _visit_nested(state: _State, data: bytes, *, filename: str, depth: int) -> None:
    kind = archive_kind(data, filename)
    if kind is None:
        return
    if kind == "unsupported":
        state.issue(
            "ARCHIVE_FORMAT_UNSUPPORTED",
            f"member={_path_ref(filename)};suffix={PurePosixPath(filename).suffix.lower()}",
        )
        return
    if depth >= state.limits.max_depth:
        state.issue(
            "ARCHIVE_DEPTH_LIMIT_EXCEEDED",
            f"member={_path_ref(filename)};budget={state.limits.max_depth}",
        )
        return
    if kind == "zip":
        _visit_zip(state, data, prefix=filename, depth=depth)
    elif kind == "tar":
        _visit_tar(state, data, prefix=filename, depth=depth)
    else:
        _visit_gzip(state, data, prefix=filename, depth=depth)


def inspect_archive(
    data: bytes,
    filename: str,
    *,
    limits: ArchiveLimits | None = None,
) -> ArchiveScanResult:
    """Inspecte récursivement une archive sans écrire sur le filesystem."""
    if limits is None:
        limits = ArchiveLimits()
    kind = archive_kind(data, filename)
    if kind is None:
        return ArchiveScanResult(
            detected=False,
            kind=None,
            complete=True,
            entries_total=0,
            entries_analyzed=0,
            entries_skipped=0,
            total_uncompressed_bytes=0,
            max_depth_seen=0,
            members=(),
            issues=(),
        )

    state = _State(limits=limits)
    invalid_limits = [
        name
        for name, value in (
            ("max_depth", limits.max_depth),
            ("max_entries", limits.max_entries),
            ("max_member_bytes", limits.max_member_bytes),
            ("max_total_uncompressed_bytes", limits.max_total_uncompressed_bytes),
        )
        if value <= 0
    ]
    if not math.isfinite(limits.max_compression_ratio) or limits.max_compression_ratio <= 0:
        invalid_limits.append("max_compression_ratio")
    if invalid_limits:
        state.issue(
            "ARCHIVE_LIMIT_CONFIG_INVALID",
            f"fields={','.join(invalid_limits)}",
        )
    else:
        try:
            if kind == "unsupported":
                state.issue(
                    "ARCHIVE_FORMAT_UNSUPPORTED",
                    f"suffix={PurePosixPath(filename).suffix.lower()}",
                )
            elif kind == "zip":
                _visit_zip(state, data, prefix=filename, depth=0)
            elif kind == "tar":
                _visit_tar(state, data, prefix=filename, depth=0)
            else:
                _visit_gzip(state, data, prefix=filename, depth=0)
        except Exception as exc:
            state.issue(
                "ARCHIVE_INSPECTION_ERROR",
                f"kind={kind};error={type(exc).__name__}",
            )

    return ArchiveScanResult(
        detected=True,
        kind=kind,
        complete=not state.incomplete,
        entries_total=state.entries_total,
        entries_analyzed=len(state.members),
        entries_skipped=state.entries_skipped,
        total_uncompressed_bytes=state.total_uncompressed_bytes,
        max_depth_seen=state.max_depth_seen,
        members=tuple(state.members),
        issues=tuple(state.issues),
    )
